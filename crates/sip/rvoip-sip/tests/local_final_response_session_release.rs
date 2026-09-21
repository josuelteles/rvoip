//! A final response authored locally for an initial INVITE must release its
//! lifecycle session. The store is capacity bounded, so a session retained by
//! every rejection eventually answers 503 to new calls.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rvoip_sip::api::callback_peer::{CallHandler, CallHandlerDecision, CallbackPeer};
use rvoip_sip::api::incoming::IncomingCall;
use rvoip_sip::api::unified::{Config, UnifiedCoordinator};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

/// How the test drives the local final response for one incoming call.
#[derive(Clone, Copy, Debug)]
enum RejectPath {
    /// `coordinator.reject(..).send()`
    CoordinatorReject,
    /// `IncomingCall::reject`
    IncomingReject,
    /// `CallHandlerDecision::Reject`
    HandlerReject,
    /// `coordinator.redirect(..).send()`
    Redirect,
    /// `coordinator.respond(..).send()` with a final status
    GenericResponse,
    /// `IncomingCallGuard::reject_and_wait`
    RejectAndWait,
}

struct PathHandler {
    path: RejectPath,
    coordinator: Arc<tokio::sync::OnceCell<Arc<UnifiedCoordinator>>>,
    handled: Arc<AtomicUsize>,
    done: mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl CallHandler for PathHandler {
    async fn on_incoming_call(&self, call: IncomingCall) -> CallHandlerDecision {
        let call_id = call.call_id.clone();
        self.handled.fetch_add(1, Ordering::SeqCst);
        let decision = match self.path {
            RejectPath::HandlerReject => CallHandlerDecision::Reject {
                status: 486,
                reason: "Busy Here".to_string(),
            },
            RejectPath::RejectAndWait => {
                let guard = call.defer(Duration::from_secs(30));
                let event = guard
                    .reject_and_wait(486, "Busy Here", Some(Duration::from_secs(10)))
                    .await
                    .expect("reject_and_wait must not expire once the response was sent");
                assert!(
                    matches!(event, rvoip_sip::api::events::Event::CallFailed { .. }),
                    "reject_and_wait resolves with the terminal event: {event:?}"
                );
                let _ = self.done.send(()).await;
                return CallHandlerDecision::Reject {
                    status: 486,
                    reason: "Busy Here".to_string(),
                };
            }
            RejectPath::IncomingReject => {
                call.reject(486, "Busy Here");
                CallHandlerDecision::Reject {
                    status: 486,
                    reason: "Busy Here".to_string(),
                }
            }
            other => {
                let coordinator = self
                    .coordinator
                    .get()
                    .expect("coordinator is published before any INVITE")
                    .clone();
                match other {
                    RejectPath::CoordinatorReject => {
                        let _ = coordinator
                            .reject(&call_id)
                            .with_status(486)
                            .with_reason("Busy Here")
                            .send()
                            .await;
                    }
                    RejectPath::Redirect => {
                        let _ = coordinator
                            .redirect(&call_id)
                            .with_contact("sip:elsewhere@127.0.0.1:5090")
                            .send()
                            .await;
                    }
                    RejectPath::GenericResponse => {
                        if let Ok(builder) = coordinator.respond(&call_id, 603) {
                            let _ = builder.send().await;
                        }
                    }
                    _ => unreachable!(),
                }
                CallHandlerDecision::Defer(call.defer(Duration::from_secs(30)))
            }
        };
        let _ = self.done.send(()).await;
        decision
    }
}

async fn reserve_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("TCP bind");
        let addr = tcp.local_addr().expect("TCP address");
        if UdpSocket::bind(addr).await.is_ok() {
            return addr.port();
        }
    }
}

fn invite(index: usize, uas_port: u16, client_port: u16) -> String {
    format!(
        "INVITE sip:uas@127.0.0.1:{uas_port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{client_port};branch=z9hG4bK-leak-{index}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:caller@127.0.0.1:{client_port}>;tag=leak-{index}\r\n\
         To: <sip:uas@127.0.0.1:{uas_port}>\r\n\
         Call-ID: leak-{index}@127.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:caller@127.0.0.1:{client_port}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{SDP}",
        SDP.len()
    )
}

fn ack(index: usize, uas_port: u16, client_port: u16, response: &str) -> String {
    let to = response
        .lines()
        .find_map(|line| line.strip_prefix("To: ").or(line.strip_prefix("to: ")))
        .unwrap_or("<sip:uas@127.0.0.1>")
        .to_string();
    format!(
        "ACK sip:uas@127.0.0.1:{uas_port} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{client_port};branch=z9hG4bK-leak-{index}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:caller@127.0.0.1:{client_port}>;tag=leak-{index}\r\n\
         To: {to}\r\n\
         Call-ID: leak-{index}@127.0.0.1\r\n\
         CSeq: 1 ACK\r\n\
         Content-Length: 0\r\n\r\n"
    )
}

/// Drives `calls` rejected INVITEs through `path` and returns the store
/// occupancy before the first call and after the last one settled.
async fn rejected_call_store_occupancy(path: RejectPath, calls: usize) -> (usize, usize) {
    let uas_port = reserve_port().await;
    let cell = Arc::new(tokio::sync::OnceCell::new());
    let handled = Arc::new(AtomicUsize::new(0));
    let (done_tx, mut done_rx) = mpsc::channel(calls.max(1));

    let peer = CallbackPeer::new(
        PathHandler {
            path,
            coordinator: cell.clone(),
            handled: handled.clone(),
            done: done_tx,
        },
        Config::local("uas", uas_port).with_auto_180_ringing(false),
    )
    .await
    .expect("UAS peer");
    let coordinator = peer.coordinator().clone();
    let _ = cell.set(coordinator.clone());
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(async move {
        let _ = peer.run().await;
    });
    sleep(Duration::from_millis(200)).await;

    let before = coordinator.retained_session_count();
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let client_port = client.local_addr().expect("client addr").port();
    let uas_addr = format!("127.0.0.1:{uas_port}");

    for index in 0..calls {
        client
            .send_to(invite(index, uas_port, client_port).as_bytes(), &uas_addr)
            .await
            .expect("INVITE");
        let mut buf = vec![0u8; 65536];
        let response = timeout(Duration::from_secs(5), async {
            loop {
                let (read, _) = client.recv_from(&mut buf).await.expect("recv");
                let text = String::from_utf8_lossy(&buf[..read]).into_owned();
                if text.starts_with("SIP/2.0 1") {
                    continue;
                }
                return text;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("call {index} received no final response"));
        client
            .send_to(
                ack(index, uas_port, client_port, &response).as_bytes(),
                &uas_addr,
            )
            .await
            .expect("ACK");
        timeout(Duration::from_secs(20), done_rx.recv())
            .await
            .expect("handler ran")
            .expect("handler channel");
    }

    // Release runs in a retained task, so settle before measuring.
    let after = timeout(Duration::from_secs(20), async {
        loop {
            let occupancy = coordinator.retained_session_count();
            if occupancy == before {
                return occupancy;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| coordinator.retained_session_count());

    assert_eq!(handled.load(Ordering::SeqCst), calls);
    shutdown.shutdown();
    let _ = timeout(Duration::from_secs(5), peer_task).await;
    (before, after)
}

async fn assert_no_session_leak(path: RejectPath, calls: usize) {
    let (before, after) = rejected_call_store_occupancy(path, calls).await;
    assert_eq!(
        after,
        before,
        "{path:?} retained {} lifecycle session(s) after {calls} rejected call(s)",
        after - before
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_thousand_coordinator_rejects_release_every_session() {
    assert_no_session_leak(RejectPath::CoordinatorReject, 1000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incoming_call_reject_releases_its_session() {
    assert_no_session_leak(RejectPath::IncomingReject, 25).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handler_reject_releases_its_session() {
    assert_no_session_leak(RejectPath::HandlerReject, 25).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redirect_releases_its_session() {
    assert_no_session_leak(RejectPath::Redirect, 25).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generic_final_response_releases_its_session() {
    assert_no_session_leak(RejectPath::GenericResponse, 25).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reject_and_wait_resolves_and_releases_its_session() {
    assert_no_session_leak(RejectPath::RejectAndWait, 10).await;
}

/// 100 rejections running at once: the release runs in retained tasks, so a
/// self-wait or a deadlock would show up here as a stalled store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rejects_release_every_session() {
    const CALLS: usize = 100;
    let uas_port = reserve_port().await;
    let cell = Arc::new(tokio::sync::OnceCell::new());
    let handled = Arc::new(AtomicUsize::new(0));
    let (done_tx, _done_rx) = mpsc::channel(CALLS);

    let peer = CallbackPeer::new(
        PathHandler {
            path: RejectPath::CoordinatorReject,
            coordinator: cell.clone(),
            handled: handled.clone(),
            done: done_tx,
        },
        Config::local("uas", uas_port).with_auto_180_ringing(false),
    )
    .await
    .expect("UAS peer");
    let coordinator = peer.coordinator().clone();
    let _ = cell.set(coordinator.clone());
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(async move {
        let _ = peer.run().await;
    });
    sleep(Duration::from_millis(200)).await;

    let before = coordinator.retained_session_count();
    let mut callers = tokio::task::JoinSet::new();
    for index in 0..CALLS {
        callers.spawn(async move {
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
            let client_port = client.local_addr().expect("client addr").port();
            let uas_addr = format!("127.0.0.1:{uas_port}");
            client
                .send_to(invite(index, uas_port, client_port).as_bytes(), &uas_addr)
                .await
                .expect("INVITE");
            let mut buf = vec![0u8; 65536];
            let response = timeout(Duration::from_secs(10), async {
                loop {
                    let (read, _) = client.recv_from(&mut buf).await.expect("recv");
                    let text = String::from_utf8_lossy(&buf[..read]).into_owned();
                    if !text.starts_with("SIP/2.0 1") {
                        return text;
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("call {index} received no final response"));
            let _ = client
                .send_to(
                    ack(index, uas_port, client_port, &response).as_bytes(),
                    &uas_addr,
                )
                .await;
        });
    }
    while let Some(result) = callers.join_next().await {
        result.expect("caller");
    }

    let after = timeout(Duration::from_secs(30), async {
        loop {
            let occupancy = coordinator.retained_session_count();
            if occupancy == before {
                return occupancy;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| coordinator.retained_session_count());
    assert_eq!(after, before, "{} session(s) retained", after - before);

    shutdown.shutdown();
    let _ = timeout(Duration::from_secs(5), peer_task).await;
}
