//! A copy of a non-INVITE request whose transaction already answered and
//! retired gets that same final back, never a server error.
//!
//! RFC 3261 §17.2.2: Timer J is 64*T1 over an unreliable transport, where the
//! transaction itself stays in `Completed` and retransmits its final, and zero
//! over a reliable one, where the transaction is gone at once. The admission
//! reservation that still holds the key keeps the final bytes for that window,
//! so a copy arriving inside it is answered with the same response and the
//! transaction user never sees the request twice.

use rvoip_sip_core::builder::SimpleResponseBuilder;
use rvoip_sip_core::{Method, StatusCode};
use rvoip_sip_dialog::transaction::{TransactionEvent, TransactionManager};
use rvoip_sip_transport::{TcpTransport, Transport, UdpTransport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};

/// Longer than the reservation of a retired transaction (its terminating and
/// draining grace periods).
const PAST_RESERVATION: Duration = Duration::from_millis(1500);

fn request(method: Method, server: SocketAddr, client: SocketAddr, proto: &str) -> Vec<u8> {
    let branch = format!("z9hG4bK.retired-final-{method}");
    format!(
        "{method} sip:bob@{server} SIP/2.0\r\n\
         Via: SIP/2.0/{proto} {client};branch={branch}\r\n\
         From: <sip:alice@example.test>;tag=alicetag\r\n\
         To: <sip:bob@example.test>;tag=bobtag\r\n\
         Call-ID: retired-final-replay\r\n\
         CSeq: 7 {method}\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Answers every new non-INVITE request with 200 and counts how many reached
/// the transaction user.
fn spawn_uas(
    manager: Arc<TransactionManager>,
    mut events: tokio::sync::mpsc::Receiver<TransactionEvent>,
) -> Arc<AtomicUsize> {
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let TransactionEvent::NonInviteRequest {
                transaction_id,
                request,
                ..
            } = event
            {
                counter.fetch_add(1, Ordering::Relaxed);
                let ok =
                    SimpleResponseBuilder::dialog_response(&request, StatusCode::Ok, None).build();
                let _ = manager.send_response(&transaction_id, ok).await;
            }
        }
    });
    seen
}

fn status_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// One TCP connection that sends `method` twice and returns both answers.
async fn tcp_pair(server: SocketAddr, method: Method, gap: Option<Duration>) -> Vec<String> {
    let socket = TcpSocket::new_v4().expect("client socket");
    socket
        .bind("127.0.0.1:0".parse().unwrap())
        .expect("bind client");
    let client = socket.local_addr().expect("client addr");
    let mut stream = socket.connect(server).await.expect("connect");

    let mut answers = Vec::new();
    for attempt in 0..2 {
        if attempt == 1 {
            if let Some(gap) = gap {
                tokio::time::sleep(gap).await;
            }
        }
        stream
            .write_all(&request(method.clone(), server, client, "TCP"))
            .await
            .expect("write request");
        let mut buf = vec![0u8; 8192];
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(bytes)) if bytes > 0 => answers.push(status_line(&buf[..bytes])),
            other => panic!("copy {attempt} was not answered over TCP ({other:?})"),
        }
    }
    answers
}

async fn tcp_uas() -> (SocketAddr, Arc<TransactionManager>, Arc<AtomicUsize>) {
    let (transport, transport_rx) =
        TcpTransport::bind("127.0.0.1:0".parse().unwrap(), Some(64), None)
            .await
            .expect("bind TCP transport");
    let server = transport.local_addr().expect("local addr");
    let (manager, events) = TransactionManager::new(Arc::new(transport), transport_rx, Some(64))
        .await
        .expect("start transaction manager");
    let manager = Arc::new(manager);
    let seen = spawn_uas(manager.clone(), events);
    (server, manager, seen)
}

/// R1: a BYE copy inside the reservation window gets the same 200 and the
/// transaction user sees one BYE.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_bye_copy_replays_the_retained_final() {
    let (server, manager, seen) = tcp_uas().await;

    let answers = tcp_pair(server, Method::Bye, None).await;

    assert_eq!(answers, vec!["SIP/2.0 200 OK", "SIP/2.0 200 OK"]);
    assert_eq!(
        seen.load(Ordering::Relaxed),
        1,
        "the copy must not reach the transaction user again"
    );
    manager.shutdown().await;
}

/// R2: the same for OPTIONS, and the retained final is released with its
/// reservation (R7: nothing is kept afterwards).
#[tokio::test(flavor = "multi_thread")]
async fn tcp_options_copy_replays_and_the_retained_final_is_released() {
    let (server, manager, seen) = tcp_uas().await;

    let answers = tcp_pair(server, Method::Options, None).await;
    assert_eq!(answers, vec!["SIP/2.0 200 OK", "SIP/2.0 200 OK"]);
    assert_eq!(seen.load(Ordering::Relaxed), 1);

    tokio::time::sleep(PAST_RESERVATION).await;
    assert_eq!(
        manager.retention_counts().retained_server_finals,
        0,
        "the retained final goes with its reservation"
    );
    manager.shutdown().await;
}

/// R3: once the reservation is released, the same request is a new one.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_request_after_the_reservation_is_a_new_transaction() {
    let (server, manager, seen) = tcp_uas().await;

    let answers = tcp_pair(server, Method::Bye, Some(PAST_RESERVATION)).await;

    assert_eq!(answers, vec!["SIP/2.0 200 OK", "SIP/2.0 200 OK"]);
    assert_eq!(
        seen.load(Ordering::Relaxed),
        2,
        "past the reservation the request is new"
    );
    manager.shutdown().await;
}

/// R6: over UDP nothing changes. The transaction stays in `Completed` until
/// Timer J and answers the copy itself, so no final is retained.
#[tokio::test(flavor = "multi_thread")]
async fn udp_copy_is_answered_by_the_transaction_itself() {
    let (transport, transport_rx) = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), Some(64))
        .await
        .expect("bind UDP transport");
    let server = transport.local_addr().expect("local addr");
    let (manager, events) = TransactionManager::new(Arc::new(transport), transport_rx, Some(64))
        .await
        .expect("start transaction manager");
    let manager = Arc::new(manager);
    let seen = spawn_uas(manager.clone(), events);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client socket");
    let client = socket.local_addr().expect("client addr");
    let mut answers = Vec::new();
    for attempt in 0..2 {
        socket
            .send_to(&request(Method::Bye, server, client, "UDP"), server)
            .await
            .expect("send request");
        let mut buf = vec![0u8; 8192];
        let read = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await;
        match read {
            Ok(Ok((bytes, _))) if bytes > 0 => answers.push(status_line(&buf[..bytes])),
            other => panic!("copy {attempt} was not answered over UDP ({other:?})"),
        }
    }

    assert_eq!(answers, vec!["SIP/2.0 200 OK", "SIP/2.0 200 OK"]);
    assert_eq!(seen.load(Ordering::Relaxed), 1);
    assert_eq!(
        manager.retention_counts().retained_server_finals,
        0,
        "an unreliable transport keeps the transaction, not a retained final"
    );
    manager.shutdown().await;
}
