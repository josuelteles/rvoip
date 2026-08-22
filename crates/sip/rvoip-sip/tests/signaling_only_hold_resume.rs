//! Regression test: hold/resume must not fail on a signaling-only session.
//!
//! `MediaMode::SignalingOnly` sessions never register a media-core session
//! for their `media_session_id` (`MediaAdapter::create_session` returns
//! early before calling `controller.start_media`/`store_session_mapping`).
//! Before this fix, `MediaAdapter::set_media_direction` - invoked by the
//! `Action::HoldCurrentCall`/`Action::RestoreMediaFlow` state-machine
//! actions behind `coordinator.hold()`/`.resume()` - still called through to
//! the media-core controller with that unregistered id, failing with
//! "session not found" even though the SIP-level hold/resume re-INVITE
//! itself has nothing to do with local media-core state in this mode.
//!
//! Also covers end-to-end hold/resume when neither endpoint allocates
//! media-core RTP, verifying idempotent behavior.

use std::net::UdpSocket;
use std::time::Duration;

use rvoip_sip::api::events::Event;
use rvoip_sip::api::stream_peer::EventReceiver;
use rvoip_sip::api::unified::{Config, MediaMode};
use rvoip_sip::{CallState, SessionHandle, StreamPeer, UnifiedCoordinator};

/// Wait for any event matching `pred` on `events`, up to `timeout`.
async fn wait_for<F>(events: &mut EventReceiver, timeout: Duration, mut pred: F) -> Option<Event>
where
    F: FnMut(&Event) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let next = tokio::time::timeout(remaining, events.next()).await;
        match next {
            Err(_) => return None,
            Ok(None) => return None,
            Ok(Some(event)) => {
                if pred(&event) {
                    return Some(event);
                }
            }
        }
    }
}

fn reserve_loopback_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("reserved loopback address")
        .port()
}

async fn wait_for_state(call: &SessionHandle, expected: CallState) {
    let wait = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if matches!(call.state().await, Ok(state) if state == expected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if wait.is_err() {
        panic!(
            "call did not reach {expected:?}; last state: {:?}",
            call.state().await
        );
    }
}

#[tokio::test]
async fn hold_and_resume_succeed_on_signaling_only_session() {
    let _ = tracing_subscriber::fmt::try_init();

    let alice_port = 35962;
    let bob_port = 35972;

    let mut alice_cfg = Config::local("alice", alice_port);
    alice_cfg = alice_cfg.with_media_mode(MediaMode::SignalingOnly { sdp_rtp_port: 9 });
    let bob_cfg = Config::local("bob", bob_port);

    let alice = UnifiedCoordinator::new(alice_cfg)
        .await
        .expect("alice coordinator");
    let bob = UnifiedCoordinator::new(bob_cfg)
        .await
        .expect("bob coordinator");

    let mut alice_events = alice.events().await.expect("alice events");
    let mut bob_events = bob.events().await.expect("bob events");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let session_id = alice
        .invite(
            Some(format!("sip:alice@127.0.0.1:{}", alice_port)),
            format!("sip:bob@127.0.0.1:{}", bob_port),
        )
        .send()
        .await
        .expect("alice invite");

    let incoming = wait_for(&mut bob_events, Duration::from_secs(5), |ev| {
        matches!(ev, Event::IncomingCall { .. })
    })
    .await
    .expect("bob did not see IncomingCall");
    let bob_session_id = match incoming {
        Event::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };

    bob.accept_call(&bob_session_id)
        .await
        .expect("bob accept_call");

    wait_for(&mut alice_events, Duration::from_secs(5), |ev| {
        matches!(ev, Event::CallAnswered { .. })
    })
    .await
    .expect("alice did not observe CallAnswered");

    // Give the session store a moment to land in `Active` state after
    // the ACK/media-flow completion driven by the CallAnswered event.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let hold_result = alice.hold(&session_id).await;
    assert!(
        hold_result.is_ok(),
        "hold() must succeed on a signaling-only session, got: {:?}",
        hold_result
    );

    let resume_result = alice.resume(&session_id).await;
    assert!(
        resume_result.is_ok(),
        "resume() must succeed on a signaling-only session, got: {:?}",
        resume_result
    );

    alice.hangup(&session_id).await.ok();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signaling_only_hold_resume_is_negotiated_and_idempotent() {
    let server_port = reserve_loopback_port();
    let mut client_port = reserve_loopback_port();
    while client_port == server_port {
        client_port = reserve_loopback_port();
    }

    let mut server = StreamPeer::with_config(
        Config::local("signaling-only-server", server_port).with_signaling_only_media(9),
    )
    .await
    .expect("start signaling-only server");
    let server_task = tokio::spawn(async move {
        let incoming = tokio::time::timeout(Duration::from_secs(8), server.wait_for_incoming())
            .await
            .map_err(|_| "incoming call timed out".to_string())?
            .map_err(|error| error.to_string())?;
        let call = incoming.accept().await.map_err(|error| error.to_string())?;
        let mut events = call.events().await.map_err(|error| error.to_string())?;
        let mut remote_holds = 0;
        let mut remote_resumes = 0;

        tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(event) = events.next().await {
                match event {
                    Event::RemoteCallOnHold { .. } => remote_holds += 1,
                    Event::RemoteCallResumed { .. } => remote_resumes += 1,
                    Event::CallEnded { .. } | Event::CallFailed { .. } => break,
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "server event loop timed out".to_string())?;
        server.shutdown().await.map_err(|error| error.to_string())?;
        Ok::<_, String>((remote_holds, remote_resumes))
    });

    let client = StreamPeer::with_config(
        Config::local("signaling-only-client", client_port).with_signaling_only_media(9),
    )
    .await
    .expect("start signaling-only client");
    let call_id = client
        .invite(format!("sip:server@127.0.0.1:{server_port}"))
        .send()
        .await
        .expect("send signaling-only INVITE");
    let call = client.coordinator().session(&call_id);
    call.wait_for_answered(Some(Duration::from_secs(8)))
        .await
        .expect("signaling-only call answered");

    call.hold().await.expect("send signaling-only hold");
    wait_for_state(&call, CallState::OnHold).await;
    call.hold().await.expect("repeat hold is idempotent");
    assert_eq!(call.state().await.expect("held state"), CallState::OnHold);

    call.resume().await.expect("send signaling-only resume");
    wait_for_state(&call, CallState::Active).await;
    call.resume().await.expect("repeat resume is idempotent");
    assert_eq!(call.state().await.expect("active state"), CallState::Active);

    call.hangup().await.expect("hang up signaling-only call");
    client.shutdown().await.expect("shutdown client");
    let (remote_holds, remote_resumes) = server_task
        .await
        .expect("join server task")
        .expect("server scenario");
    assert_eq!(remote_holds, 1, "repeated hold emitted another negotiation");
    assert_eq!(
        remote_resumes, 1,
        "repeated resume emitted another negotiation"
    );
}
