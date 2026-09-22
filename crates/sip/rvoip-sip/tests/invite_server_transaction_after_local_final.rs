//! Lifetime of the INVITE server transaction after a local final response
//! (RFC 3261 §9.2, §17.2.1, §17.2.3).
//!
//! The session of a locally answered INVITE is released right away, but the
//! server transaction keeps protocol authority: after a 300-699 final it stays
//! in `Completed`, retransmits the final on Timer G over UDP, absorbs the ACK
//! into `Confirmed` and ends on Timer I, or ends on Timer H without an ACK.
//!
//! Every test runs on a paused Tokio clock that only moves when the test
//! advances it, so the timer schedule is exact virtual time. The peer is a raw
//! UDP socket or TCP stream, and the transaction state is read from the
//! coordinator diagnostic snapshot, which needs `perf-tests`.

#![cfg(feature = "perf-tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rvoip_sip::api::callback_peer::{CallHandler, CallHandlerDecision, CallbackPeer};
use rvoip_sip::api::handle::CallId;
use rvoip_sip::api::incoming::IncomingCall;
use rvoip_sip::api::unified::{Config, UnifiedCoordinator};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

// RFC 3261 defaults, which the stack uses unless configured otherwise.
const T1: Duration = Duration::from_millis(500);
const T2: Duration = Duration::from_secs(4);
const TIMER_H: Duration = Duration::from_secs(32);
const TIMER_I: Duration = Duration::from_secs(5);
const TOLERANCE: Duration = Duration::from_millis(50);
/// Upper bound for the manager to remove a terminated transaction (its
/// terminating and draining grace periods).
const REMOVAL_GRACE: Duration = Duration::from_secs(1);
/// Virtual-time step used to drive the timers.
const STEP: Duration = Duration::from_millis(10);
/// Upper bound on real-time settle rounds for one frozen-clock wait.
const SETTLE_ROUNDS: usize = 500;

const NON_2XX_ACK: &str = "Processing ACK for non-2xx response";
const DIALOG_MATCHED_ACK: &str = "Found ACK for 2xx response using dialog-based matching";
const ORPHAN_ACK_WARN: &str = "Dropping ACK whose exact server INVITE has no dialog binding";
const SESSION_ACK: &str = "ACK received; media may start on UAS side";
const STRAY_ACK: &str = "No matching INVITE transaction found for ACK request";

/// Lets real loopback I/O and ready tasks run without moving virtual time.
/// A running blocking task inhibits the paused clock's auto-advance, so the
/// clock only moves when a test advances it.
async fn settle() {
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(2)))
        .await
        .expect("settle task");
}

/// Log lines captured from the stack, used as supporting evidence next to
/// the transaction state and the wire.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<String>>>);

impl LogCapture {
    fn count(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.insert_str(0, &format!("{value:?}"));
        } else {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(format!(
            "{} {} {}",
            event.metadata().level(),
            event.metadata().target(),
            visitor.0
        ));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Udp,
    Tcp,
}

impl Wire {
    fn token(self) -> &'static str {
        match self {
            Wire::Udp => "UDP",
            Wire::Tcp => "TCP",
        }
    }
}

/// What the UAS does once the automatic 180 reached the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Reject with 480 through `RejectBuilder`.
    Reject480,
    /// Stay in `Ringing` until the test answers the call.
    Hold,
    /// Accept with 200.
    Accept,
}

struct UasHandler {
    mode: Mode,
    coordinator: Arc<tokio::sync::OnceCell<Arc<UnifiedCoordinator>>>,
    ringing_seen: Arc<tokio::sync::Notify>,
    held: Arc<Mutex<Vec<CallId>>>,
}

#[async_trait::async_trait]
impl CallHandler for UasHandler {
    async fn on_incoming_call(&self, call: IncomingCall) -> CallHandlerDecision {
        let call_id = call.call_id.clone();
        timeout(Duration::from_secs(1), self.ringing_seen.notified())
            .await
            .expect("the automatic 180 reaches the client before the handler answers");
        match self.mode {
            Mode::Reject480 => {
                let coordinator = self
                    .coordinator
                    .get()
                    .expect("coordinator is published before any INVITE")
                    .clone();
                coordinator
                    .reject(&call_id)
                    .with_status(480)
                    .with_reason("Temporarily Unavailable")
                    .send()
                    .await
                    .expect("480 reject");
                CallHandlerDecision::Defer(call.defer(Duration::from_secs(60)))
            }
            Mode::Hold => {
                self.held.lock().unwrap().push(call_id);
                CallHandlerDecision::Defer(call.defer(Duration::from_secs(60)))
            }
            Mode::Accept => CallHandlerDecision::Accept,
        }
    }
}

enum Writer {
    Udp(Arc<UdpSocket>, String),
    Tcp(tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>),
}

/// Splits a TCP byte stream into SIP messages by Content-Length.
fn take_stream_message(buffer: &mut Vec<u8>) -> Option<String> {
    let text = String::from_utf8_lossy(buffer).into_owned();
    let head_end = text.find("\r\n\r\n")?;
    let body_len = text[..head_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim();
            (name.eq_ignore_ascii_case("Content-Length") || name.eq_ignore_ascii_case("l"))
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let total = head_end + 4 + body_len;
    if buffer.len() < total {
        return None;
    }
    let message = String::from_utf8_lossy(&buffer[..total]).into_owned();
    buffer.drain(..total);
    Some(message)
}

struct Harness {
    wire: Wire,
    mode: Mode,
    coordinator: Arc<UnifiedCoordinator>,
    writer: Writer,
    uas_port: u16,
    client_port: u16,
    inbound: mpsc::UnboundedReceiver<(Instant, String)>,
    /// Every message the client received so far, in arrival order.
    seen: Vec<(Instant, String)>,
    shutdown: rvoip_sip::api::callback_peer::ShutdownHandle,
    peer_task: tokio::task::JoinHandle<()>,
    logs: LogCapture,
    ringing_seen: Arc<tokio::sync::Notify>,
    held: Arc<Mutex<Vec<CallId>>>,
    _log_guard: tracing::subscriber::DefaultGuard,
}

impl Harness {
    async fn start(wire: Wire, mode: Mode) -> Self {
        let logs = LogCapture::default();
        let filter = tracing_subscriber::EnvFilter::new(
            std::env::var("C0_LOG_FILTER").unwrap_or_else(|_| "warn,rvoip_sip_dialog=debug".into()),
        );
        let subscriber = tracing_subscriber::registry().with(logs.clone().with_filter(filter));
        let log_guard = tracing::subscriber::set_default(subscriber);

        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let uas_port = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let cell = Arc::new(tokio::sync::OnceCell::new());
        let ringing_seen = Arc::new(tokio::sync::Notify::new());
        let held = Arc::new(Mutex::new(Vec::new()));
        let peer = CallbackPeer::new(
            UasHandler {
                mode,
                coordinator: cell.clone(),
                ringing_seen: ringing_seen.clone(),
                held: held.clone(),
            },
            Config::local("uas", uas_port).with_auto_180_ringing(true),
        )
        .await
        .expect("UAS peer");
        let coordinator = peer.coordinator().clone();
        let _ = cell.set(coordinator.clone());
        let shutdown = peer.shutdown_handle();
        let peer_task = tokio::spawn(async move {
            let _ = peer.run().await;
        });

        let uas_addr = format!("127.0.0.1:{uas_port}");
        let (tx, inbound) = mpsc::unbounded_channel();
        let (writer, client_port) = match wire {
            Wire::Udp => {
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("client"));
                let port = socket.local_addr().expect("client addr").port();
                let reader = socket.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    while let Ok((read, _)) = reader.recv_from(&mut buf).await {
                        let text = String::from_utf8_lossy(&buf[..read]).into_owned();
                        if tx.send((Instant::now(), text)).is_err() {
                            return;
                        }
                    }
                });
                (Writer::Udp(socket, uas_addr), port)
            }
            Wire::Tcp => {
                let stream = TcpStream::connect(&uas_addr).await.expect("TCP connect");
                let port = stream.local_addr().expect("client addr").port();
                let (mut read_half, write_half) = stream.into_split();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = vec![0u8; 65536];
                    while let Ok(read) = read_half.read(&mut chunk).await {
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        while let Some(message) = take_stream_message(&mut buffer) {
                            if tx.send((Instant::now(), message)).is_err() {
                                return;
                            }
                        }
                    }
                });
                (Writer::Tcp(tokio::sync::Mutex::new(write_half)), port)
            }
        };

        Self {
            wire,
            mode,
            coordinator,
            writer,
            uas_port,
            client_port,
            inbound,
            seen: Vec::new(),
            shutdown,
            peer_task,
            logs,
            ringing_seen,
            held,
            _log_guard: log_guard,
        }
    }

    async fn send(&self, message: String) {
        match &self.writer {
            Writer::Udp(socket, uas_addr) => {
                socket
                    .send_to(message.as_bytes(), uas_addr)
                    .await
                    .expect("send to UAS");
            }
            Writer::Tcp(stream) => {
                stream
                    .lock()
                    .await
                    .write_all(message.as_bytes())
                    .await
                    .expect("write to UAS");
            }
        }
    }

    fn pump(&mut self) {
        while let Ok(item) = self.inbound.try_recv() {
            self.seen.push(item);
        }
    }

    /// Arrival times of the responses with `status` to `method`.
    fn arrivals(&mut self, status: u16, method: &str) -> Vec<Instant> {
        self.pump();
        self.seen
            .iter()
            .filter(|(_, text)| is_response(text, status, method))
            .map(|(at, _)| *at)
            .collect()
    }

    fn count(&mut self, status: u16, method: &str) -> usize {
        self.arrivals(status, method).len()
    }

    /// The `n`th (1-based) response with `status` to `method`, waited for
    /// without moving virtual time: it answers something the stack does
    /// immediately.
    async fn expect_nth(&mut self, status: u16, method: &str, n: usize) -> (Instant, String) {
        for _ in 0..SETTLE_ROUNDS {
            self.pump();
            if let Some(found) = self
                .seen
                .iter()
                .filter(|(_, text)| is_response(text, status, method))
                .nth(n - 1)
            {
                return found.clone();
            }
            settle().await;
        }
        report("timeout", &[], &self.logs);
        panic!("no response #{n} {status} to {method} while virtual time was frozen")
    }

    async fn expect(&mut self, status: u16, method: &str) -> (Instant, String) {
        self.expect_nth(status, method, 1).await
    }

    /// Lets the stack process what was just sent, without moving time. A TCP
    /// read takes a few more runtime turns than a datagram, so this leaves a
    /// generous real-time margin.
    async fn quiesce(&mut self) {
        for _ in 0..50 {
            settle().await;
        }
        self.pump();
    }

    /// Advances virtual time to `until` in `STEP`s.
    async fn run_until(&mut self, until: Instant) {
        while Instant::now() < until {
            let step = STEP.min(until - Instant::now());
            tokio::time::advance(step).await;
            settle().await;
            self.pump();
        }
    }

    async fn snapshot(&self) -> TransactionView {
        TransactionView::from(self.coordinator.perf_diagnostic_snapshot().await)
    }

    /// Virtual time the session store took to drop back to `baseline`,
    /// stepping the clock up to `limit`. `None` when it never did.
    async fn session_released(&self, baseline: u64, limit: Duration) -> Option<Duration> {
        let started = Instant::now();
        loop {
            for _ in 0..3 {
                if self.snapshot().await.sessions == baseline {
                    return Some(started.elapsed());
                }
                settle().await;
            }
            if started.elapsed() >= limit {
                return None;
            }
            tokio::time::advance(STEP).await;
        }
    }

    fn held_call(&self) -> CallId {
        self.held
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a held call")
    }

    async fn stop(self) {
        self.shutdown.shutdown();
        let _ = timeout(Duration::from_secs(5), self.peer_task).await;
    }

    fn via(&self, tag: &str, sent_by: Option<&str>, extra: &str) -> String {
        let sent_by = sent_by
            .map(str::to_string)
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.client_port));
        format!(
            "Via: SIP/2.0/{} {sent_by};branch=z9hG4bK-{tag}{extra}",
            self.wire.token()
        )
    }

    fn invite(&self, tag: &str) -> String {
        let (uas_port, client_port) = (self.uas_port, self.client_port);
        format!(
            "INVITE sip:uas@127.0.0.1:{uas_port} SIP/2.0\r\n\
             {via}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:caller@127.0.0.1:{client_port}>;tag={tag}\r\n\
             To: <sip:uas@127.0.0.1:{uas_port}>\r\n\
             Call-ID: {tag}@127.0.0.1\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:caller@127.0.0.1:{client_port};transport={transport}>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{SDP}",
            SDP.len(),
            via = self.via(tag, None, ""),
            transport = self.wire.token().to_ascii_lowercase(),
        )
    }

    /// ACK of a non-2xx final: the INVITE branch and the final's To tag
    /// (RFC 3261 §17.1.1.3).
    fn non_2xx_ack(&self, tag: &str, response: &str, sent_by: Option<&str>) -> String {
        self.ack(tag, response, self.via(tag, sent_by, ""))
    }

    /// ACK of a 2xx: a new branch, end to end (RFC 3261 §13.2.2.4).
    fn ack_2xx(&self, tag: &str, response: &str) -> String {
        self.ack(tag, response, self.via(&format!("{tag}-ack2xx"), None, ""))
    }

    fn ack(&self, tag: &str, response: &str, via: String) -> String {
        let (uas_port, client_port) = (self.uas_port, self.client_port);
        let to = header(response, "To").expect("final response carries a To header");
        format!(
            "ACK sip:uas@127.0.0.1:{uas_port} SIP/2.0\r\n\
             {via}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:caller@127.0.0.1:{client_port}>;tag={tag}\r\n\
             To: {to}\r\n\
             Call-ID: {tag}@127.0.0.1\r\n\
             CSeq: 1 ACK\r\n\
             Content-Length: 0\r\n\r\n"
        )
    }

    /// CANCEL of the INVITE `tag` (RFC 3261 §9.1): same branch, sent-by and
    /// To (without tag) unless a test overrides them.
    fn cancel(
        &self,
        tag: &str,
        branch_tag: &str,
        sent_by: Option<&str>,
        to: Option<&str>,
        via_extra: &str,
    ) -> String {
        let (uas_port, client_port) = (self.uas_port, self.client_port);
        let default_to = format!("<sip:uas@127.0.0.1:{uas_port}>");
        let to = to.unwrap_or(&default_to);
        format!(
            "CANCEL sip:uas@127.0.0.1:{uas_port} SIP/2.0\r\n\
             {via}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:caller@127.0.0.1:{client_port}>;tag={tag}\r\n\
             To: {to}\r\n\
             Call-ID: {tag}@127.0.0.1\r\n\
             CSeq: 1 CANCEL\r\n\
             Content-Length: 0\r\n\r\n",
            via = self.via(branch_tag, sent_by, via_extra),
        )
    }

    /// INVITE sent and answered with 180, handler let through. In `Hold`
    /// mode, returns once the handler registered the call.
    async fn ringing(&mut self, tag: &str) -> String {
        let held_before = self.held.lock().unwrap().len();
        self.send(self.invite(tag)).await;
        let (_, ringing) = self.expect(180, "INVITE").await;
        self.ringing_seen.notify_one();
        if self.mode == Mode::Hold {
            for _ in 0..SETTLE_ROUNDS {
                if self.held.lock().unwrap().len() > held_before {
                    return ringing;
                }
                settle().await;
            }
            panic!("the handler never took the held call");
        }
        ringing
    }
}

fn header(message: &str, name: &str) -> Option<String> {
    message.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn is_response(text: &str, status: u16, method: &str) -> bool {
    text.starts_with(&format!("SIP/2.0 {status} "))
        && header(text, "CSeq").is_some_and(|cseq| cseq.ends_with(method))
}

/// The parts of the diagnostic snapshot these tests read.
#[derive(Debug)]
struct TransactionView {
    sessions: u64,
    server_transactions: u64,
    server_by_state: serde_json::Value,
    dialog_index: u64,
}

impl TransactionView {
    fn state_count(&self, state: &str) -> u64 {
        self.server_by_state[state].as_u64().unwrap_or(0)
    }

    /// The ACK confirmed the transaction: `Confirmed` over UDP. Over TCP
    /// Timer I is zero, so it may already have ended.
    fn acked(&self, wire: Wire) -> bool {
        match wire {
            Wire::Udp => self.state_count("Confirmed") == 1,
            Wire::Tcp => {
                self.state_count("Completed") == 0
                    && self.state_count("Proceeding") == 0
                    && self.state_count("Confirmed") + self.state_count("Terminated")
                        == self.server_transactions
            }
        }
    }
}

impl From<serde_json::Value> for TransactionView {
    fn from(snapshot: serde_json::Value) -> Self {
        let tm = &snapshot["transaction_manager"];
        Self {
            sessions: snapshot["session_store"]["total"].as_u64().unwrap_or(0),
            server_transactions: tm["server_transactions"].as_u64().unwrap_or(0),
            server_by_state: tm["breakdown"]["server_by_state"].clone(),
            dialog_index: tm["server_invite_dialog_index"].as_u64().unwrap_or(0),
        }
    }
}

/// Timer G offsets from the first final response: T1, then doubling up to
/// T2, for as long as Timer H allows.
fn timer_g_schedule() -> Vec<Duration> {
    let mut schedule = Vec::new();
    let mut interval = T1;
    let mut at = Duration::ZERO;
    loop {
        at += interval;
        if at >= TIMER_H {
            return schedule;
        }
        schedule.push(at);
        interval = (interval * 2).min(T2);
    }
}

fn offsets(from: Instant, times: &[Instant]) -> Vec<Duration> {
    times.iter().map(|at| at.duration_since(from)).collect()
}

fn close(actual: &[Duration], expected: &[Duration]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(a, e)| {
            let diff = if a > e { *a - *e } else { *e - *a };
            diff <= TOLERANCE
        })
}

fn report(case: &str, lines: &[String], logs: &LogCapture) {
    println!("--- {case}");
    for line in lines {
        println!("{case}: {line}");
    }
    // Set C0_DUMP_LOGS=1 to print every captured stack log line.
    if std::env::var_os("C0_DUMP_LOGS").is_some() {
        for line in logs.0.lock().unwrap().iter() {
            println!("{case} log: {line}");
        }
    }
}

/// Runs a scenario once per transport.
macro_rules! over_udp_and_tcp {
    ($udp:ident, $tcp:ident, $scenario:ident) => {
        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn $udp() {
            $scenario(Wire::Udp).await;
        }

        #[tokio::test(flavor = "current_thread", start_paused = true)]
        async fn $tcp() {
            $scenario(Wire::Tcp).await;
        }
    };
}

// ===== C0: the INVITE server transaction outlives the released session =====

/// C0a: 480 and no ACK. The session is released at once, the transaction
/// retransmits on Timer G over UDP (not over TCP) and ends on Timer H.
async fn c0a(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Reject480).await;
    let baseline = h.snapshot().await;

    h.ringing("c0a").await;
    let (first_final, _) = h.expect(480, "INVITE").await;
    let released = h.session_released(baseline.sessions, T1 / 2).await;
    let after_release = h.snapshot().await;

    h.run_until(first_final + TIMER_H - STEP).await;
    let before_h = h.snapshot().await;
    let finals = h.arrivals(480, "INVITE");
    h.run_until(first_final + TIMER_H + Duration::from_secs(10))
        .await;
    let after_h = h.snapshot().await;
    let late = h.count(480, "INVITE") - finals.len();

    let expected = match wire {
        Wire::Udp => timer_g_schedule(),
        Wire::Tcp => Vec::new(),
    };
    let actual = offsets(first_final, &finals[1..]);
    let lines = vec![
        format!("baseline: {baseline:?}"),
        format!("session released after {released:?} of virtual time"),
        format!("after release: {after_release:?}"),
        format!("retransmissions at {actual:?}"),
        format!("expected Timer G at {expected:?}"),
        format!("just before Timer H: {before_h:?}"),
        format!("retransmissions after Timer H: {late}"),
        format!("10s after Timer H: {after_h:?}"),
        format!("orphan-ACK warnings: {}", h.logs.count(ORPHAN_ACK_WARN)),
    ];
    report(&format!("C0a/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert!(
        released.is_some(),
        "session store did not return to baseline"
    );
    assert_eq!(
        after_release.state_count("Completed"),
        1,
        "the INVITE server transaction must still be in Completed after the session release"
    );
    assert!(
        close(&actual, &expected),
        "retransmissions {actual:?} do not follow {expected:?}"
    );
    assert_eq!(
        before_h.state_count("Completed"),
        1,
        "Completed until Timer H"
    );
    assert_eq!(late, 0, "retransmission after Timer H");
    assert_eq!(
        after_h.server_transactions, baseline.server_transactions,
        "the transaction must end on Timer H"
    );
}

over_udp_and_tcp!(
    c0a_480_without_ack_retransmits_until_timer_h,
    c0a_480_without_ack_over_tcp_ends_on_timer_h,
    c0a
);

/// C0b: the first 480 is lost on the way to the client. The retransmission
/// arrives, its ACK confirms the transaction, retransmissions stop and Timer
/// I ends it. UDP only: a reliable transport does not lose it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn c0b_lost_first_480_is_recovered_by_timer_g() {
    let mut h = Harness::start(Wire::Udp, Mode::Reject480).await;
    let baseline = h.snapshot().await;
    let tag = "c0b";

    // Dropped on the way: the client does not act on it and the stack got
    // no send error.
    h.ringing(tag).await;
    let (first_final, response) = h.expect(480, "INVITE").await;
    let released = h.session_released(baseline.sessions, T1 / 2).await;

    h.run_until(first_final + T1 + TOLERANCE).await;
    let recovered = h.arrivals(480, "INVITE")[1..].to_vec();
    let mut confirmed = None;
    let mut after_ack = 0;
    let mut after_timer_i = None;
    let mut removed = None;
    if !recovered.is_empty() {
        h.send(h.non_2xx_ack(tag, &response, None)).await;
        h.quiesce().await;
        confirmed = Some(h.snapshot().await);
        let acked_at = Instant::now();
        let before = h.count(480, "INVITE");
        h.run_until(acked_at + TIMER_I - STEP).await;
        after_ack = h.count(480, "INVITE") - before;
        h.run_until(acked_at + TIMER_I + TOLERANCE).await;
        after_timer_i = Some(h.snapshot().await);
        h.run_until(acked_at + TIMER_I + REMOVAL_GRACE).await;
        removed = Some(h.snapshot().await);
    }

    let lines = vec![
        format!("session released after {released:?} of virtual time"),
        format!(
            "retransmissions after the lost 480: {:?}",
            offsets(first_final, &recovered)
        ),
        format!("after ACK: {confirmed:?}"),
        format!("retransmissions after ACK: {after_ack}"),
        format!("after Timer I: {after_timer_i:?}"),
        format!("after the removal grace: {removed:?}"),
        format!("non-2xx ACK path: {}", h.logs.count(NON_2XX_ACK)),
        format!(
            "dialog-matched 2xx path: {}",
            h.logs.count(DIALOG_MATCHED_ACK)
        ),
        format!("orphan-ACK warnings: {}", h.logs.count(ORPHAN_ACK_WARN)),
    ];
    report("C0b", &lines, &h.logs);
    h.stop().await;

    assert!(
        released.is_some(),
        "session store did not return to baseline"
    );
    assert!(
        close(&offsets(first_final, &recovered), &[T1]),
        "the lost 480 must be retransmitted once at T1: {:?}",
        offsets(first_final, &recovered)
    );
    let confirmed = confirmed.expect("ACK sent");
    assert_eq!(confirmed.state_count("Confirmed"), 1, "ACK must confirm");
    assert_eq!(after_ack, 0, "retransmissions after the ACK");
    let after_timer_i = after_timer_i.expect("Timer I checked");
    assert_eq!(
        after_timer_i.state_count("Terminated"),
        after_timer_i.server_transactions,
        "Timer I must end the transaction"
    );
    assert_eq!(
        removed.expect("removal checked").server_transactions,
        baseline.server_transactions,
        "the terminated transaction must be removed"
    );
}

/// C0c: the ACK of the 480 takes the non-2xx transaction path, never the
/// dialog-matched 2xx path. The client ACKs the first 480 right away, as in
/// the observed INVITE -> 180 -> 480 -> ACK exchange.
async fn c0c(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Reject480).await;
    let baseline = h.snapshot().await;
    let tag = "c0c";

    h.ringing(tag).await;
    let (first_final, response) = h.expect(480, "INVITE").await;
    let released = h.session_released(baseline.sessions, T1 / 2).await;
    let before_ack = h.snapshot().await;

    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;
    let after_ack = h.snapshot().await;
    let before = h.count(480, "INVITE");
    h.run_until(first_final + TIMER_I - STEP).await;
    let retransmits = h.count(480, "INVITE") - before;

    let non_2xx = h.logs.count(NON_2XX_ACK);
    let dialog_matched = h.logs.count(DIALOG_MATCHED_ACK);
    let orphan = h.logs.count(ORPHAN_ACK_WARN);
    let session_ack = h.logs.count(SESSION_ACK);
    let lines = vec![
        format!("session released after {released:?} of virtual time"),
        format!("before ACK: {before_ack:?}"),
        format!("after ACK: {after_ack:?}"),
        format!("retransmissions after ACK: {retransmits}"),
        format!("non-2xx ACK path: {non_2xx}"),
        format!("dialog-matched 2xx path: {dialog_matched}"),
        format!("orphan-ACK warnings: {orphan}"),
        format!("session ACK projections: {session_ack}"),
    ];
    report(&format!("C0c/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert!(
        released.is_some(),
        "session store did not return to baseline"
    );
    assert_eq!(
        before_ack.state_count("Completed"),
        1,
        "the transaction must be live in Completed when the ACK arrives"
    );
    assert!(
        after_ack.acked(wire),
        "the ACK must confirm the live transaction"
    );
    assert_eq!(retransmits, 0, "retransmissions after the ACK");
    assert_eq!(non_2xx, 1, "ACK must take the non-2xx path");
    assert_eq!(dialog_matched, 0, "ACK must not take the 2xx path");
    assert_eq!(orphan, 0, "no orphan 2xx-ACK warning for a non-2xx ACK");
    assert_eq!(session_ack, 0, "a non-2xx ACK is not a session ACK");
}

over_udp_and_tcp!(
    c0c_ack_of_480_takes_the_non_2xx_path,
    c0c_ack_of_480_over_tcp_takes_the_non_2xx_path,
    c0c
);

// ===== A: ACK classification by the final the transaction sent =====

/// A1 and A2: the ACK of a 200 is an end-to-end `AckRequest` that reaches the
/// session exactly once. A second copy, after the binding was consumed, is
/// the orphan 2xx ACK and warns exactly once.
async fn a1_a2(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Accept).await;
    let tag = "a1";

    h.ringing(tag).await;
    let (_, ok) = h.expect(200, "INVITE").await;
    h.send(h.ack_2xx(tag, &ok)).await;
    h.quiesce().await;
    let first = (
        h.logs.count(DIALOG_MATCHED_ACK),
        h.logs.count(SESSION_ACK),
        h.logs.count(ORPHAN_ACK_WARN),
    );
    h.send(h.ack_2xx(tag, &ok)).await;
    h.quiesce().await;
    let second = (
        h.logs.count(DIALOG_MATCHED_ACK),
        h.logs.count(SESSION_ACK),
        h.logs.count(ORPHAN_ACK_WARN),
    );
    let non_2xx = h.logs.count(NON_2XX_ACK);

    let lines = vec![
        format!("after the ACK (2xx path, session ACK, orphan warn): {first:?}"),
        format!("after a second copy: {second:?}"),
        format!("non-2xx ACK path: {non_2xx}"),
    ];
    report(&format!("A1-A2/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(
        first,
        (1, 1, 0),
        "A1: one AckRequest, one session projection"
    );
    assert_eq!(
        second,
        (2, 1, 1),
        "A2: the unbound copy warns once and projects nothing"
    );
    assert_eq!(non_2xx, 0, "a 2xx ACK never takes the non-2xx path");
}

over_udp_and_tcp!(
    a1_a2_2xx_ack_is_an_ack_request_projected_once,
    a1_a2_2xx_ack_over_tcp_is_an_ack_request_projected_once,
    a1_a2
);

/// A3: a duplicate ACK of a 480 is absorbed in `Confirmed`, with no session
/// projection and no 2xx handling. Over TCP Timer I is zero, so the
/// transaction ends on the first ACK and a copy is stray, still with no
/// session projection and no 2xx handling.
async fn a3(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Reject480).await;
    let tag = "a3";

    h.ringing(tag).await;
    let (_, response) = h.expect(480, "INVITE").await;
    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;
    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;
    let after = h.snapshot().await;

    let counts = (
        h.logs.count(NON_2XX_ACK),
        h.logs.count(DIALOG_MATCHED_ACK),
        h.logs.count(SESSION_ACK),
        h.logs.count(ORPHAN_ACK_WARN),
        h.logs.count(STRAY_ACK),
    );
    let lines = vec![
        format!("after two ACKs: {after:?}"),
        format!("(non-2xx, 2xx path, session ACK, orphan warn, stray): {counts:?}"),
    ];
    report(&format!("A3/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    match wire {
        Wire::Udp => {
            assert_eq!(after.state_count("Confirmed"), 1);
            assert_eq!(counts, (2, 0, 0, 0, 0));
        }
        Wire::Tcp => {
            assert_eq!(
                after.state_count("Confirmed"),
                0,
                "Timer I is zero over TCP"
            );
            assert_eq!(counts, (1, 0, 0, 0, 1));
        }
    }
}

over_udp_and_tcp!(
    a3_duplicate_non_2xx_ack_is_absorbed_in_confirmed,
    a3_duplicate_non_2xx_ack_over_tcp_is_absorbed_in_confirmed,
    a3
);

/// A4: an ACK of the 480 after Timer H ended the transaction is stray, never
/// a 2xx ACK, even though the dialog index still holds the binding.
async fn a4(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Reject480).await;
    let tag = "a4";

    h.ringing(tag).await;
    let (first_final, response) = h.expect(480, "INVITE").await;
    h.run_until(first_final + TIMER_H + REMOVAL_GRACE).await;
    let before_ack = h.snapshot().await;
    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;

    let counts = (
        h.logs.count(STRAY_ACK),
        h.logs.count(DIALOG_MATCHED_ACK),
        h.logs.count(SESSION_ACK),
        h.logs.count(ORPHAN_ACK_WARN),
        h.logs.count(NON_2XX_ACK),
    );
    let lines = vec![
        format!("before the late ACK: {before_ack:?}"),
        format!("(stray, 2xx path, session ACK, orphan warn, non-2xx): {counts:?}"),
    ];
    report(&format!("A4/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(
        before_ack.server_transactions, 0,
        "Timer H ended the transaction"
    );
    assert_eq!(counts, (1, 0, 0, 0, 0));
}

over_udp_and_tcp!(
    a4_non_2xx_ack_after_timer_h_is_stray,
    a4_non_2xx_ack_over_tcp_after_timer_h_is_stray,
    a4
);

// ===== M: server transaction matching (RFC 3261 §17.2.3) =====

/// M1: the same branch from another sent-by is another transaction. A CANCEL
/// gets 481 and leaves the INVITE alone; an ACK does not confirm the 480.
async fn m1(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Hold).await;
    let tag = "m1";
    let foreign = "127.0.0.1:9";

    h.ringing(tag).await;
    h.send(h.cancel(tag, tag, Some(foreign), None, "")).await;
    let (_, _) = h.expect(481, "CANCEL").await;
    h.quiesce().await;
    let after_cancel = h.snapshot().await;
    let terminated = h.count(487, "INVITE");

    let coordinator = h.coordinator.clone();
    coordinator
        .reject(&h.held_call())
        .with_status(480)
        .with_reason("Temporarily Unavailable")
        .send()
        .await
        .expect("480 after the foreign CANCEL");
    let (first_final, response) = h.expect(480, "INVITE").await;
    h.send(h.non_2xx_ack(tag, &response, Some(foreign))).await;
    h.quiesce().await;
    let after_foreign_ack = h.snapshot().await;
    h.run_until(first_final + T1 + TOLERANCE).await;
    let retransmitted = h.count(480, "INVITE") > 1;
    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;
    let after_ack = h.snapshot().await;

    let lines = vec![
        format!("after the foreign CANCEL: {after_cancel:?}"),
        format!("487 after the foreign CANCEL: {terminated}"),
        format!("after the foreign ACK: {after_foreign_ack:?}"),
        format!("480 retransmitted after the foreign ACK: {retransmitted}"),
        format!("after the matching ACK: {after_ack:?}"),
    ];
    report(&format!("M1/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(
        after_cancel.state_count("Proceeding"),
        1,
        "the INVITE is unaffected"
    );
    assert_eq!(terminated, 0, "no 487 for a CANCEL that does not match");
    assert_eq!(
        after_foreign_ack.state_count("Completed"),
        1,
        "an ACK from another sent-by does not confirm the 480"
    );
    assert_eq!(
        retransmitted,
        wire == Wire::Udp,
        "Timer G keeps running over UDP"
    );
    assert!(after_ack.acked(wire));
}

over_udp_and_tcp!(
    m1_same_branch_other_sent_by_does_not_match,
    m1_same_branch_other_sent_by_over_tcp_does_not_match,
    m1
);

// ===== C: CANCEL against the INVITE final (RFC 3261 §9.2) =====

/// C1: a conforming CANCEL while the INVITE is in `Proceeding` gets 200, and
/// the INVITE gets exactly one 487.
async fn c1(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Hold).await;
    let baseline = h.snapshot().await;
    let tag = "c1";

    h.ringing(tag).await;
    h.send(h.cancel(tag, tag, None, None, "")).await;
    let (_, _) = h.expect(200, "CANCEL").await;
    let (_, terminated) = h.expect(487, "INVITE").await;
    h.send(h.non_2xx_ack(tag, &terminated, None)).await;
    h.quiesce().await;
    let released = h.session_released(baseline.sessions, T1 / 2).await;
    h.run_until(Instant::now() + TIMER_I + REMOVAL_GRACE).await;
    let after = h.snapshot().await;
    let counts = (
        h.count(200, "CANCEL"),
        h.count(487, "INVITE"),
        h.count(480, "INVITE"),
    );

    let lines = vec![
        format!("(200 CANCEL, 487 INVITE, 480 INVITE): {counts:?}"),
        format!("session released after {released:?}"),
        format!("after Timer I: {after:?}"),
    ];
    report(&format!("C1/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(counts, (1, 1, 0));
    assert!(released.is_some(), "the cancelled session is released");
    assert_eq!(after.server_transactions, baseline.server_transactions);
}

over_udp_and_tcp!(
    c1_cancel_in_proceeding_gets_200_and_one_487,
    c1_cancel_over_tcp_in_proceeding_gets_200_and_one_487,
    c1
);

/// C2: a conforming CANCEL after the local 480 gets 200. The 480 stands and
/// no 487 is sent.
async fn c2(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Reject480).await;
    let tag = "c2";

    h.ringing(tag).await;
    let (first_final, response) = h.expect(480, "INVITE").await;
    h.send(h.cancel(tag, tag, None, None, "")).await;
    let (_, _) = h.expect(200, "CANCEL").await;
    h.quiesce().await;
    let after_cancel = h.snapshot().await;
    h.run_until(first_final + T1 + TOLERANCE).await;
    let finals = h.count(480, "INVITE");
    h.send(h.non_2xx_ack(tag, &response, None)).await;
    h.quiesce().await;
    let after_ack = h.snapshot().await;
    let terminated = h.count(487, "INVITE");

    let lines = vec![
        format!("after the CANCEL: {after_cancel:?}"),
        format!("480 by T1: {finals}, 487: {terminated}"),
        format!("after the ACK: {after_ack:?}"),
    ];
    report(&format!("C2/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(terminated, 0, "no 487 after a final");
    assert_eq!(after_cancel.state_count("Completed"), 1, "the 480 stands");
    let expected_finals = if wire == Wire::Udp { 2 } else { 1 };
    assert_eq!(
        finals, expected_finals,
        "the 480, retransmitted over UDP only"
    );
    assert!(after_ack.acked(wire));
}

over_udp_and_tcp!(
    c2_cancel_after_the_local_final_preserves_it,
    c2_cancel_over_tcp_after_the_local_final_preserves_it,
    c2
);

/// C3: the CANCEL and the local 480 race to the INVITE. Exactly one final
/// crosses the transport and the CANCEL gets 200 whatever the order: CANCEL
/// handled first (487), final committed first (480), or both in flight. The
/// exact write-boundary interleaving is pinned down by the transaction
/// manager unit test with a transport barrier.
async fn c3(wire: Wire) {
    #[derive(Clone, Copy, Debug)]
    enum Order {
        CancelFirst,
        FinalFirst,
        Concurrent,
    }
    let mut h = Harness::start(wire, Mode::Hold).await;
    let mut outcomes = Vec::new();
    let rounds = [
        Order::CancelFirst,
        Order::FinalFirst,
        Order::Concurrent,
        Order::Concurrent,
        Order::Concurrent,
    ];

    for (round, order) in rounds.into_iter().enumerate() {
        let tag = format!("c3-{round}");
        h.ringing(&tag).await;
        let call = h.held_call();
        let coordinator = h.coordinator.clone();
        let reject = async move {
            let _ = coordinator
                .reject(&call)
                .with_status(480)
                .with_reason("Temporarily Unavailable")
                .send()
                .await;
        };
        let cancel = h.cancel(&tag, &tag, None, None, "");
        match order {
            Order::CancelFirst => {
                h.send(cancel).await;
                let _ = h.expect_nth(200, "CANCEL", round + 1).await;
                reject.await;
            }
            Order::FinalFirst => {
                reject.await;
                h.send(cancel).await;
            }
            Order::Concurrent => {
                let task = tokio::spawn(reject);
                h.send(cancel).await;
                task.await.expect("reject task");
            }
        }
        let _ = h.expect_nth(200, "CANCEL", round + 1).await;
        h.quiesce().await;
        let invite_finals: Vec<String> = h
            .seen
            .iter()
            .map(|(_, text)| text)
            .filter(|text| {
                header(text, "Call-ID").is_some_and(|id| id.starts_with(&format!("{tag}@")))
                    && (is_response(text, 480, "INVITE") || is_response(text, 487, "INVITE"))
            })
            .cloned()
            .collect();
        // Over UDP the winning final is retransmitted; count distinct finals.
        let mut statuses: Vec<String> = invite_finals
            .iter()
            .map(|text| text.split_whitespace().nth(1).unwrap_or("?").to_string())
            .collect();
        statuses.dedup();
        if let Some(first) = invite_finals.first() {
            h.send(h.non_2xx_ack(&tag, first, None)).await;
            h.quiesce().await;
        }
        outcomes.push((order, statuses));
    }

    let lines = vec![format!("(order, INVITE finals): {outcomes:?}")];
    report(&format!("C3/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    for (order, statuses) in &outcomes {
        assert_eq!(
            statuses.len(),
            1,
            "exactly one final to the INVITE ({order:?}): {statuses:?}"
        );
        match order {
            Order::CancelFirst => assert_eq!(statuses[0], "487"),
            Order::FinalFirst => assert_eq!(statuses[0], "480"),
            Order::Concurrent => {}
        }
    }
}

over_udp_and_tcp!(
    c3_cancel_racing_the_final_yields_one_final,
    c3_cancel_over_tcp_racing_the_final_yields_one_final,
    c3
);

/// C4: a CANCEL whose branch matches no INVITE gets 481 and the INVITE is
/// untouched.
async fn c4(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Hold).await;
    let tag = "c4";

    h.ringing(tag).await;
    h.send(h.cancel(tag, "c4-unknown", None, None, "")).await;
    let (_, _) = h.expect(481, "CANCEL").await;
    h.quiesce().await;
    let after = h.snapshot().await;
    let terminated = h.count(487, "INVITE");

    let lines = vec![format!(
        "after the unmatched CANCEL: {after:?}, 487: {terminated}"
    )];
    report(&format!("C4/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(after.state_count("Proceeding"), 1);
    assert_eq!(terminated, 0);
}

over_udp_and_tcp!(
    c4_unmatched_cancel_gets_481,
    c4_unmatched_cancel_over_tcp_gets_481,
    c4
);

/// C5: a duplicate CANCEL is answered by the CANCEL transaction again and has
/// no second effect on the INVITE. Over TCP Timer J is zero, so there is no
/// CANCEL transaction left to answer the copy (a conforming UAC never sends
/// one); the invariant checked there is that the INVITE sees no second
/// effect.
async fn c5(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Hold).await;
    let tag = "c5";

    h.ringing(tag).await;
    let cancel = h.cancel(tag, tag, None, None, "");
    h.send(cancel.clone()).await;
    let (_, _) = h.expect(200, "CANCEL").await;
    let (_, terminated) = h.expect(487, "INVITE").await;
    h.send(h.non_2xx_ack(tag, &terminated, None)).await;
    h.quiesce().await;
    h.send(cancel).await;
    h.quiesce().await;
    let counts = (
        h.count(200, "CANCEL"),
        h.count(487, "INVITE"),
        h.count(481, "CANCEL"),
    );
    let cancel_responses: Vec<String> = h
        .seen
        .iter()
        .map(|(_, text)| text)
        .filter(|text| {
            text.starts_with("SIP/2.0 ")
                && header(text, "CSeq").is_some_and(|cseq| cseq.ends_with("CANCEL"))
        })
        .map(|text| text.lines().next().unwrap_or("").to_string())
        .collect();

    let lines = vec![
        format!("(200 CANCEL, 487 INVITE, 481 CANCEL): {counts:?}"),
        format!("CANCEL responses: {cancel_responses:?}"),
    ];
    report(&format!("C5/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(counts.1, 1, "no second 487 to the INVITE");
    if wire == Wire::Udp {
        assert_eq!(counts, (2, 1, 0), "the CANCEL transaction answers the copy");
    }
}

over_udp_and_tcp!(
    c5_duplicate_cancel_is_answered_without_a_second_effect,
    c5_duplicate_cancel_over_tcp_is_answered_without_a_second_effect,
    c5
);

/// C6: interoperability only, never evidence for the conforming case. The
/// CANCEL copies the To tag of the 180 and carries `received=` in its Via,
/// as the observed client did. Neither field is part of the match.
async fn c6(wire: Wire) {
    let mut h = Harness::start(wire, Mode::Hold).await;
    let tag = "c6";

    let ringing = h.ringing(tag).await;
    let to_with_tag = header(&ringing, "To").expect("180 To");
    h.send(h.cancel(tag, tag, None, Some(&to_with_tag), ";received=127.0.0.1"))
        .await;
    h.quiesce().await;
    let counts = (
        h.count(200, "CANCEL"),
        h.count(481, "CANCEL"),
        h.count(487, "INVITE"),
    );

    let lines = vec![format!("(200 CANCEL, 481 CANCEL, 487 INVITE): {counts:?}")];
    report(&format!("C6/{wire:?}"), &lines, &h.logs);
    h.stop().await;

    assert_eq!(counts, (1, 0, 1));
}

over_udp_and_tcp!(
    c6_cancel_with_copied_to_tag_is_accepted,
    c6_cancel_over_tcp_with_copied_to_tag_is_accepted,
    c6
);
