# INVITE server transaction after a local final response

RFC 3261 §17.2.1: an INVITE server transaction that sent a 300-699 final stays
in `Completed`. Over UDP it retransmits the final on Timer G. An ACK moves it
to `Confirmed` and Timer I ends it; without an ACK, Timer H ends it. The
session that produced the final can be released right away. The transaction
cannot.

The regression tests live in
`crates/sip/rvoip-sip/tests/invite_server_transaction_after_local_final.rs`.

## C0: baseline measurements

Recorded on 2026-09-22, before any code change.

### Harness

- `CallbackPeer` UAS on UDP with the automatic 180. The handler waits until the
  client has read the 180, then rejects with 480 through `RejectBuilder`
  (`coordinator.reject(..).with_status(480).send()`).
- The UAC is a raw UDP socket: INVITE, then read the 180 and the 480.
- Paused Tokio clock with the RFC defaults (T1 500 ms, T2 4 s, Timer H 32 s,
  Timer I 5 s). The test moves the clock by hand in 10 ms steps
  (`tokio::time::advance`). Between steps, a short `spawn_blocking` task lets
  real loopback I/O finish without moving virtual time, because a running
  blocking task inhibits auto-advance. With plain auto-advance, the clock
  sometimes jumped 5 s before a loopback datagram became readable, so the
  results were not repeatable.
- The transaction state and the session store come from
  `UnifiedCoordinator::perf_diagnostic_snapshot()` (`perf-tests` feature):
  `transaction_manager.server_transactions`,
  `transaction_manager.breakdown.server_by_state`, `session_store.total` and
  `transaction_manager.server_invite_dialog_index`.
- A tracing layer counts three log lines as supporting evidence only: the
  non-2xx ACK path, the dialog-matched 2xx path and the orphan-ACK warning.
- "Lost first 480" (C0b) means the client ignores the first 480. The stack got
  no send error.

The two baselines were built in separate target directories. Sharing one
target directory between the main tree and a worktree gave the two builds the
same artifact hash, and later "bdaa9b8f" runs were actually running the
1d4ce510 build.

### Commands

```text
# bdaa9b8f (main tree)
cargo test -p rvoip-sip --features perf-tests \
  --test invite_server_transaction_after_local_final -- --nocapture --test-threads=1

# 1d4ce510 (detached worktree, same test file copied in, own target dir)
git worktree add --detach <wt> 1d4ce510
CARGO_TARGET_DIR=<own-dir> cargo test -p rvoip-sip --features perf-tests \
  --test invite_server_transaction_after_local_final -- --nocapture --test-threads=1
```

### Results

| Case | 1d4ce510 | bdaa9b8f |
|---|---|---|
| C0a: session released after the 480 | no (`sessions: 1` until the test ends) | yes, with no virtual time elapsed |
| C0a: INVITE server transaction right after the 480 | gone (`server_transactions: 0`) | gone (`server_transactions: 0`) |
| C0a: Timer G retransmissions (expected at 0.5, 1.5, 3.5, 7.5, 11.5 ... 31.5 s) | none | none |
| C0a: transaction ends on Timer H | no transaction left to end | no transaction left to end |
| C0b: retransmission after the lost 480 | none, the call cannot recover | none, the call cannot recover |
| C0c: transaction live when the ACK arrives | no | no |
| C0c: ACK path | dialog-matched "2xx" path, 1 orphan-ACK `WARN` | dialog-matched "2xx" path, 1 orphan-ACK `WARN` |
| Verdict | C0a, C0b and C0c fail | C0a, C0b and C0c fail |

C0d: the transaction behavior is identical in both baselines. The only
difference is the session. 1d4ce510 leaks it, and bdaa9b8f releases it.

Excerpt of the bdaa9b8f run:

```text
C0a: session released after Some(0ns) of virtual time
C0a: after release: TransactionView { sessions: 0, server_transactions: 0, server_by_state: Object {}, dialog_index: 1 }
C0a: retransmissions at []
C0a: expected Timer G at [500ms, 1.5s, 3.5s, 7.5s, 11.5s, 15.5s, 19.5s, 23.5s, 27.5s, 31.5s]
C0c: before ACK: TransactionView { sessions: 0, server_transactions: 0, server_by_state: Object {}, dialog_index: 1 }
C0c: non-2xx ACK path: 0
C0c: dialog-matched 2xx path: 1
C0c: orphan-ACK warnings: 1
test result: FAILED. 0 passed; 3 failed
```

Excerpt of the 1d4ce510 run:

```text
C0a: session released after None of virtual time
C0a: after release: TransactionView { sessions: 1, server_transactions: 0, server_by_state: Object {}, dialog_index: 1 }
C0a: retransmissions at []
C0c: before ACK: TransactionView { sessions: 1, server_transactions: 0, server_by_state: Object {}, dialog_index: 1 }
C0c: dialog-matched 2xx path: 1
C0c: orphan-ACK warnings: 1
test result: FAILED. 0 passed; 3 failed
```

### Who removes the transaction

The early removal predates bdaa9b8f. Debug logs of one C0c run on bdaa9b8f,
in order (`C0_DUMP_LOGS=1`):

```text
rvoip_sip::state_machine::executor   State transition: Ringing -> Terminated
rvoip_sip::state_machine::actions    Action::SendRejectResponse ... with status 480
rvoip_sip_dialog::transaction::runner  State transition: Proceeding -> Completed
rvoip_sip_dialog::transaction::server::invite  Entered Completed state, starting Timers G and H
rvoip_sip::state_machine::actions    Executing action: CleanupDialog
rvoip_sip_dialog::transaction::runner  Received Terminate command, shutting down transaction
rvoip_sip_dialog::transaction::manager Removing terminated transaction after grace period
...
rvoip_sip::api::unified              local BYE finalizer owns exact terminal release
rvoip_sip::session_store::store      removed exact SIP session lifetime
...
rvoip_sip_dialog::transaction::manager::handlers  Found ACK for 2xx response using dialog-based matching
rvoip_sip_dialog::manager::core      Dropping ACK whose exact server INVITE has no dialog binding
```

The `CleanupDialog` action of the `RejectCall` transition in
`state_tables/default.yaml` (the same action exists for redirect, and in both
baselines) calls `DialogAdapter::cleanup_session_exact_lane_owned`. That calls
`DialogManager::cleanup_dialog_storage_and_transactions`, which runs
`terminate_transaction` on every transaction indexed to the dialog, including
the INVITE server transaction that entered `Completed` a moment earlier. The
release that bdaa9b8f added reaches the same cleanup later, but by then the
transaction is already gone.

The hypothesis is therefore confirmed in mechanism (the forced dialog cleanup
destroys the `Completed` transaction) and refuted in attribution (bdaa9b8f
did not start it).

The observed production symptoms follow from this:

- ACK of the 480: the branch lookup misses because the transaction is gone,
  `server_invite_dialog_index` still holds the entry, and the ACK is labeled
  as a 2xx ACK. It then hits the orphan-ACK `WARN`.
- No retransmission after the ACK: there was no transaction left to
  retransmit.
- 481 to a CANCEL that arrived before the 480 was written: the CANCEL is
  matched after the reject cleanup, so the INVITE is no longer in
  `server_transactions`.

## Decision on correction 1

C0a and C0b fail on bdaa9b8f because the transaction is removed early, so the
correction applies. The remover is not the hypothesized one, though: it is
the dialog cleanup that the session runs (the `CleanupDialog` action, and
later the exact release), not a path that only bdaa9b8f added. The fix is
therefore placed in that cleanup, whoever calls it, and bdaa9b8f's immediate
session release stays as it is.

## Corrections

### 1. Session lifetime and transaction lifetime

- `DialogManager::cleanup_dialog_storage_for_session_end` (new) removes the
  dialog, its indexes and its other transactions like the forced variant, but
  leaves an INVITE server transaction that owns a 300-699 final
  (`TransactionManager::server_invite_owns_non_2xx_final`: live, `Completed`
  or `Confirmed`) running. The transaction is unlinked from the dialog, so its
  later events arrive unassociated.
- `cleanup_dialog_storage_and_transactions` (forced) is unchanged and still
  has its own test. Rollback of an outbound INVITE and shutdown keep using it.
  An INVITE with no final yet is still terminated by the session-end variant,
  which covers rollback before any final was sent.
- rvoip-sip uses the session-end variant in `DialogAdapter`'s exact session
  cleanup (the `CleanupDialog` action and the exact release) and in the cleanup
  after an admission-overload rejection.
- Found by the TCP half of the matrix: the server INVITE started Timer G on
  every transport and Timer I always used T4. Timer G now runs only on an
  unreliable response route, and Timer I is zero on a reliable one (RFC 3261
  §17.2.1). Timer H is unchanged.

### 2. ACK classification

- The dialog-index ACK path publishes `AckRequest` (with its source) instead
  of `AckReceived`. `AckReceived` is emitted only by the transaction that
  absorbed the ACK of a non-2xx final.
- Dialog-core hands `AckRequest` to the session ACK handling (media start,
  session ACK event). `AckReceived` is an observation only, bound or not.
- The orphan-ACK `WARN` fires only for an `AckRequest` without an exact
  binding. An unbound `AckReceived` logs at debug.
- Each dialog-index binding records the class of the final its transaction
  authorized (`ServerInviteFinalClass`). `TransactionManager::send_response`
  records it before the write, the first committed final wins, and a
  zero-wire retryable attempt (transaction back in `Proceeding`) clears it.
  `find_server_invite_for_ack` only matches a binding that authorized a 2xx,
  so a late non-2xx ACK is stray, never a 2xx ACK.
- The branch path takes the ACK when the transaction is in `Completed`, or in
  `Confirmed` (a retransmitted ACK is absorbed by the transaction, not sent to
  the dialog index). It also takes it in `Proceeding` when a non-2xx final is
  already at the write boundary. The upstream `f0f3824e` covers the same
  transition with the same test shape. It reads `last_response` under its
  lock; this version uses the recorded final class instead, because that lock
  is held across the write.
- The `AckReceived` and `AckRequest` documentation in
  `transaction/event.rs` no longer contradicts itself.

### 3. Server transaction matching

- `TransactionManager::server_request_sent_by_matches` compares the
  normalized top Via sent-by (`NormalizedViaSentBy`: host without case and
  trailing dot, port defaulted by transport) with the request that created
  the transaction. `TransactionKey` keeps its public shape.
- It gates retransmission matching, the non-2xx ACK path, the CANCEL match in
  `handle_request`, the inherited CANCEL principal and
  `find_invite_server_transaction_for_cancel`. A CANCEL with the same branch
  and another sent-by gets 481. Any other request with a colliding key gets a
  stateless 500 with `Retry-After: 1`, the answer for any request that cannot
  open a server transaction, and is counted. It is never dropped in silence
  (`retained_transaction_key_ingress` covers a TCP reconnect with a new
  sent-by).
- The peer/flow binding under listener authorization is unchanged and already
  covered (M2 below).

### 4. CANCEL against the final

- `handle_cancel_request_event` answers 200 to a matched CANCEL. It then sends
  487 only while the INVITE has no final
  (`TransactionManager::server_invite_has_final`: left `Proceeding`, or a final
  write started). When the 487 is refused because another final won the write,
  that final stands and the CANCEL is done. The dialog is terminated as
  cancelled only when the 487 was sent.

### Diagnostics

New `rvoip_sip_dialog::diagnostics::Snapshot` counters, with no identifiers or
payloads: `non_2xx_invite_server_retained`,
`non_2xx_invite_server_ack_confirmed`, `non_2xx_invite_server_timer_h` and
`server_sent_by_mismatch`. The session side already has
`cleanup_diag::local_final_response_released`.

## Results after the corrections

`cargo test -p rvoip-sip --features perf-tests --test invite_server_transaction_after_local_final`:
25 passed, stable over three runs.

| Case | UDP | TCP |
|---|---|---|
| C0a: 480, no ACK | session released at once; `Completed`; retransmissions at 0.5, 1.5, 3.5, 7.5 ... 31.5 s; ended on Timer H | session released; `Completed`; no retransmission; ended on Timer H |
| C0b: first 480 lost | recovered at 500 ms; ACK to `Confirmed`; no retransmission after it; Timer I, then removed | not applicable |
| C0c: ACK of the 480 | non-2xx path, `Confirmed`, no `WARN`, no session ACK | non-2xx path, ended at once (Timer I zero), no `WARN` |
| A1: 2xx ACK with binding | one `AckRequest`, one session ACK | same |
| A2: 2xx ACK without binding | exactly one orphan `WARN`, no projection | same |
| A3: duplicate non-2xx ACK | absorbed in `Confirmed`, nothing projected | the copy is stray (Timer I zero), nothing projected, no `WARN` |
| A4: non-2xx ACK after Timer H | stray, never `AckRequest` | same |
| M1: same branch, other sent-by | CANCEL 481, INVITE untouched; ACK does not confirm; Timer G keeps running | same, without Timer G |
| M2: same branch and sent-by, other peer | covered by `ingress_authorization_binds_replays_and_cancel_to_transport_peer` and `ingress_authorization_binds_non_2xx_ack_to_transport_peer` (sip-dialog) | transport independent |
| C1: CANCEL in `Proceeding` | 200 to CANCEL, one 487, session released | same |
| C2: CANCEL after the 480 | 200 to CANCEL, no 487, 480 kept | same |
| C3: CANCEL races the final | one final per order (487 when the CANCEL is handled first, 480 when the final is, one of them when concurrent); write boundary pinned by `a_final_at_the_write_boundary_refuses_a_second_final` | same |
| C4: unmatched CANCEL | 481, INVITE untouched | same |
| C5: duplicate CANCEL | second 200 from the CANCEL transaction, no second 487 | no second 487; the copy is answered statelessly with 200 (481 once the INVITE is gone), never 500 |
| C6: CANCEL with the 180 To tag and `received=` | 200 and one 487 (interop only) | same |

New sip-dialog unit tests:
`session_end_cleanup_keeps_the_invite_server_transaction_of_a_non_2xx_final`,
`session_end_cleanup_still_terminates_an_invite_without_a_final`,
`non_2xx_ack_is_a_transaction_observation_only`,
`non_2xx_ack_at_the_final_write_boundary_is_transaction_owned`,
`non_2xx_final_never_turns_a_dialog_matched_ack_into_a_2xx_ack`,
`same_branch_with_another_sent_by_never_matches_the_server_transaction` and
`a_final_at_the_write_boundary_refuses_a_second_final`.

## Follow-up fixes

- Duplicate CANCEL over TCP. Timer J is zero on a reliable transport, so a
  copy that arrives while the CANCEL transaction is being retired cannot open
  a transaction (`transaction_exists`) and used to get the generic stateless
  500. A CANCEL copy is now answered statelessly with a recomputed result,
  which has no side effect (RFC 3261 §9.2): 200 while the matched INVITE
  exists (the first CANCEL already left it with a final), 481 once it is gone.
- The server-INVITE ACK index (binding deadline and expiry queue) runs on
  `tokio::time::Instant`, the clock of the transaction timers. C0a now checks
  that the retired binding expires under the paused clock.

## Known limitations

- A request with the same branch as a live server transaction but another
  sent-by is a separate transaction by RFC 3261 §17.2.3, but `TransactionKey`
  (public, used by sharding, indexes and diagnostics) has no sent-by, so it
  cannot open its own transaction. It gets a stateless 500 with
  `Retry-After: 1` and never touches the existing transaction. This includes
  a TCP client that reconnects, puts the new port in its Via and resends the
  INVITE with the same branch: before, it got the retained final replayed.
  Fixing it properly means carrying sent-by in the transaction key.
- Other non-INVITE copies over TCP (a BYE, for example) that land in the same
  retirement window still get the generic retriable 500: their original
  response is not retained on a reliable transport and cannot be recomputed.
- A redirect still publishes a generic terminal event; there is no typed
  redirect event.

The C0 cases of the final test file (which adds the TCP variants) were run
again on 1d4ce510 with its own target directory: all five fail the same way
as recorded above (transaction gone right after the 480, no retransmission,
ACK on the 2xx path with one orphan `WARN`, session retained).

## Suites

Debug builds, 2026-09-22:

| Command | Result |
|---|---|
| `cargo test -p rvoip-sip-dialog --no-fail-fast` | 1091 passed, 0 failed |
| `cargo test -p rvoip-sip --no-fail-fast` | 1527 passed, 0 failed, 39 ignored |
| `cargo test -p rvoip-sip --features perf-tests --no-fail-fast` | everything passes except the 16 `perf_*` benchmark targets, which refuse to run outside `--release` ("debug-build numbers are not citable") |
| `cargo test -p rvoip-sip-proxy -p rvoip-sip-registrar --no-fail-fast` | passed |
| `cargo test -p rvoip-sip --features perf-tests --test invite_server_transaction_after_local_final` | 25 passed |
| `cargo test -p rvoip-sip --test local_final_response_session_release` | 7 passed |
