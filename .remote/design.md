# Work Process dispatch: bounded admission, a fair share per round, and a turn that panics let go of

Design only. Nothing in `D:\Repos\Xmip` was changed, built or run. Line numbers are those of the runtime submodule at `1ffd652` (2026-11-12). Its only uncommitted changes, in `src/running.rs` and `src/storage/reached.rs`, touch no file this design cites.

Scope: `module/platform/runtime/src/work_step*` and `src/pool.rs`, their tests, and the records that follow them. No new execution framework: the send step's admission (`send_step/admission.rs`) and its two drop guards (`send_step/dispatch.rs`) are the patterns, applied where their meaning is the same.

---

## 1. What the records and the code say now

**The records.**

- runtime-model.md section 3, *Threads, pools and chunks* (lines 521-529): *"A dynamic, bounded pool per step ... An I/O-bound step's pool grows while work waits, up to a configured maximum — the bulkhead, ADR-0018 clause 11 — and never below one thread."* ADR-0018 clause 11 (line 170): *"Not restarting six at once is a bulkhead."*
- The send step already holds what it takes to its pool's threads (`send_step/admission.rs:5-14`): *"What the node holds is bounded by the pool's threads. A Message is claimed and taken into memory only under a place the pool has room for ... What has no place stays durable and unclaimed in its queue, and its queue is read again the moment a place frees, so a slow far end leaves its backlog in the Ledger, never in memory."* The Work Process step has no such door.
- runtime-model.md section 22 (lines 2593-2596): *"Nothing waits on a thread. An Instance waiting for a Message is a record ... one waiting for a time is the due time of the Journey whose turn started the timer, taken up by a scan when it is due, on any node."* Lines 2533-2534: *"A Process Instance must not use thread, Host Service or node memory as its source of truth."* So a read's cursor is a node's convenience, never truth: losing it on a restart costs a reread and nothing else.
- ADR-0066, amendment 2026-11-12, *a Work Process's queue is waited on* (lines 701-710): *"Its scan is `[tuning] work_scan` ... now only the bound on one wait and the recovery of what no write tells"*, and *"A turn that waited is read again where another was written while it was held (`WorkStep::disown`)."* That behavior is kept unchanged.
- ADR-0066, second amendment 2026-11-12 (lines 746-748): *"What is due in its queue comes with the wake: the Work Process step reads its queue from the page the wait's answer carried."* Kept.
- ADR-0018, amendment 2026-11-12 (lines 1562-1572): the steps wait on their queues on a thread of their own; *"Their scans of every queue stay"* as recovery and the bound on one wait. Kept.
- runtime-model.md section 22, *Process outcome* (lines 2674-2677): an Instance that ends Failed *"leaves it `Failed` with the code and why, kept in its Work Process's queue for an operator's Retry or Dismiss."* A turn that panics ends the same way.

**Unbounded dispatch, in the code.**

- `work_step/dispatch.rs:172-194` (`due`) reads every page of a queue into one `Vec<Held>` before anything is dispatched.
- `work_step/dispatch.rs:121-147` (`scan`) then walks that Vec and hands each entry it owns to the pool (`take`, 196-206).
- `pool.rs:122-134` (`Pool::run`) pushes every piece onto `queued: VecDeque` (line 124). Threads are bounded by `most` (line 125); the queue is not.
- `work_step/dispatch.rs:53-63`: the Work Processes are read in their configured order, each to its end, so the first one's backlog is read and queued ahead of every other one's work.
- A Work Process that names a Correlation takes its turns on the dispatching thread itself (`dispatch.rs:141-142`), so its whole backlog is turned there before the next Work Process is read.

**The panicking turn, in the code.**

- `work_step.rs:199-202` (`own`) records the Journey in `State::owned` before the turn is scheduled.
- `work_step/dispatch.rs:210-230` (`settled`) calls `disown` (line 223) only after `turn()` returns.
- `pool.rs:162-187` (`serve`) catches the panic (line 168) and takes the next piece, but nothing gives the Journey back. Every later read skips it (`own` answers `None`, `dispatch.rs:138-140`), even after its Storage claim (`WORK_LEASE`, 30 s) lapses. The Journey is stranded until the node restarts.
- On the sequenced path (`dispatch.rs:141-142`) the panic is not caught at all. It ends the dispatching thread, and every Work Process on the node stops being dispatched.
- The send step handles the same kind of failure with two guards. `Taking` (`send_step/dispatch.rs:310-323`) gives back a place however a claim ends. `Sending` (325-346) settles a send that panicked: written Failed with why, the claim ended, let go of.

---

## 2. The design in one paragraph

The step admits a turn only under a place in the Work pool. It never holds more turns than the pool has threads, queued and running together: the bulkhead the send step already keeps. Each Work Process keeps how its read of its queue stands between rounds: a continuation cursor, the page a wake brought, whether its head is to be read first, whether to go again from the start, and whether it is starved for a place. Each round, every Work Process with something to read gets one quantum, in rotation: at most one page from the head of its queue (only where it was asked while a pass was under way) and one page from its cursor. A quantum admits no more than the Work Process's share of the pool, which is the pool's threads divided among the Work Processes with work. An entry this node already holds in a turn, or one that failed, is moved past without a turn. Where no place is left, the cursor stays on that entry and the Work Process is read on from there once a place frees.

Every admitted turn is held by an `Owning` guard. It gives the place and the local ownership back however the turn ends, and audits a turn that unwound. The turn itself catches a panic at its boundary, under its claim. There the Journey is written Failed with what the panic said, through the same write a flow's uncaught error uses, and the claim is given back where that write cannot be made.

---

## 3. Bounded admission

### Where the bound is configured

**No new `[tuning]` key.** The bound is the Work pool's `most`: `[tuning] send_threads_per_hardware_thread` times the hardware threads (two by default). `Tuning::work()` (`tuning.rs:230-235`) already sizes the Work pool from it: *"The node's Work pool on this machine, sized as its Send pool"*. That is the configured hardware assumption the send step's admission is bounded by too (`send_step/admission.rs:116-119`, `room_in`).

The other two figures are not hardware assumptions:

- The page is `queue_watch::DUE` (64, `queue_watch.rs:36-39`), already *"a page, as many as the steps read of a queue at once"*.
- One head page and one pass page per Work Process per round is a rule of the algorithm, not a figure.

The doc comment on `Tuning::work` gains one sentence: its `most` also bounds the turns the Work Process step holds. Whether the Work pool should get a key of its own (`work_threads_per_hardware_thread`) is the owner's question, not part of this change.

### How many each Work Process may hold

- **The node.** Turns owned ≤ `limits.most`. Owned means admitted and not yet ended: queued in the pool or running. So the pool's queue never holds more than `most` pieces from this step.
- **One Work Process.** Its held turns stay below `share = most.div_ceil(busy)`. `busy` is the number of Work Processes that hold a turn, have a pass under way, or have their head asked; at least one. A Work Process alone gets the whole pool. With two, each may hold half. A Work Process already above its share admits nothing until its own turns bring it below.
- **Promptness.** A second Work Process that finds the pool full waits for the first turn of any Work Process to end, never for another Work Process's backlog. A turn is short (`WORK_LEASE` doc, `work_step.rs:65-67`: *"a turn is short"*). No static reservation: a place kept free for every idle Work Process would throttle a single busy one on a node configured with many Work Processes.

### `work_step/admission.rs` (new, about 190 lines)

The module doc mirrors `send_step/admission.rs:1-25`: the one door every turn goes through, bounded by the pool's threads, the rest left durable in the Ledger. It moves `own` and `disown` here from `work_step.rs:197-223`, so ownership has one home.

```rust
/// What an admission answered.
pub(super) enum Admitted<'a> {
    /// A place in the Work pool, owned until the guard is dropped.
    Turn(Owning<'a>),
    /// In a turn on this node already: moved past.
    Held,
    /// No place: in the pool, or in this Work Process's share.
    Full,
}

impl WorkStep {
    /// `journey`, of the Work Process at `at`, admitted for a turn within `share`.
    pub(super) fn admit(&self, journey: JourneyId, at: usize, share: usize) -> Admitted<'_> {
        let mut state = self.lock();
        if state.owned.contains(&journey) { return Admitted::Held; }
        if state.owned.len() >= self.limits.most.max(1) || state.readings[at].held >= share {
            return Admitted::Full;
        }
        state.owned.insert(journey);
        state.readings[at].held += 1;
        let since = state.written;
        Admitted::Turn(Owning { step: self, journey, at, since, ended: None })
    }

    /// Moved from work_step.rs:204-223. The body is unchanged: the queue is
    /// asked after a written turn, or where another turn was written while it
    /// was held. In addition: `readings[at].held -= 1`, and every starved
    /// reading is freed (`State::freed`, below), as
    /// send_step/admission.rs:153-163 frees its starved queues.
    fn disown(&self, journey: JourneyId, at: usize, (done, since): (bool, u64)) { /* … */ }

    /// A turn that unwound past its own catch: counted and audited
    /// (stage `process`, through `WorkStep::failed`, work_step.rs:225-229).
    /// It is let go of here, and taken up again once its claim lapses.
    fn unwound(&self, journey: JourneyId, at: usize) { /* … */ }
}

/// The pool's places shared among the Work Processes with work.
pub(super) fn share(most: usize, busy: usize) -> usize {
    most.max(1).div_ceil(busy.max(1))
}
```

### The guard (fixes the panicking turn)

`Owning` is the work step's counterpart of the send step's `Taking` (`send_step/dispatch.rs:310-323`). It is created at admission on the dispatching thread and moved into the pool's piece, or kept on the dispatching thread for a sequenced Work Process.

```rust
/// A Journey this node holds in a turn, from its admission until its turn
/// ends, however it ends. Its place in the Work pool and its local ownership
/// are given back on every exit. A turn that unwound is audited and left to
/// its claim's lapse, so a later read takes it up again, where until
/// 2026-11-12 it stayed owned and every read passed it over.
pub(super) struct Owning<'a> {
    step: &'a WorkStep,
    journey: JourneyId,
    /// Its Work Process, by its place in `WorkStep::running`.
    at: usize,
    /// How many turns this node had written as it was admitted.
    since: u64,
    /// Set once its turn returned: whether it was written.
    ended: Option<bool>,
}

impl Owning<'_> {
    /// The turn ended by its own word, `done` where it was written.
    pub(super) fn ended(mut self, done: bool) { self.ended = Some(done); }
}

impl Drop for Owning<'_> {
    fn drop(&mut self) {
        let done = self.ended.unwrap_or_else(|| {
            self.step.unwound(self.journey, self.at);
            false
        });
        self.step.disown(self.journey, self.at, (done, self.since));
    }
}
```

The step's lock is `xcore::lock::Locked` (`core/src/lock.rs:1-6`). It is taken even when the thread that held it panicked, so `disown` in a `Drop` after a panic always gets its lock.

---

## 4. The continuation cursor

### `work_step/reading.rs` (new, about 180 lines with its unit tests)

It is named as the send step's own `send_step/reading.rs` is: *"What is left to read of a queue"*. One `Reading` per Work Process, kept in `State` across rounds.

```rust
#[derive(Default)]
pub(super) struct Reading {
    /// Where its pass goes on, oldest first: `None` where none is under way.
    from: Option<(u64, u64)>,
    /// What is due in it as a wake brought it: the next read from the start reads it.
    first: Option<DueQueue>,
    /// Asked while its pass was under way: its head read before the pass goes on.
    head: bool,
    /// Asked while its pass was under way: another pass, from the start, once it ends.
    again: bool,
    /// Its share or the pool had no place: read on once a turn ends.
    starved: bool,
    /// Its turns admitted and not yet ended.
    pub(super) held: usize,
}
```

The transitions are pure and unit-tested:

- **`asked(first)`.** Where no pass is under way, a pass begins at `(0, 0)`, and the wake's page, if any, is its first page. Where one is under way, `head = true` and `again = true`, and the wake's page serves the head read. This is every ask: `WorkStep::ask` (`work_step.rs:150-160`), `woken` (165-172), `ask_every` (175-184), a due timer (`next`, `dispatch.rs:96-102`), and `disown`'s ask (`work_step.rs:218-220`). A periodic scan asks every reading with no page: *"Read wholly, a queue is read afresh, not from a wake"*, `dispatch.rs:55-60`.
- **`to_read()`.** Gives the head to read (with its page) and the pass to read (its cursor, and the page where the pass is at `(0, 0)`). Nothing while starved. The head is left out where the pass is itself at `(0, 0)`.
- **`went(Went)`.**
  - `On(Some(next))`: the cursor moves on.
  - `On(None)`: the pass is read to its end. Where `again` is set, a new pass begins at `(0, 0)` at once.
  - `Starved(at)`: the cursor is kept at the entry that found no place, and the reading is starved.
  - `Unanswered`: Xmip Storage did not answer. The pass ends and is read at the next ask or scan, as `due` does now (`dispatch.rs:178-181`).
- **`headed()`.** Clears `head`. A head that starves keeps `head` set and is read again once a place frees.
- **`freed()`.** Clears `starved`.
- **`goes_on()`** is `!starved && (from.is_some() || head)`. It is what keeps `next` from waiting.
- **`wants()`** is `held > 0 || from.is_some() || head`. It is what `busy` counts.

`page()` replaces `due()` (`dispatch.rs:166-194`). It reads one page of `DuePart::Due` from `from` (or uses `first`), notes the earliest retry not yet due (`step.noted`, as line 183-185 does now), and answers the entries and where the next page starts. That is `DueQueue::after(last)` where the page was full, and `None` at the end, the rule at `dispatch.rs:186-190`.

The cursor rule is `DueQueue::after` (`persist/.src/storage/due.rs:91-96`). A read from `(0, n)` reads the queue's entries due since they were held from place `n`, then its due retries. A read from `(due, n)` reads only retries. So:

- A Message published while the cursor stands among the retries is reached by the next pass. `again` makes that pass come at once, because a local Publication asks the queue (`message_path.rs:198`) and a remote one wakes it.
- An older entry that becomes runnable behind the cursor is read at once by the head page, and in any case by the next pass.

---

## 5. A round, and fairness across Work Processes

### `work_step/dispatch.rs` (230 lines now, about 300 after)

`next` (`dispatch.rs:78-105`) becomes `next(until) -> Option<Round>` (`None` once closed). Under the one lock it:

- waits as now, also ready where any reading `goes_on()`;
- folds the asked queues and their wake pages, and the due timers, into their readings, every reading asked afresh where `until` has passed (the periodic scan);
- counts `busy` and computes `share`;
- lists, from `state.first`, the Work Processes whose reading `goes_on()`, and moves `first` on by one. The Work Processes take turns at going first, so the first configured never always goes first.

```rust
pub fn dispatch<'scope, 'env>(scope, runtime, pickup) {
    // … pool and watch thread as at dispatch.rs:32-44 …
    let mut next_scan = Instant::now();
    while let Some(round) = step.next(next_scan) {
        for &at in &round.order {
            quantum(&pool, runtime, pickup, (&step.running[at], at), round.share);
        }
        if round.all {
            next_scan = Instant::now() + step.scan;
            step.lock().scans += 1;
        }
    }
}
```

`quantum` replaces `scan` (`dispatch.rs:117-147`). It is one Work Process's share of a round: its head where asked, then one page of its pass. Each entry is offered in queue order:

- failed, or seen in this quantum: moved past;
- `Admitted::Held`: moved past;
- `Admitted::Full`: stop, and keep the cursor on this entry (`Went::Starved`, the head kept);
- `Admitted::Turn(owning)`, on a sequenced Work Process: `catch_unwind(AssertUnwindSafe(|| settled(…, (&held, owning))))` on the dispatching thread. A sequenced turn keeps its place in the queue's order, as `dispatch.rs:128-130` requires, and the dispatching outlives a panic in it, as the pool's own threads do (`pool.rs:158-161`);
- `Admitted::Turn(owning)`, otherwise: `take(pool, …, (held, owning))`.

The cursor after a quantum is `DueQueue::after` of the last entry offered, never of one not offered. The `seen` set is per quantum, at most two pages.

What this gives:

- **Fairness.** One quantum per Work Process per round, at most two page reads and at most `share` turns. A sequenced Work Process runs at most `share` turns on the dispatching thread before the next Work Process's quantum.
- **Moving past what may not go now.** Entries owned here and failed entries cost no turn and do not stop the cursor. An admitted entry moves the cursor however its turn ends, so a page of entries that each turn into `Waits` never holds back the page behind it.
- **No spin.** Every round either moves a cursor, admits a turn, or starves a reading. A pass read to its end stops going on unless `again` is set.

The rest of `dispatch.rs`:

- `take` (196-206) moves `owning` into the piece: `pool.run(Box::new(move || settled(runtime, pickup, running, (&held, owning))))`.
- `settled` (210-230) takes `owning` in place of `since`, and ends with `owning.ended(done)` where line 223 called `step.disown(...)`. The `rescan` and `ask_every` after a written turn stay as they are (226-229).
- `turn_due` (152-164), the test helper, reads each queue wholly through `reading::page`, then turns what it read on the caller's thread. Its meaning is unchanged, its memory is the test's own queue, and there is no admission. The one page reader serves both callers.
- `PAGE` (19-20) moves to `reading.rs`.

### `work_step.rs` (247 lines now, about 245 after)

- The module diagram (lines 6-19): `-> scan` becomes *a page a round from where its pass stands, oldest first, each Work Process a share of the Work pool's threads (`admission`, `reading`)*.
- `mod admission; mod reading;`.
- `State` (92-108):
  - `owned` stays a `HashSet<JourneyId>`, now *admitted for a turn, queued in the pool or running*;
  - new `readings: Vec<Reading>`, one per `running` entry, sized in `new` (115-135);
  - new `first: usize`;
  - new `unwound: u64`.
- `own` and `disown` (197-223) move to `admission.rs`.
- Test support (238-246), beside `scans()`: `held()` (`owned.len()`) and `unwound()`.

---

## 6. The panicking turn: the outcome at the turn's boundary

The `Owning` guard alone releases local ownership. It cannot write a useful Failed reason (a `Drop` never sees the panic's payload), and Ledger writes during an unwind risk a second panic, which aborts the node. So the turn catches its own panic under its claim and settles it with normal code, off the unwind path.

### `work_step/turning.rs` (331 lines now, about 350 after)

`turn` (45-129) keeps the claim (59-63). Everything after it, lines 64-128, moves into `fn claimed(runtime, pickup, running, held, &claim) -> Turned`, called as:

```rust
match panic::catch_unwind(AssertUnwindSafe(|| claimed(runtime, pickup, running, held, &claim))) {
    Ok(turned) => turned,
    Err(thrown) => written::panicked(runtime, running, (held, &claim), &crate::pool::said(thrown.as_ref())),
}
```

This covers the flow (`flow.advance`, line 290), a unit's call and a splitter (`acts::work`, `acts.rs:71-72`), the runtime's own act code, and the turn's write. A panic in a linked flow or unit reaches here. A loaded unit's own C ABI guard (`abi::guarded`, `abi/.src/unwind.rs:20`) already answers a panic as a status.

### `work_step/turning/written.rs` (127 lines now, about 185 after)

There is one failure writer:

- `hand_on` (89-110) becomes a free `fn hand_on(claim, journey, made) -> HandOn`, used by `Taking::written` and by `failed`.
- `failed(runtime, running, claim, journey, why) -> Turned` is the body of today's `Taking::fail` (112-131): Failed, `current_work_process`, `Failure { queue, reason }`. `Taking::fail` resets `made` and calls it.
- `panicked(runtime, running, (held, claim), said) -> Turned` reads the Journey record again under the claim (`storage.read_journey`, then `Journey::from_record`). It touches no Message, which may be what panicked. Then it calls `failed(…, "its turn panicked: {said}")`, which answers:
  - `Ok(true)`: `Turned::Failed`, visibly failed, kept in its queue's failed index, audited by `settled` (`dispatch.rs:215`) at stage `process`;
  - `Ok(false)`: `Waits { "its claim was another's" }`. A turn whose write landed before the panic has already ended the claim, so this never overwrites a written turn;
  - unreadable Journey, or Xmip Storage not answering: the claim is released and the answer is `Turned::Unwritten`, recoverable at once. This is the send step's `abandoned` rule (`send_step/pass.rs:190-208`).

### `pool.rs` (289 lines now, about 310 after)

- `pub(crate) fn said(thrown: &(dyn Any + Send)) -> String` answers what a panic said: a `&str` or a `String` payload, else *"it said nothing readable"*. It has one home, beside the runtime's other catch (`serve`, line 168). No such helper exists in the estate (searched for `downcast_ref::<&str>`).
- `run` (120-134) states its contract: *a caller hands it no more than its most, as each step admits what it hands it* (`send_step/admission.rs`, `work_step/admission.rs`, the receive's room at `receiving.rs:167-171`). It checks the contract in debug builds with `debug_assert!(state.queued.len() <= self.most, …)`, a tripwire. Each caller was checked: the receive's room, the send step's room (owned plus admitted), and the new work admission.
- The doc of `serve` (155-161) names the work step's `Owning` beside `receiving`'s telling.

### What a panic now comes to

| Where it panics | What the Ledger holds | Local state | Audit | Who goes on |
|---|---|---|---|---|
| Flow, unit, splitter, act code or the turn's write (under the claim) | Journey `Failed` with "its turn panicked: …", in its Work Process queue's failed index; or the claim released where that cannot be written | `Owning` ended normally | One line through `settled` | The pool thread, the dispatching, every other Work Process |
| Before the claim or after the catch (the runtime's own code), pool path | Nothing written. A claim, if one was taken, lapses after `WORK_LEASE` | `Owning::drop` gives the place back and records the turn as unwound | One line, "unwound … taken up again once its claim lapses" | As above; the pool catches (`pool.rs:168`) |
| The same, sequenced path | As above | As above | As above | The dispatching thread, which catches in `quantum` |

### How the states surface

Each state is carried by a record that exists today, so no per-surface code is needed:

- **waiting**: the Journey kept in its Work Process's queue, unclaimed; `Waiting` with its due time where a timer waits. A turn read but not admitted stays there, in the Ledger, not in memory.
- **running**: the Journey's claim in Xmip Storage, naming the node, for `WORK_LEASE`. No write marks a turn's start: one would cost a sync on every turn (the millisecond rule).
- **failed**: the Journey `Failed` with why, in the queue's failed index, and the audit at stage `process` (`WorkStep::failed`, `work_step.rs:225-229`).

A live count per Work Process in the node's snapshot is left out. Its scope, `…/process/<name>` (estate-map.md `artifact-scope`, lines 303-311), already carries each Subscription's record in `running/publication.rs:155-173`, and that file is 696 lines. Adding it is a change of its own: the owner's call.

---

## 7. Tests

### Unit tests (in the files they test)

- `pool.rs`: `what_a_panic_said_is_its_message_or_said_to_be_none` (a `&str`, a `String`, and another payload). The three existing tests stay; `a_piece_that_panics_leaves_its_thread_taking_the_next` (266-288) among them.
- `work_step/reading.rs`:
  - `a_pass_begins_where_none_is_under_way_and_reads_a_wakes_page_first`;
  - `asked_while_a_pass_is_under_way_its_head_is_read_and_it_goes_again_once_it_ends`;
  - `a_starved_pass_goes_on_from_the_entry_that_found_no_place_once_one_frees`;
  - `a_periodic_scan_reads_afresh_not_from_a_wake`;
  - `a_pass_storage_does_not_answer_ends_until_the_next_ask`.
- `work_step/admission.rs`: `the_pool_is_shared_among_the_work_processes_with_work`. `share(8,1)=8`, `share(8,3)=3`, `share(2,5)=1`, `share(0,0)=1`.

### Ledger tests (`tests/ledger`)

The send step's `send_bounded.rs` is the model. The shared pieces go in `work_design.rs` (215 lines now, about 290 after):

- a design `CALLS`: a start, a `serviceTask` with `xmip:call module="Units" unit="Call"`, and an end;
- `Gated` units: count the call, wait at a gate, answer `message.assigned(new id, same context)` as `acts.rs:66-69` does;
- `Panicking` units: `panic!("a unit that panics")`;
- a `Recorded` flow: wraps `Compiled` and pushes its Work Process's name on each `advance`;
- a `Sender` with `send_threads_per_hardware_thread = 1` and `work_scan` an hour.

`main.rs` registers two new files and names them in its header list (lines 17-74).

**`work_panicked.rs` (new, under 300 lines): the panicking turn's acceptance.**

1. `a_turn_whose_unit_panics_is_written_failed_with_what_it_said`. Through `turn_due`: `Turned::Failed` contains "panicked: a unit that panics". The Journey is `Failed`. `storage.read_failed(queue, 0, 10)` holds it with that reason. Its claim ended (another node can claim it, the `free` helper of `send_bounded.rs:65-71`).
2. `a_turn_that_panics_leaves_unrelated_work_going_on_without_a_restart`. One node dispatching two Work Processes, `Calls` with `Panicking` units and `Absorb` (start and end, as `woken_behind.rs:67-75`). Carry to `Calls`, then to `Absorb`. Until `Calls`' Journey is `Failed` and `Absorb`'s is `Completed`. Carry to `Calls` again: it too ends `Failed`, so the step still takes that Work Process's work. At the end, `work.held() == 0` and `work.unwound() == 0`.
3. `a_sequenced_turn_whose_flow_panics_keeps_the_dispatching_going`. `Sends.points` holds a `PointKind::WorkProcess` point for `Calls` (`OnFailure::Skip`), so its turns run on the dispatching thread. The flow wraps `Compiled` and panics in `advance`. Its Journey ends `Failed`, then a Message to `Absorb` is `Completed`. Without the catch in `quantum` the dispatching ends and this never completes.
4. `a_turn_that_unwinds_before_its_claim_is_let_go_of_and_taken_up_again`. `Failing` over `memory()`, `failing.before(Operation::Claim, Box::new(|| panic!("a claim that panics")))` once. Until `work.unwound() == 1`; then `work.held() == 0`; `work.ask_every()`; until the Journey is `Completed`. Without the guard it stays owned and is never taken up. Run it on both paths, the second with the Work Process point of test 3.

**`work_bounded.rs` (new, under 400 lines): the unbounded dispatch's acceptance.**

5. `a_scan_takes_no_more_turns_than_the_work_pool_can_run` (as `send_bounded.rs:96-124`). `most = hardware_threads()`. Carry `most + 8` Messages of distinct clients, without the Receive Location's sequence (gate points cleared, as `woken_behind.rs:262-263`). `Gated` units, dispatching. Until `entered == most`. Assert `work.held() == most`, and that exactly 8 are free to claim: left durable and unclaimed. Open the gate; every one ends `Completed`.
6. `turns_another_node_holds_keep_no_place_from_those_behind_them`. The dispatch-level form of the existing page regression. Carry 64 (`one page`) clients' first Messages and claim each for an hour by `node_scope(1)` (as `send_bounded.rs:169-178`). Then carry one more client's. Dispatching with `work_scan` an hour: until the last one is `Completed`. The 64 are still not this node's.
7. `a_backlog_in_one_work_process_holds_back_no_turn_of_another`. Two Work Processes with `Recorded` flows: `First` with `16 * most` Messages carried, then `Second` with one. Dispatching: until all are `Completed`. `Second`'s first entry in the record is at index ≤ `most`. Today it comes after all of `First`'s backlog, at about `16 * most`.
8. `the_dispatching_reads_one_page_before_its_first_turn_however_long_the_backlog`. `Failing`, 1,000 Messages carried (16 pages). `failing.before(Operation::Claim, …)` records `failing.asked_times(Operation::ReadDue)` at the first claim. The assertion is `== 1`. Today it is 17, every page read before the first turn.
9. `a_backlog_is_dispatched_in_memory_a_page_bounds`, run `alone` (`bounded.rs:59-85`, the estate's counting allocator `xcore::held`). For 256 and then 4,096 Messages in one Work Process: `xcore::held::reset()` as dispatching starts, and `xcore::held::most()` read in the `before(Claim)` hook. Assert that the peak before the first claim for 4,096 is within 64 KiB of the one for 256. Today it grows with the backlog by every `Held` read.

**Kept as they are, and required to pass:**

- `work_process.rs:49-67`, `a_scan_reads_its_queue_to_the_end_not_only_its_first_page`. This is the regression added in `77bd9d4` (2026-11-04): 65 clients, one more than a page, *"the last one's Message waits behind a page that may all have to wait"*. It goes through `turn_due`, which still reads to the end. Test 6 is its dispatch-level twin, with 64 entries that really are blocked.
- `work_process.rs:69-98`, two clients dispatched at once, never overtaking.
- `woken.rs` and `woken_behind.rs`. Their queues are empty at the first scan, so `scans()` keeps its meaning: periodic scans begun.
- `stream_order.rs`, `work_debatch.rs`, and `tests/measured/work_turn.rs`.

---

## 8. Files and their sizes (≤ 400 lines each, split by concern)

| File | Now | After | Concern |
|---|---|---|---|
| `src/work_step.rs` | 247 | about 245 | the step, its state, its asks |
| `src/work_step/admission.rs` | new | about 190 | the door: admit, share, `Owning`, disown, unwound |
| `src/work_step/reading.rs` | new | about 180 | per-Work-Process cursor, head, again, starved; `page` |
| `src/work_step/dispatch.rs` | 230 | about 300 | the loop, `next`, the round, `quantum`, `take`, `settled`, `turn_due` |
| `src/work_step/turning.rs` | 331 | about 350 | the turn, caught at its boundary |
| `src/work_step/turning/written.rs` | 127 | about 185 | the one failure writer, `panicked` |
| `src/pool.rs` | 289 | about 310 | `said`, the contract on `run` |
| `tests/ledger/work_design.rs` | 215 | about 290 | the shared designs and units |
| `tests/ledger/work_panicked.rs` | new | under 300 | the panicking turn |
| `tests/ledger/work_bounded.rs` | new | under 400 | the unbounded dispatch, memory |
| `tests/ledger/main.rs` | 189 | about 193 | registered and listed |

**Records that follow, in the same landing** (Change everything related):

- `module/platform/runtime/README.md` line 13, the Work Process step paragraph: admission and share, a page a round, a turn that panics ends Failed, the new tests;
- runtime-model.md section 3, *Threads, pools and chunks*: a *Built for the Work Process step* sentence beside receive and send;
- runtime-model.md section 22: the *Built* note;
- ADR-0066: an amendment, *a Work Process's turns are admitted by their share of the Work pool, read a page a round, and a turn that panics ends Failed*, with provenance (the review the owner brought; how it is built is the assistant's, for the owner to overrule).

---

## 9. Risks

1. **Blocked entries are re-turned once per pass, and once per head read while asks keep coming.** Each costs a claim, a read and a release. This exists today (every written turn asks every queue, which rescans and resubmits every blocked entry); it is now bounded by `share`. A set of Journeys passed over until what they wait on moves would end it, but holds memory per blocked entry. Left out.
2. **The cursor stands among the retries.** A Message published then is reached by the next pass, which `again` starts at once. Its latency is the rest of the current pass, at most one read of the queue: what today's whole read costs every time.
3. **A long turn of one Work Process delays another's first turn by at most that turn,** where the pool is full. A lone busy Work Process still gets the whole pool. No place is reserved, so a node configured with many idle Work Processes does not throttle its busy one.
4. **`catch_unwind` in `turn`** asserts unwind safety over `&Runtime`: its locks are taken poisoned or not (`Locked`), and the turn's partial `Made` is dropped. Streams a Debatch wrote before the panic stay unreferenced, as after any failed turn. `panicked` writes after the catch, never during an unwind, so it cannot abort the node.
5. **A panic outside the turn's catch** (the claim call, `settled`'s own code) leaves its claim to lapse (30 s) and the periodic scan to take it up. One that panics every time does so once per lease, audited each time. A panic in the dispatching thread's own code, outside `quantum`, still ends dispatching, as today.
6. **The pool's `debug_assert`** turns a caller that over-hands into a panic in debug builds. Each caller was checked; it is a tripwire for the future, and the first thing to drop if it fires falsely during the joint landing.
7. **This lands with two other fixes.** All of it is in `work_step` and `pool.rs`. `dispatch.rs`, `turning.rs` and `work_step.rs` are rewritten in part, so merge order matters. Land this one first or last, never interleaved.
8. **`turn_due` still reads wholly.** It is a test helper, bounded by the test's own queue.
9. **The next-page rule** (`held.last().filter(|_| len == PAGE).map(DueQueue::after)`) is written three times: `send_step/reading.rs:99-103` and `153-158`, and here. It belongs on `persist::storage::DueQueue` as one method, which is a persist change outside this landing.
