# Native Agent Chat backport

This fork selectively carries official NousResearch Hermes changes onto
`d7b3e4f32a3ee7db62fee928cf1da0a6dfeb5369`. It does not update the upstream
baseline, introduce an alternate chat API, or include Bot Mode/Group Chat.

## Contract

`GET /v1/capabilities` advertises `features.runs_idempotency` with
`supported`, `durable`, and `retention_seconds` (86400). Clients must require
`durable: true` before retrying an ambiguous submission. The additional
backport discovery flags are `run_session_history`, `run_events_replay`, and
`run_approval_request_id`.

`POST /v1/runs` with `input`, `session_id`, and `Idempotency-Key` resumes the
native SessionDB transcript, preserving tool calls/results and following the
current compression continuation. The agent's durable conversation-root lease
serializes load/run/flush across processes, refreshes native history after admission, preserves explicit caller/Responses snapshots, refreshes during long turns, and
fences stale transcript writes. Approvals retain their separate per-run scope.

A retry with the same key, JSON body, and session-key header returns HTTP 202
with the original `run_id`, `replayed: true`, and `Idempotency-Replayed: true`.
A different body under the same scoped key returns HTTP 409 with
`error.code=idempotency_key_conflict`. Keys are scoped to authenticated bearer
identity and routed profile; credentials and request bodies are not stored.
Reservations use SQLite `BEGIN IMMEDIATE` and survive restart. Keyed run status
(including terminal output/error/usage/session_id) is recoverable through
`GET /v1/runs/{run_id}`. A nonterminal reservation whose owning process died
becomes `interrupted`, never a new execution. Terminal reservations expire
24 hours after their last status update; clients must not retry indefinitely.
The upstream store falls back to memory if disk storage cannot open, and the
capability then reports `durable: false`.

SSE events carry numeric `id:` and `seq`; reconnect using `Last-Event-ID` or
`last_seq`. Each subscriber receives its own fanout queue. Replay retains the
last 1000 events in memory, reports `replay.truncated` on a gap, and closes slow
subscribers rather than silently skipping events. Replay is not durable across
restart. The existing upstream 300-second orphan transport TTL remains;
clients recover expired/disconnected streams through run status and SessionDB.
A transport failure is not evidence that the run failed.

Approval events carry `request_id`; clients must send that exact ID with
`choice: once` or `deny` to `POST /v1/runs/{run_id}/approval`. A stale ID cannot
resolve the next queued approval. Omission retains the pre-existing FIFO
contract for older clients; Agent Chat must always supply the ID. Pending
approval waits are not reconstructed after restart, and an interrupted run
must never automatically grant or repeat its old approval. Stop remains
cooperative and does not promise rollback of effects already executed.

## Upstream provenance and adaptations

All revisions below are from https://github.com/NousResearch/hermes-agent:

- `e7433910e96c097ddf34352ea28653e83d951fbb`: native session history loading,
  durable idempotency store/admission/status and authenticated profile scope.
  The store is retained as the original standalone module; Group Chat routes,
  grants, steering, and unrelated extraction are excluded.
- `0efb525420668b91568aa0e73050c5b41b336044`: adopt the live compression tip for
  client-addressed native runs. Existing fork SessionDB helpers are reused.
  Native history read failures return 503 before admission, instead of silently
  running an empty context.
- `6e929a96946a5c69644d08bd59c9dcfdc757e91b`, `3b0945601955e13b6159816141dc4acbc80c4132`,
  `5e2be43fd4`, `c21efeeb52`, `f1025b2c00`, `19b1204392`, `967391cd4b`,
  `6b25e67047`: conversation-root leases, interruptible waiting, refresh,
  compression-root handling, transcript write fencing, and refresher teardown.
  Later reload-skipping optimization is deliberately excluded: native API
  submissions must reload the admitted durable transcript. Existing base
  error text is retained; classification at the failed write is carried from
  `2a9f5b3476` for the lease regression contract.
- `52a2835136d44896427a20b97103cffefacb94aa`,
  `4937863e4d28106d62bdd4571cdabc6783aaf4c3`,
  `10963689dcbb8b9271315150891356adee5c698f`,
  `61286a889ec9ee1162b1a80bf1d13c6a914f2bfe`: SSE fanout, replay, bounded
  subscriber buffering, write timeout, and explicit overflow disconnection.
  Stream code is taken from the resulting upstream implementation at
  `e824425e8c15b05e0847e818f3860c58290394cc` and adapted to the existing adapter.
- `f703e7061869fd6af9efb599ee3cfa435c49c551`: stable approval request IDs and
  matching under the approval queue lock. Desktop-only acknowledgements and
  reconnect plumbing are excluded; the API forwards the correlated ID.

Upstream authors remain credited in the backport commit. These patches are
intended to be superseded by a separately reviewed upstream upgrade containing
these behaviors. At that point remove duplicate adapters/discovery flags only
after preserving the published capability and recovery contracts.

## Verification

Tests use real temporary SQLite databases and deterministic fake agents; no
provider/model call, production deployment, or real tool execution is needed.
Native HTTP tests cover tool metadata, compression continuation, retry/conflict,
restart interruption, event replay, and stale approval IDs. Upstream lease tests
exercise separate database handles, lock contention, compression roots,
refresh, interrupted waiting, and stale-writer fencing.

Run with the repository's hermetic wrapper:

```sh
scripts/run_tests.sh tests/state tests/run_agent tests/gateway/test_api_server*.py -j 8 -q
```

Broad local verification: 184 files, 1652 passed, 8 failed before installing
optional pinned `anthropic==0.87.0`. Rerunning all five failing files after that
installation: 299 passed, one failure. The remaining
`test_primary_runtime_restore.py::TestTryRecoverPrimaryTransport::test_allowed_for_nous_anthropic_messages`
also fails on an untouched `origin/main` worktree (23 pass / 1 fail), because
its empty model fixture resolves a 36864-token context below the 64000 minimum.
This baseline provider-fixture failure is outside the backport.

## Review hardening

- Durable statuses loaded from another worker are refreshed from SQLite until
  terminal; an earlier GET cannot hide subsequent completion or owner death.
- The native adapter maps `interrupted: true` agent results (including lease
  loss) to `run.interrupted`, persists the reason/status, and never emits a
  successful completion for that run. Explicit stop retains its cancelled
  status. Idempotent retries return the interrupted original run.
- Agent turn admission only reloads caller-supplied history when its caller
  explicitly sets `reload_session_history=True`. Native session continuation
  opts in, after resolving its initial history source; explicit history and
  `previous_response_id` retain their supplied snapshots. Calls without any
  supplied history also load durable state. The lease and write fence apply
  regardless of which history source is authoritative.
- Integrated regressions combine the HTTP adapter, real AIAgent admission and
  real SQLite handles, stubbing only the model conversation body. Owner-death
  polling additionally uses a real short-lived subprocess.

Review-round focused verification: 65 tests passed across native HTTP recovery,
original API runs/approval/stop, agent turn admission, and real SQLite lease
suites. Explicit empty history is also preserved; it is not reinterpreted as a
request to reload native context.

The review-round broader run covered 184 files: 1667 passed, 1 failed. Its only remaining failure is
the same independently reproduced baseline primary-runtime fixture described
above; no native-chat, API, persistence, or lease regression failed.

## Database-focused follow-up review

Compression children inherit their parent model configuration. Branch/delegate
markers therefore identify an independent fork only when they name that row's
immediate parent; they must not hide later compression continuations. The three
SessionDB continuation queries now share this parent-bound predicate. Real SQLite
and native Runs HTTP tests verify that original branches stay independent while
compressed branch/delegate sessions resume the compacted history. The expanded
focused regression run passed 143 tests across 10 files.

The upstream durable-run store retains a few unused acknowledgement/retention
helpers. They are not additional services or exposed custom chat endpoints; they
remain with the upstream implementation to keep the backport auditable rather
than introducing a second privately redesigned store.
