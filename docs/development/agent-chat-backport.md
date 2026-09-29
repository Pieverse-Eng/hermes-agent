# Native Agent Chat backport

## Scope and maintenance policy

This is a selective backport of official NousResearch Hermes functionality onto
`d7b3e4f32a3ee7db62fee928cf1da0a6dfeb5369`, with explicit old-version adaptations
and local correctness fixes. It is **not** an unmodified cherry-pick or a new
chat protocol. It does not upgrade the upstream baseline or bring in Group Chat,
Bot Mode, desktop features or the upstream repository-wide module refactor.

Prefer unchanged upstream modules and implementation fragments. Keep unavoidable
adaptation at the existing API, AIAgent and SessionDB boundaries. Before adding a
local fix, check the official follow-up chain; identify any remaining local fix
below and keep its behavior regression. Do not add a second executor, transcript
store or public compatibility protocol.

## Source ledger

All source revisions refer to https://github.com/NousResearch/hermes-agent.
Commit references identify source material, not claims that whole commits were
cherry-picked. The initial backport preserves upstream contributor attribution.

| Capability | Official source | Backport boundary |
| --- | --- | --- |
| Durable run idempotency | `e7433910e96c097ddf34352ea28653e83d951fbb` | `api_server_run_idempotency.py` is copied unchanged. Admission, status and bearer/profile scope are wired into the old monolithic adapter. Room grants/steering/routes are excluded. |
| Native session continuation | `e7433910e96c097ddf34352ea28653e83d951fbb`, `0efb525420668b91568aa0e73050c5b41b336044` | Reuse the old SessionDB history/resume helpers. Do not import declared-room/wake machinery just to continue a supplied session ID. |
| Conversation-root leases | `6e929a96946a5c69644d08bd59c9dcfdc757e91b`, `3b0945601955e13b6159816141dc4acbc80c4132`, `5e2be43fd4`, `c21efeeb52`, `f1025b2c00`, `19b1204392`, `967391cd4b`, `6b25e67047` | Carry acquire/wait/refresh/release and stale-writer fencing into the old AIAgent/SessionDB layout. Do not import the later facade/finalizer refactor. Failed-write classification comes from `2a9f5b3476`. |
| SSE fanout and replay | `52a2835136d44896427a20b97103cffefacb94aa`, `4937863e4d28106d62bdd4571cdabc6783aaf4c3`, `10963689dcbb8b9271315150891356adee5c698f`, `61286a889ec9ee1162b1a80bf1d13c6a914f2bfe` | `_RunStream` and stream behavior use the resulting official implementation at `e824425e8c15b05e0847e818f3860c58290394cc`, adapted to the existing HTTP adapter. |
| Request-bound approvals | `f703e7061869fd6af9efb599ee3cfa435c49c551` | Carry queue request-ID matching and API forwarding; omit desktop/TUI reconnect and acknowledgement plumbing. |

Directly cherry-picking only these revisions is insufficient: `e7433910e9`
contains 52 files of Group Chat work and extracts the Runs adapter; subsequent
SSE and continuation patches target that extraction. Pulling their full
ancestry would also introduce unrelated refactors. Selective backporting avoids
that dependency expansion while preserving the required native behavior.

## Explicit local adaptations and fixes

These are maintenance obligations, not additional official features. The tests
below are the acceptance criteria for replacing them during an upstream upgrade.

| Local delta | Why it exists on this baseline | Replacement/removal condition |
| --- | --- | --- |
| API glue in `api_server.py` | Old baseline keeps Runs handlers in one class. Wires upstream store, streams, approval IDs and native history into those handlers. | Use the official Runs module during the full upgrade; remove the duplicate glue after the HTTP contract suite passes. |
| History read failure returns 503; explicit empty history remains authoritative | Prevent a failed history read from silently starting an empty-context turn, and preserve existing Responses/caller snapshots. This is stricter than the cited upstream fallback. | Verify the target official behavior; if it differs, explicitly resolve the product behavior before deleting the guard. Do not silently copy the guard into the new runtime. |
| Internal `reload_session_history` argument | Native continuation must reload after lease admission; explicit history/Responses callers must retain their supplied snapshot. Avoid importing the full new turn facade for this distinction. | Adopt the target official history/admission mechanism after continuation, contention and explicit-history tests pass. |
| Nonterminal cross-worker status refresh and interruption mapping | Cached status must not hide completion/owner death; lease interruption must not report success. | Replace with official status/recovery paths after restart and interruption regressions pass. |
| First-turn lease and final-persistence failure handling (`06713e6c54`) | Serialize a session before its first row exists and avoid reporting a successful reply whose final transcript was rejected by the lease fence. | Verify equivalent behavior in the target official lease/finalizer path, then discard these old-layout additions. |
| Parent-bound branch/delegate predicate (`cd17f0b27b`) | Compression descendants inherit fork markers; those markers must not hide the live compressed continuation or merge independent branches. | Use the target official lineage resolver once branch/delegate isolation and compressed continuation regressions pass. |

A few unused helpers remain inside the unchanged official durable store. Keeping
that module intact makes comparison and eventual removal easier than pruning it
into a private variant. Do not expose those helpers as new APIs.

## Public runtime contract

Use official feature names from `/v1/capabilities`: `run_submission`,
`run_status`, `run_events_sse`, `session_resources`, `runs_idempotency`,
`run_stop`, `run_approval_response`, `approval_events` and `tool_progress_events`.
There are no backport-only capability flags. In particular, clients must not
require `run_session_history`, `run_events_replay` or `run_approval_request_id`.
The old runtime without durable idempotency remains unsupported.

These flags advertise endpoints and availability, not proof of every continuation,
replay or approval semantic. Before promoting any image (backport or later
upstream upgrade), validate the behavior contract against its exact pinned source
and deployed authentication/Router path. Never infer that any arbitrary build
with these flags is fully tested.

- Native Runs accept the current `input`, `session_id` and `Idempotency-Key`.
  SessionDB remains authoritative for context, including tool calls/results and
  compression continuations; Platform replay records are not injected as history.
- Keys are scoped to authenticated bearer identity and profile. Identical retries
  return the original run; changed payloads conflict. SQLite reservations survive
  restart. An unfinished reservation whose owning process died is interrupted,
  never automatically executed again. Terminal retention is 24 hours after the
  last update. A memory-only store advertises `durable: false`.
- SSE uses numeric `id`/`seq` and `Last-Event-ID` or `last_seq`. Replay keeps the
  latest 1,000 events in memory, reports truncation and disconnects slow readers.
  Replay is not restart-durable; the existing 300-second orphan transport TTL
  remains. Recover using native run status and history, without resubmission.
- Approvals carry `request_id`; Platform always sends the exact pending ID with
  `once` or `deny`. The legacy FIFO omission behavior remains for older clients.
  Restart does not reconstruct pending approvals or authorize their replay.
- Stop is cooperative; it does not roll back effects already executed.

## Verification and future upstream upgrade

Tests use temporary SQLite and stubbed model execution; no provider call or live
trade is required. Run via the repository's hermetic wrapper:

```sh
scripts/run_tests.sh tests/state tests/run_agent tests/gateway/test_api_server*.py -j 8 -q
```

Key behavior suites: `test_api_server_native_runs.py`,
`test_cross_process_turn_lease.py`, `test_session_turn_lease.py` and
`test_compression_lineage_guard.py`. Platform additionally runs its native HTTP
integration tier against `HERMES_TEST_ROOT` and uses the official capability
response shape in adapter tests. Keep those tests through the later upgrade;
adapt test fixtures to official internals without weakening their assertions.

For the eventual full upgrade:

1. Select and pin an official revision containing the source capabilities and
   relevant follow-up fixes. Review existing Pieverse integrations separately.
2. Replace this backport's modules/glue with official implementations. Do not
   overwrite unrelated fork customizations or duplicate the old lease/store code.
3. Run native continuation/isolation, tool history/compression, duplicate/conflict,
   restart/reconnect, stop and stale-approval tests. Check every local-delta row
   above; any remaining semantic difference needs an explicit decision.
4. Run Platform native integration and deployed canary checks for both runtimes.
   Keep Platform on the official protocol; no new fork-only discovery flags.
5. Once equivalent behavior is verified, remove superseded adaptation code and
   archive this ledger as upgrade provenance. Do not remove regressions merely
   because their original source files moved.

Do not run a pre-backport binary concurrently with a lease-aware Hermes binary
against the same writable SQLite state: the pre-backport binary does not
participate in the new leases. Image
building, migration and production promotion are separate release operations.
