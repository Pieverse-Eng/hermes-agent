# Hosted runtime activity ownership

`platform_activity.py` implements the platform supervisor's existing Unix-socket
activity protocol. It is enabled only for the explicit hosted runtime contract.
The supervisor owns DB authorization, instance/owner fencing and lease heartbeats;
Hermes reports admission and completion. Ordinary installations keep their normal
executor cancellation behavior.

## Ownership

A message turn acquires residency before entering the agent path and retains
it through final channel delivery and adapter cleanup. Its
`platform_activity_scope` propagates that admission to blocking work submitted
through `platform_run_in_executor` or `platform_to_thread`, including message
preparation, the normal gateway executor and pre-turn context compression.
The shared async session-store and session-database facades use the same helper,
so cancellation cannot release residency while a persistence worker is still
running. Manual `/compress` reuses the adapter's message admission so its
provider, transcript mutation, response delivery, and adapter cleanup share one
ownership envelope. Direct callers acquire the same admission themselves.
Every work-bearing slash command acquires admission at the shared dispatch
boundary; only status, stop, approve, and deny remain available during drain.
This includes unknown plugin and quick-command names, so future command additions
fail closed. Commands such as `/debug` that perform external work remain fenced
even when their result is primarily diagnostic. A hosted quick-command cancellation
terminates its owned process group and retains residency until the shell and
all live descendants have actually exited; its existing timeout likewise settles them before reporting
completion. Fire-and-forget background agents acquire their own independent
admission for their complete execution and delivery lifetime.
Cancelling or timing out an executor *wait* does
not stop the Python thread. The lease therefore retains the actual executor
future and finishes only after all of its workers exit. Once finishing begins,
that scope refuses additional submissions before scheduling a worker. A queued
message task can inherit its parent's ContextVars, but the adapter acquires an
independent admission for that message. Failed admission explicitly clears copied
context before producing the refusal response, and a finishing or completed
hosted lease rejects any worker that reaches it.

API chat/response work and `/v1/runs` keep their own admitted executor lifetimes.
Hosted API cancellation waits through repeated cancellation until the actual
worker exits. An accepted `/v1/runs` request whose admission fails receives a
terminal failure and closes its event stream.

| Event | Required behavior |
| --- | --- |
| Normal result or worker exception | Finish residency after the worker exits. |
| Cancelled request or expired coroutine wait | Retain residency until actual work stops; preserve caller cancellation. |
| Concurrent completion callers | Share one completion task and one protocol finish. |
| Cancelled start with an accepted late ACK | Finish that exact handle before propagating cancellation. |
| Start/finish ACK deadline | Replay identical bytes and request ID on the existing stream. |
| Sibling admission/cancellation | Preserve every other handle and its heartbeat ownership. |
| Permanent producer stream failure with live handles | Exit the hosted process with status 1. |
| Idle stream EOF after every request settles | Reconnect on the next admission. |
| Stream loss with an unresolved request | Exit because commit state is uncertain. |

## Why response deadlines do not close the stream

The supervisor multiplexes all of the process's handles on one persistent
connection and deduplicates requests by ID and bytes. A missed acknowledgement
does not establish whether a start or finish committed. Hermes preserves the
response future and replays the same request instead of inventing another
admission, discarding a late acknowledgement, or abandoning sibling handles.
The five-second timeout is a response retry interval, not permission to release
residency. If the supervisor remains connected but cannot respond, protocol
settlement continues waiting conservatively; a cancelled caller can also remain
in settlement until the result is known.

Permanent connection loss is different: the supervisor stops renewing that
producer's handles. Python cannot forcibly cancel a running executor thread,
and a request without an acknowledgement may already have committed. The client
fails closed with `os._exit(1)` when a live handle or unresolved request loses
the stream; the platform owns restart/recovery and expiry of the old leases.
This bypasses Python shutdown cleanup intentionally, since cleanup cannot
guarantee that executor threads stop. A stream that closes after all requests
and handles settle owns no remote state, so the next admission reconnects. The
public client's explicit `close()` is for callers that have already stopped
their workers (including test teardown), not recovery of an uncertain request.

The owning behavior suites are `test_platform_activity.py`,
`test_platform_activity_workers.py`, `test_api_server.py`, and
`test_api_server_runs.py`. Run them using `scripts/run_tests.sh`; platform
acceptance must additionally exercise the exact runtime image and supervisor
together before enabling the hosted cohort.

`gateway/run.py`, `gateway/slash_commands.py`, and the base platform adapter are
activity-owned execution surfaces. Blocking work in those modules must use
`platform_to_thread` or `platform_run_in_executor`; the worker-ownership
regression rejects raw asyncio executor submission so a newly added command or
delivery step cannot silently escape residency.
