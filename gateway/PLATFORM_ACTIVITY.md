# Hosted runtime activity ownership

`platform_activity.py` implements the platform supervisor's existing Unix-socket
activity protocol. It is enabled only for the explicit hosted runtime contract.
The supervisor owns DB authorization, instance/owner fencing and lease heartbeats;
Hermes reports admission and completion. Ordinary installations keep their normal
executor cancellation behavior.

## Ownership

A message turn acquires residency before entering the agent path. Its
`platform_activity_scope` propagates that admission to blocking work submitted
through `platform_run_in_executor`, including the normal gateway executor and
pre-turn context compression. Cancelling or timing out an executor *wait* does
not stop the Python thread. The lease therefore retains the actual executor
future and finishes only after all of its workers exit. Once finishing begins,
that scope refuses additional submissions before scheduling a worker.

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
producer's handles. Python cannot forcibly cancel a running executor thread.
Continuing the hosted process would therefore allow real work to outlive its
residency protection. The client fails closed with `os._exit(1)` when live
handles lose the stream; the platform owns restart/recovery and expiry of the
old leases. This bypasses Python shutdown cleanup intentionally, since cleanup
cannot guarantee that executor threads stop. The public client's explicit
`close()` is for callers that have already stopped their workers (including test
teardown), not recovery of an uncertain request.

The owning behavior suites are `test_platform_activity.py`,
`test_platform_activity_workers.py`, `test_api_server.py`, and
`test_api_server_runs.py`. Run them using `scripts/run_tests.sh`; platform
acceptance must additionally exercise the exact runtime image and supervisor
together before enabling the hosted cohort.
