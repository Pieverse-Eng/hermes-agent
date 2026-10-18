# Current API conversation messages

Native `/v1/runs` can publish `message.interactive` text with Telegram-compatible `reply_markup.inline_keyboard` rows. `callback_data` is 1–64 UTF-8 bytes; URLs are HTTP(S) without embedded credentials. Host metadata describes proposals, not executed actions. The authenticated host must validate owner, run, account, target version and human confirmation before executing anything.

The `api_interactions` toolset exposes a current-conversation `send_message` wrapper and scoped clarification. Delivery cannot fall back to another channel when the stream is detached or stopped. `/v1/runs/:id/clarify` only answers the active question in the matching profile/run; run status includes its current pending ID. Resolution events contain an ID/reason, not the answer. Stop clears pending waits and awaits the actual worker before releasing its hosted lease. Ordinary Chat and Telegram defaults are unchanged.

Optional `interaction_context` is frozen host data, bounded to 32 KiB, exposed via `send_message(action=context)` rather than rewriting prompts or past history. Hosts should treat model-produced card metadata as untrusted proposals.

For `mode=paper`, or an explicitly bound Live context with `execution_policy=proposal_only`, proposal-only tools are fixed at Agent construction and intersect the configured toolkit. Research, memory, history, todo, skills listing and current messages may remain available. Arbitrary shell/code/browser, credential/file reads, skill mutation, delegate/cron, tool-search bridges and unknown plugin/MCP execution are unavailable. Dispatcher and registry enforce this in the worker scope; ordinary unbound runs keep their existing toolkit. This is removal of execution entry points, not a shell sandbox; restoring arbitrary execution needs a separately scoped credential/identity design. Trusted operator-installed hook implementations remain a host trust boundary.

Proposal schemas are read before tool-search assembly so `send_message` remains visible without making it globally core. Capability consumers must require `interactive_messages` plus the matching `paper_proposal_only` or `live_proposal_only` capability before enabling host trade proposals. Live consumers must explicitly send `execution_policy=proposal_only` and verify their exact plugin manifest. A Paper capability alone does not prove Live support. Source tests do not prove hosted model behavior, external Telegram delivery or deployment.

Validation: `scripts/run_tests.sh tests/gateway/test_api_server_interactive_messages.py tests/gateway/test_api_server_native_runs.py tests/gateway/test_api_server_toolset.py tests/tools/test_send_message_react.py tests/tools/test_clarify_gateway.py -j 1 --file-retries 0`.

Paper tool schemas are frozen for the Run and skip native between-turn MCP discovery. Vision/video tools remain unavailable until media sources can be bound to authenticated host input; normal Agent tool behavior is unchanged.

## Current-Run host tools (v1)

Client-visible native tool lifecycle events, session message history and terminal
turn transcripts share the same structured credential redaction. Known public
wallet/market identities, validated receipt cursors and tool-call IDs remain
intact; credential fields and nested JSON-encoded credentials are masked.
This is an outbound presentation boundary: stored SQLite messages and the
conversation passed to model continuation are not rewritten. Unaffected strings
retain their exact bytes, including meaningful whitespace.

Platform plugins can register schemas in `api_host_tools`. They are proxies:
registry dispatch uses only the current Run broker and never calls a local handler.
Only tools enabled for the authenticated API platform can be admitted. Telegram,
ordinary chat and unbound Live do not gain a host binding. No proxy confirms transactions.

`interaction_context.host_tools` is a unique list of at most eight registered names;
`serial_host_tools` is a subset for preparation calls. These require Paper mode or
explicit Live `execution_policy=proposal_only`, and a configured API key. Live
manifests without that policy are rejected before reserving a Run. The exact owner/host tool scope participates in native schema
caching, prompt construction and Skill dependency discovery.

SSE `host_tool.request` contains `run_id`, `callId`, `name`, `arguments`,
`argumentsJson`, `requestHash` and an epoch-seconds `deadline`. The compact UTF-8
`argumentsJson` preserves the bytes hashed by the producer (including number
spelling); the host verifies its parsed values match `arguments` before using
those bytes for the digest. Legacy requests without it use canonical JSON. The authenticated host responds to
`POST /v1/runs/{run_id}/host-tools/{call_id}/result` with
`{"requestHash":"...","result":{"status":"ready","data":{}}}`. Replies are bound
to the original Run/profile/hash. Identical replies are idempotent while the Run
broker exists; conflicts fail. An authenticated result for a known expired or
stopped call returns HTTP 410 with `error.code=host_call_inactive` and is never
delivered to the model. The host may retain its own outcome and drain the Run;
this acknowledgement does not confirm execution. An unknown call remains 404,
and a conflicting hash/result remains 409. Once the terminal Run's broker has
been removed, the host must verify that Run's authenticated terminal status
before treating a 404 result endpoint as drainable. Requests are finite JSON objects
up to 8 KiB, results 32 KiB, deadline 15 seconds, two concurrent reads and one
serialized preparation. Stop/shutdown release pending calls. Timeout returns the
original call ID as `HOST_CALL_UNKNOWN`; the host must recover the original receipt
rather than issue a new financial command. A gateway restart interrupts the Run;
it does not replay the model or recreate a call automatically.

Proposal-only native `skill_view` preserves normal verification, disabled-Skill checks and
safe path-template substitution. It exposes only `SKILL.md` and Markdown references,
never inline shell processing, environment passthrough or credential preparation.
Repeated views recheck restricted policy instead of returning an old permission
cache entry. Ordinary native Skill behavior is unchanged.

Capabilities expose `host_tools_v1` and enabled `host_tool_names`. The bridge being
present alone does not prove a platform plugin, backend service or real model is
available. Those must be tested and versioned separately.

Unbound ordinary/Live/News API runs remove `api_host_tools` even when an operator
included it in configured toolsets. Only a validated proposal-only host binding can add
its exact manifest. This keeps proxy schemas and their Skill dependencies out
of normal conversation catalogues. Registry schema admission enforces the same
boundary for `all/*`, raw tool-search catalogues and native messaging plugin
discovery, including Telegram. Timeout marks a call inactive under the same
lock that chooses its unknown outcome, before pending-call cleanup.
