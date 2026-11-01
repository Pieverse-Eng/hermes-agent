# Public room Run policy

`POST /v1/room-runs` accepts the authenticated, server-owned policy
`room_policy: "squad-public-market-v1"`. Its capabilities declaration is:

```json
{"policy":"squad-public-market-v1","run_path":"/v1/room-runs","memory":false,"context_files":false,"tools":["discover_markets"]}
```

The dedicated admission route is a mixed-version fence: older pods return 404
before inference. Callers must never fall back to `/v1/runs` after that refusal.
Ordinary private runs keep their existing route.

This declaration appears at `features.squad_room_isolation`. The caller cannot
supply a wider tool list or turn memory on. Policy requests need a valid bearer
and a dedicated `agent-chat-pawchat-isolated-v1-<UUID>` session. They accept one
input string, no explicit history, previous response or financial interaction
context. The policy is part of the durable idempotency fingerprint. Replays
return the existing Run; they do not rebuild or resend it.
Legacy room identities also refuse ordinary Runs instead of falling back to
an owner's private policy, including after a platform rollback.

Capabilities and admission refuse externally configured runtimes. The resolved
Agent transport must use `chat_completions`, `codex_responses`,
`anthropic_messages` or `bedrock_converse` in Hermes' own tool loop. Codex
app-server and ACP transports refuse before Agent/client construction. Turn
entry checks again if an Agent's mode changed. Room Agents have no inherited
fallback chain. Capability discovery reads configuration only and does not
resolve or refresh provider credentials; actual resolved modes are checked
again after request overrides. Private runtime selection stays unchanged.

Room turns never load native session history. They use a fixed system prompt,
not the caller's instructions or the owner's configured prompt. The actual
Agent constructor disables built-in and provider memory, owner context files,
SOUL identity and custom context engines. Generic owner hooks and middleware
cannot inject context into a room. Configuration stays unchanged for ordinary
private conversations and concurrent Runs.

Tool schemas and dispatch admit only public `discover_markets`. That tool is
available when the platform's market-research plugin is installed. Memory and
session recall also receive a guard at the Agent-local execution boundary,
before middleware or a handler can run. The Agent retains its room marker if
ambient context is lost; tool callbacks restore their captured room scope.
Nested proposal scopes cannot widen the allowlist, and MCP refresh stays off.
The policy trusts the pinned runtime and platform tool implementation; it is
not an operating-system sandbox for arbitrary user plugins.

Qualification uses `tests/gateway/test_public_room.py`: actual Agent
construction with private memory/SOUL/USER sentinels, real public tool dispatch,
forbidden-handler controls, native HTTP admission, simultaneous private/room
Runs and durable replay. Tests use isolated homes and fixture credentials and stubbed inference;
they make no paid model call. Use `scripts/run_tests.sh -j 1` under the host's
resource limits.

Platform Agent asks and tenant-image promotion retain their own release gates.
Source checks do not activate a feature or qualify a production image.
