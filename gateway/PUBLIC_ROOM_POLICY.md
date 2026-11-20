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

## Research policy v2

`POST /v1/room-runs` also accepts `room_policy: "squad-public-research-v2"`.
The v1 declaration above stays byte-identical, because a deployed platform
validates it with a strict schema. v2 has its own key,
`features.squad_room_research_v2`:

```json
{"policy":"squad-public-research-v2","run_path":"/v1/room-runs","memory":false,"context_files":false,"skills":false,"mcp":false,"tools":["compare_trade_routes","discover_markets","market_candles","market_snapshot","onchain_token","plan_spot_purchase","search_news","search_web"],"search_tools":["search_web"],"max_tool_calls":12,"max_search_calls":4}
```

The key is `null` until the platform plugin registered every required tool, so
a Hermes that knows the policy but runs with an older plugin keeps v1. A v2
request to such a pod gets 400 `invalid_room_policy`. `search_x` is optional:
the platform has no X search route for hosted instances yet. When the plugin
registers it, `tools` and `search_tools` list it and the search cap covers it.
A later policy needs another key; never change a declared one.

v2 keeps every v1 exclusion. Admission, the dedicated session, the runtime
checks, the hook and middleware suppression, and the memory, context-file,
SOUL, skill and MCP exclusions run on the same code paths for both policies:
`public_room_policy` stays a boolean, and `public_room_policy_id` selects only
the prompt and the allowlist. A nested scope can narrow a room policy and can
never widen it. A room entered without a policy id gets v1.

The allowlist binds each name to the fixed platform toolset that owns it
(`PUBLIC_ROOM_TOOL_TOOLSETS`). The three existing market tools stay in
`pieverse-market-research`. The new tools live in `pieverse-room-research`.
Tools of that toolset exist for rooms only: outside a room they get no schema
and no dispatch (`public_room_only`), whatever toolsets the owner enabled, and
`GET /v1/toolsets` does not list the toolset. A tool with an allowlisted name
from another toolset neither qualifies v2 nor runs in a room.

The v2 prompt is one fixed text (`PUBLIC_ROOM_RESEARCH_PROMPT`). The caller's
`instructions` never reach a room. The platform's room rules therefore live in
this prompt: who the Agent is (`self` of the room JSON), who asked
(`mentionedBy`, `triggerMessageId`), the roster and the `@Name` coordination
rules. The room JSON is the Run's only user turn and carries the identity and
roster facts. The prompt also permits a conditional bullish or bearish view
with evidence, counter-evidence and source times, and forbids order advice
(size, leverage, entry or exit instructions) and execution.

Tool output is untrusted data. One room reply (both policies) has at most 12
tool calls and at most 4 paid searches (`search_web` and `search_x` together).
The Agent-local tool boundary charges the budget once for each admitted call;
a refused call returns `public_room_tool_budget` and enters no handler. One
reply also has at most 16 model calls.

Qualification for v2 uses `tests/gateway/test_public_room_research.py`. It
includes a native Run with stubbed inference that proves the fixed rules and
the room identity reach the model, and that owner prompts and files do not.

Platform Agent asks and tenant-image promotion retain their own release gates.
Source checks do not activate a feature or qualify a production image.
