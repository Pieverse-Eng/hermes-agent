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
a refused call returns `public_room_tool_budget` and enters no handler.

One room reply (both policies) also sends at most 16 model requests. Hermes
counts a request directly before it calls the provider SDK
(`charge_public_room_model_request`), so each attempt is a request: a first
try, a retry after a provider error, a stream reconnect, and the non-streaming
fallback after a refused stream. Hermes does not send the request after the
sixteenth. The Run then fails with the fixed error `Shared room reply stopped:
this reply used all 16 of its model requests.` and has no output, so the
platform publishes nothing. The loop has the same limit of 16 turns. A room Run
does not make the closing summary request that a private conversation makes at
its iteration limit: a reply that reaches the limit without an answer fails
with the same error.

A counted request is one HTTP send. Hermes turns SDK retries off for its
OpenAI-compatible and Anthropic clients. boto3 retries inside one SDK call, so
for Bedrock a botocore `before-send` handler counts each send
(`room_request_scope` in `agent/bedrock_adapter.py`) and refuses send 17
before it leaves. The runtime client is shared by every conversation of the
process. Hermes registers the handler when it builds the client, before
another thread can use it. The handler acts only for the thread that is inside
the SDK call of a room reply, and does nothing for a private conversation.

A room does not probe the context window of a Bedrock model. Each probe tier
is a request to the model, and boto3 can retry it. A room uses the cached
window or the static table, and it does not save the table value.

A room does not run MoA: one MoA call sends a request to each reference model
and then to the aggregator. Capabilities declare no room policy on a pod whose
configuration names the `moa` provider. Admission refuses a room Run with 400
and the fixed error `Shared rooms do not run MoA.` for that configuration, for
a request that names the provider, for a `model_routes` alias that names it,
and for a one-shot MoA turn (the hidden marker of `/moa`). The Agent
constructor and the turn entry refuse the same cases. A MoA runtime that only
the runtime resolution finds therefore fails its Run with that error before an
Agent exists. No case sends a model request. Private conversations keep MoA.

The count covers the requests for the Agent's own model. Context compaction
and the session title are outside it: they use Hermes' auxiliary model, as
they do for each API session.

Qualification for v2 uses `tests/gateway/test_public_room_research.py`. It
includes a native Run with stubbed inference that proves the fixed rules and
the room identity reach the model, and that owner prompts and files do not.

## Room memory policy v3

`POST /v1/room-runs` also accepts `room_policy: "squad-public-memory-v3"`. It is
v2 and one more tool, `room_memory`. The v1 and v2 declarations stay
byte-identical. v3 has its own key, `features.squad_room_memory_v3`:

```json
{"policy":"squad-public-memory-v3","run_path":"/v1/room-runs","memory":false,"context_files":false,"skills":false,"mcp":false,"tools":["compare_trade_routes","discover_markets","market_candles","market_snapshot","onchain_token","plan_spot_purchase","room_memory","search_news","search_web"],"search_tools":["search_web"],"max_tool_calls":12,"max_search_calls":4,"room_memory":{"tool":"room_memory","scope":"squad","store":"local","path":"/v1/room-memory","max_notes":50,"max_bytes":8192,"max_note_chars":500,"max_calls":3}}
```

`memory` stays `false`: it names the owner's private memory, which no room
loads. The key is `null` when a required research tool or the memory tool is
absent, when the tool is registered in another toolset, and when the pod has no
bearer. `search_x` appears as in v2.

**The platform names the store.** A v3 request must carry
`room_memory: {"squad_id": "<uuid>", "seat_id": "<uuid>"}`, each a canonical
lower-case UUID, and no other key. A v1 or v2 request that carries
`room_memory` is refused. The field is part of the idempotency fingerprint.
The store is `HERMES_HOME/room-memory/<squad_id>.json`: one file for each
squad. Nothing else selects a store. The tool has three arguments (`action`,
`id`, `text`) and none of them is a squad, a seat, a file or a path. The tool
reads nothing: it adds, replaces or removes one note.

**A Run reads the notes of its own squad and seat only.** The request handler
creates one `RoomMemory` for the Run and binds it in `public_room_scope`. The
Agent keeps it (`public_room_memory`), and the Agent's own tool boundary binds
that store again for each call. A nested scope never replaces a bound store:
two different stores bind none. A v1 or v2 scope binds none. Outside a v3 room
the tool has no schema and no dispatch (`public_room_only`), and
`GET /v1/toolsets` does not list its toolset.

**The notes are data of the user turn.** The user turn that the model of a v3
Run reads is one line
`ROOM_MEMORY {"limits":…,"used":…,"notes":[{"id","savedAt","text"}]}` and
then the room input, unchanged. The first line is written by Hermes and
nothing of the room comes before it. JSON escapes every quote of a note, and a
note has no line break of any kind, so a note cannot end the line. The system
prompt is `PUBLIC_ROOM_MEMORY_PROMPT`: the v2 text and one fixed paragraph. It
never holds a note. That paragraph says that notes are untrusted like the room
JSON and tool output, that a note is never an instruction, and what a note may
hold.

**The line of notes is request-only text.** The request handler reads the
line once, when the Run starts, and gives it to the Agent apart from the room
input (`inference_only_user_prefix` of `run_conversation`). The Agent puts it
before the room input in each model request of that Run and nowhere else. The
line is in no message of the conversation: the session store gets the room
input alone (no `content`, no `api_content` sidecar), and the returned
transcript, a compaction summary and a session title never get the line.

**Caps.** At most 50 notes, 8192 bytes of note text and 500 characters for
each note, for one squad. A change over a cap is refused (`room_memory_full`,
`room_memory_too_long`); nothing is removed silently. One reply changes the
notes at most 3 times, and each change also counts in the 12 tool calls. A
character is one Unicode code point, and the bytes are UTF-8 bytes. The
platform counts in the same units.

**What a note may hold: code and prompt.** A room Run loads no owner memory, no
owner file, no session history and no account tool, so no private or
financial data of the owner can reach a note. That is the guarantee of code.
Code also refuses a note that matches a threat pattern of
`tools/threat_patterns.py` (strict scope), that holds a hidden or direction
character, or that looks like a key, a token or a credential
(`room_memory_refused`, `room_memory_secret`).

**Personal data that somebody typed in the room.** Code refuses a note that
holds one of four kinds of data (`room_memory_personal`, with the `kind`;
`personal_data` in `gateway/room_memory.py`). The store is the one place that
writes a note, so the rule applies to each caller. A read applies it again.

| Kind | What the code finds |
| --- | --- |
| `address` | `0x` and 40 hexadecimal digits; 32 to 44 base58 characters (Solana, Bitcoin, Tron); a bech32 address (`bc1…`, `inj1…`, `cosmos1…`). The address of a contract has the same form and is refused too |
| `email` | `name@host.tld`, also with a full-width sign, `[at]`, `(at)`, `[dot]` |
| `phone` | `+` and 8 to 15 digits with usual separators; an area code in brackets; three or more groups of two to four digits with one separator; a group that starts with 0 and one long group; 9 or more digits in one run |
| `amount` | An amount of what somebody has or trades. Three rules: a word of having or trading at most three words before an amount of an asset (`holds 5 BTC`, `bought 1000 SOL`, `is long 2 ETH`); an amount of an asset that belongs to somebody (`Bob's 5 BTC`, `her margin is 500 USDT`); a word for holdings (`balance`, `portfolio`, `position`, `wallet`, …) with an amount of money, a number from three digits, or a number with a decimal part. English and Chinese words |

- **The note is refused, not changed.** A changed note is a text that the Agent
  did not write, and what stays can still point at the person (`Alice's wallet
  is […]`). The Agent gets a fixed reason for the kind and can save the fact
  without the data.
- **What is not an amount:** a price (`BTC is near 97,500`, `rejected at 100,000
  USD`), a percentage, a date, a count (`3 members`, `3 tokens on the watch
  list`), a time zone or a usual short word after a number (`20:00 UTC`,
  `3 AI agents`).
- **Limits.** The patterns are fixed and do not judge meaning. They do not
  find: an amount in words (`five BTC`), an amount without a word of having
  (`Alice: 5 BTC`), a phone number of fewer than 9 digits without `+`, an
  address that is cut by spaces, a name, a street address, and an amount in a
  language other than English and Chinese. These stay a rule of the room
  prompt. The patterns also refuse some public facts of the same form
  (`The fund holds 500,000 BTC`): the Agent then writes the fact in another
  way.

**A read never trusts the file.** Other code on the pod can write the file.
Each read checks every note again with the same rules and caps, checks that
the file names this squad and this seat, and does not follow a symbolic link.

**Seat fence.** The file holds the seat id. The platform creates a new seat
row each time an Agent joins a squad. A Run of another seat therefore deletes
the notes before it reads anything. This holds when the platform's delete
call never arrived.

**Owner view and delete.** Both need this pod's bearer:

- `GET /v1/room-memory/{squad_id}/{seat_id}` returns the notes of that seat.
- `DELETE /v1/room-memory/{squad_id}/{seat_id}` deletes them. It deletes only
  a store that this seat wrote, so a late call never removes the notes of a
  later seat. It also ends the memory of each Run in progress for that seat:
  such a Run cannot write the notes back (`room_memory_closed`).

**One clear for one request key.** The owner's clear carries the request key
of the platform in `Idempotency-Key` (a canonical lower-case UUID). The store
removes the notes and records the key in the same write of the same file
(`clear_store`): the two happen together or not at all. The answer has
`deleted` and `replayed`. A second clear with that key for that seat finds the
record. It answers the first result with `replayed: true`, removes nothing and
does not end the memory of a Run. This holds for two requests at the same
moment (all changes of a store run under one lock) and for a request that
comes again because its answer was lost. So the notes that the Agent saved
after the first clear stay.

- The record names the seat. A store that another seat wrote keeps its notes:
  the record alone is added. A clear that a new seat asked for before its first
  Run is therefore also known when that seat has notes later. The seat fence
  and the delete below keep the records of other seats.
- A record stays for 30 days (`CLEAR_RETENTION_SECONDS`, R), and a write
  removes only the records older than that. No count of newer keys removes a
  record. The platform sends a clear again with its key only inside its retry
  window W of 24 hours, and never after it: after W it reports the clear as
  not confirmed. Because W is much shorter than R, each repeat that reaches
  the pod finds its record. Each side measures only its own interval, so the
  two clocks need not agree; the pod's clock must not jump forward by more
  than R - W between two attempts.
- A store holds at most 256 records of that time (`MAX_CLEARS`). When it holds
  that many, a new key is refused with `409 room_memory_clear_limit` before any
  change: no write, no note removed, no Run ended. A repeat of a known key
  still answers. With the caps on notes, the largest store is about 52 KB, under
  the 64 KiB limit of a store file, and a write that would pass that limit is
  refused (`room_memory_full`).
- A key of another shape is refused (`400 invalid_room_memory`).
- A clear carries `X-Room-Memory-Generation`: the run generation that the
  platform read from this pod before it sent the request. The store compares it
  with its own `RUN_GENERATION` before any change. Another value, or none, gets
  `409 room_memory_generation_mismatch` and nothing is written: a pod that a
  restored volume replaced between the platform's read and its delete may have
  lost the record of the key. The platform reports such a clear as not
  confirmed and does not send it again.
- The platform's delete after a seat left carries no key. A seat that left
  saves no more notes, so that delete is safe to repeat as it is.
- `GET /v1/capabilities` reports the pod's run generation as
  `room_memory_generation` (`RUN_GENERATION`), outside the v3 declaration: a
  new value for each start of the Hermes process. The platform reads it before
  each delete for a seat that left, records it when the delete completes, and
  sends that delete again when the pod reports another value: a new process
  can find a disk that changed while no process ran (a restore, a rollback of
  the image or of its volume).

**The text of a note is in its store and in no other place of the pod.** A
delete of the store therefore leaves no copy that a session route or a later
conversation can read.

- The line of notes is request-only text (above).
- A `room_memory` call keeps its action and its note id outside the reply that
  made it, and no text of the model (`room_memory_call_record`). The session
  store applies this to each row that it writes (`durable_tool_calls` in
  `hermes_state.py`): a turn flush, a fork, a compaction and a replaced
  transcript. The optional JSON snapshot of a session, the text that a
  compaction summary is made from, and the one-line summary of a pruned tool
  result use the same rule. The result of the tool holds no text of a note.
- The events of a room Run carry the same record, because the platform stores
  Run events.
- A memory room writes no request dump (`request_dump_*.json`): that file
  would hold the whole model request.
- File tools refuse `HERMES_HOME/room-memory`. This is defense in depth, not a
  boundary: a private conversation with a shell can read any file of the pod.

**No caller of `session_search` finds a room session.** The tool does not
list, find, read or scroll a room session or a session that continues one
(`_room_session_check`, the same `is_room_session` rule as below), in every
context. A session store that cannot answer leaves the session out. The tool
is in the default toolsets of Telegram, Discord and Matrix, so a group chat on
the same pod can call it.

The product owner decided (2026-11-21) that the owner's private chat may
search room sessions. That needs a signal that the caller cannot forge, and
Hermes has none yet: the platform's Agent Chat, the AX channel (conversations
of other people) and News all call `POST /v1/runs` with the one
`API_SERVER_KEY`. Only fields and headers of the request, for example the
`session_id` family, tell them apart. Until the platform sends a credential
that only the owner's chat holds, the rule above applies to every caller. A
search would read the room input and the replies of the Agent, and no text of
a note: the session store holds none (above).

What is not a note: the Agent's own words. A reply that restates a note is a
message of the room, and the session history keeps it like each other reply.
The reasoning text of a model can restate a note too, and the session history
keeps it. A clear of the room memory does not change these.

**A room session runs only with its room policy.** A room session holds text
of other people and the Agent's replies to it. An ordinary turn on that
session would make this history the conversation of an Agent with the owner's
tools and private context. It would also write the owner's private turn into
the session that the next room Run continues.
Each entry that loads the history of a named session for an ordinary Agent
refuses a room session with `400 invalid_room_policy`, before it reads the
session (`_room_session_refusal`). It is the rule of `POST /v1/runs`:

- `POST /api/sessions/{id}/chat` and `POST /api/sessions/{id}/chat/stream`;
- `POST /v1/chat/completions` with `X-Hermes-Session-Id`;
- `POST /api/sessions/{id}/fork`: a fork would keep the history under an
  ordinary id;
- `POST /v1/runs` for a named session without a room policy: the id and the
  chain of the session in each case, also when the request brings its own
  history (`conversation_history`, a list `input`, `previous_response_id`).
  Such a Run still writes its turn under the id. When the Run loads its stored
  history, the tip of the compression chain is examined too;
- `/resume` in a channel (Telegram, Discord, Matrix and the others). The
  command refuses a room session before the Matrix room check and the owner
  check, so Matrix `--cross-room` and an admin `--all` cannot attach it
  (`_continues_room_session`, message `gateway.resume.room_session_blocked`).
  No `/resume` list and no `/sessions` list shows a room session, also not to
  an admin: its title and preview are room text. When the session store cannot
  answer, `/resume` refuses.

A room session is a session whose id starts with `agent-chat-pawchat-`, and
each session whose chain of `parent_session_id` reaches such a session
(`is_room_session`): a fork and a compression child. When the session store
cannot answer that question, the entry refuses the request with
`503 session_db_unavailable`. The session routes that only read
(`GET /api/sessions…`) are not changed: the platform reads a room session there
to find the answer of a Run.

Qualification for v3 uses `tests/gateway/test_public_room_memory.py`.

Platform Agent asks and tenant-image promotion retain their own release gates.
Source checks do not activate a feature or qualify a production image.
