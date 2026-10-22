# Hosted platform control

The API server's internal platform endpoints require the configured API bearer
key. Hosted confidential supervisors call them over loopback. They accept fixed
operations and never a caller-selected path, shell command or destination.

`GET /internal/platform/gateway/status` includes `processMarker` for the live
gateway and `stateProcessMarker` for the persisted status generation. A controller
must refuse populated platform health when these differ. It must not publish
stale channel connectivity after a gateway restart.

`POST /internal/platform/pairing/{operation}` supports `telegram` and `line`:

- `approve`: `{channel, code}` with an eight-character uppercase alphanumeric
  code; returns `{status: "approved", allowFrom}` or `not_found`. `incomplete`
  means a grant may already be durable; reconcile through `allow-from` before
  retrying. Codes and user names are never echoed.
- `allow-from`: `{channel}`; returns `{allowFrom}`.
- `revoke`: `{channel, mode: "account" | "requests" | "entry", entry?}`;
  returns `{changed, removedAllowFromCount, removedRequestCount, allowFrom}`.
  Entry mode removes matching pending requests as well as the grant. Other
  channels remain intact. The gateway's pairing store lock fences adapters.

These runtime grants are discovery inputs for a hosted controller. The
controller persists its authorized allowlist and rebuilds managed runtime config
from that durable source, including after encrypted restore.

`POST /internal/platform/logs/tail` accepts `{limit?, maxBytes?, cursor?}`.
It reads only `HERMES_HOME/logs/gateway.log`, with at most 5,000 lines and
1,000,000 bytes per read. It returns `{lines, cursor}`; pass the opaque cursor
back to follow. Cursors bind the opened file's device, inode and byte position,
restart on rotation or truncation, and retain incomplete lines for the next
read. Symbolic links and non-regular files refuse. The owner-authorizing
controller must stream answers without persisting or logging their contents.

Confidential images set `HERMES_ENV_LITERAL_VALUES=1` before starting Hermes.
In this mode dotenv loading preserves literal `${...}` text and opaque UTF-8
credential values, without environment interpolation or ASCII credential
sanitization. Ordinary profiles retain their existing dotenv behavior.

## Durable native turn provenance

For an idempotent `POST /v1/runs`, the server stamps the current user message
with `display_metadata.api_run = {id, idempotency_key}` at the normal turn-start
persist. The IDs come from the authenticated native admission. An ordinary user
message remains an ordinary user message; provenance does not change its text,
model input or display kind. Existing SessionDB storage and backups retain it.

Authenticated `/api/sessions/{session_id}/messages` exposes that bounded object
as `api_run` on user rows. It exposes no other display metadata. Capability
`session_run_provenance` names this contract. Shared TEE News uses the exact
idempotency key to associate follow-up replies after supervisor restart, including
identical successive inputs. It never guesses by text, timestamp or position;
compacted-away rows provide no turn evidence. This adds no run-retention lease.


## Current-conversation publication registration

`GET /v1/capabilities` advertises `publication_ack_v1`. A caller may opt in
with the strict boolean `publication_ack: true` on `POST /v1/runs`; configured
API bearer authentication is required. The normal unopted delivery remains
unchanged. `send_message(target="current")` then emits a bounded internal
`__publish_current_message` host request and waits for authenticated registration
through the existing host-result endpoint before emitting `message.interactive`.
A rejected, expired or cancelled registration never falls back to another channel
and never publishes the unregistered message. This transport operation is not
added to the model's tool manifest. Its request budget is 64 KiB; ordinary host
tools retain 8 KiB and all results retain 32 KiB. The acknowledgement's
`registered` object must be a JSON object of at most 32 KiB, or registration is
treated as unconfirmed. Only its card (`coachCard`), `context` and callback
(`callbackScope`) references are added to the delivered message; without a
registered context the message carries `context: null`, never the run context.
The saved tool result carries those references at top level and the whole
`registered` object, unchanged, so follow-up operations can name the original
resource identities. The hosting service must persist those references before
acknowledging; this native protocol does not grant financial execution authority.
