# PR #62: recovery, profile controls and literal-value regression fixes

## Scope

Follow-up to the maintainer review of
[PR #62](https://github.com/Pieverse-Eng/hermes-agent/pull/62), using reviewed
head `b99c68df284299efd8eaf5e7f22db15bda367716` as the starting point.
Keep the existing API contracts, stored data, ordinary dotenv behavior and
single-profile CLI behavior. No schema migration, dependency update or new CI
gate is required.

## Reproduced defects and corrections

| Area | Behavior reproduced before the correction | Correction and retained coverage |
| --- | --- | --- |
| Profile pairing control | All 13 HTTP profile cases failed: a valid worker credential read or changed the default store; the older Telegram projection had the same problem. | Resolve both control surfaces through the authenticated profile's native store; cover reads, approval, every revoke mode, wrong keys, unknown profiles and a missing cached store. |
| Primary-store startup | Two HTTP cases completed an approval while another thread held the primary store's lock because the explicit profile path created a second store. | Reuse the primary store only when its captured home matches the requested profile; cover both the default and a named primary profile with event-ordered lock tests. |
| Pairing mirrors | Scoped writes changed the process allowlist; revocation purged another profile's live adapter; successive revocations reused a scope snapshot and restored an earlier grant. | Bind mirrors to the store's home, read current profile state, opt out of process-environment writes, restrict adapter updates to the owning store, and batch account revocation under its lock. |
| LINE authorization | Two real adapter-gate cases still authorized a revoked paired user through the cached `allowed_users` list. | Clear the owning adapter's supported user-list snapshots and config entries; preserve other users, groups, rooms and profiles. |
| Run recovery | Ten read-only/retention cases attempted `BEGIN IMMEDIATE`; two actual HTTP/SQLite contention cases blocked the event loop and returned `500`. | Use a scoped read and shared expiry predicate; offload storage and owner-death reconciliation while retaining event-loop ownership of caches. Test writer-release event order, expiry boundaries, key reuse and completion racing a stale snapshot. |
| Literal environment values | Fourteen initial cases failed across runtime readers, raw Unicode separators, decoding-mode cache changes and save/reload. Standalone send had two additional literal-mode failures. | Share one pure format parser and writer across startup, config/provider reads, profile secrets, reload and send; retain ordinary parsing paths. |
| Literal file maintenance | The migration sanitizer trimmed an unquoted literal value; writer calls could not preserve the process environment during scoped edits. | Skip generic dotenv repairs in literal mode; add explicit `update_process_env=False` while preserving the default writer behavior. |
| Publication receipts | Omitting `registered` reused the run context in both a unit path and a real HTTP/SSE publication. An empty object already behaved correctly. | Normalize presentation for every accepted opted-in acknowledgement; retain acceptance of older hosts and emit `context: null` when no context was registered. |
| Log tails | Two initial-window cases dropped a complete first line, including a window containing exactly one complete trailing line. Inside-line and byte-zero controls passed. | Inspect the preceding byte before dropping a partial record; preserve cursor and response schemas. |

The clarification-detach test also had a synchronization error: registration
preceded publication, so the test sometimes removed the stream before the
question was delivered. It now waits for the actual SSE question. Production
clarification semantics are unchanged.

All defect reproductions were run before their corresponding production edits.
Tests use real store files, SQLite connections and HTTP/SSE paths where relevant;
they do not assert source text. Concurrency assertions use events rather than
narrow elapsed-time thresholds. Profile fixtures isolate both `HERMES_HOME` and
the filesystem home.

## How to verify

Use the repository's canonical runner and an interpreter with the locked dev,
messaging and anthropic extras. Local loopback access is required by the HTTP
tests. Disable file retries so a failure cannot be hidden by an automatic rerun:

```bash
HERMES_PYTHON=/path/to/venv/bin/python scripts/run_tests.sh --file-retries 0 -j 2 \
  tests/agent/test_synthetic_turn_display_kind.py \
  tests/agent/test_secret_scope.py \
  tests/agent/test_secret_scope_tier1_migration.py \
  tests/gateway/test_api_host_tools.py \
  tests/gateway/test_api_server_active_work_drain.py \
  tests/gateway/test_api_server_interactive_messages.py \
  tests/gateway/test_api_server_native_runs.py \
  tests/gateway/test_api_server_platform_logs.py \
  tests/gateway/test_api_server_platform_pairing.py \
  tests/gateway/test_api_server_pairing_profiles.py \
  tests/gateway/test_api_server_run_lookup.py \
  tests/gateway/test_api_server_runs.py \
  tests/gateway/test_publication_receipts.py \
  tests/gateway/test_pairing.py \
  tests/gateway/test_pairing_allowlist_bypass.py \
  tests/gateway/test_pairing_profile_mirrors.py \
  tests/gateway/test_multiplex_pairing_stores.py \
  tests/gateway/test_api_server_multiplex_secret_scope.py \
  tests/gateway/test_api_publication_ack.py \
  tests/gateway/test_host_tool_broker.py \
  tests/gateway/test_api_server_tool_history.py \
  tests/gateway/test_line_plugin.py \
  tests/gateway/test_telegram_auth_check.py \
  tests/hermes_cli/test_pairing.py \
  tests/hermes_cli/test_env_literal_values.py \
  tests/hermes_cli/test_env_loader.py \
  tests/hermes_cli/test_env_load_cache.py \
  tests/hermes_cli/test_env_export_line_lifecycle.py \
  tests/hermes_cli/test_env_export_prefix.py \
  tests/hermes_cli/test_env_sanitize_on_load.py \
  tests/hermes_cli/test_send_cmd.py \
  tests/hermes_cli/test_managed_scope_env.py \
  tests/hermes_cli/test_managed_scope_regression.py \
  tests/hermes_cli/test_config.py
```

## Acceptance record

The complete command above passed **496 tests across 34 files, with 0 failures
and 2 existing skips**, in 59.0 seconds with two workers and file retries
disabled. The runner's bytecode precompilation, the configured Ruff checks on
all changed production Python files, and `git diff --check` also passed.

The validation environment is Linux with Python 3.11.17 and SQLite 3.53.1,
using the repository's frozen lockfile. These checks exercise the gateway
contracts locally; they do not repeat the original PR author's TDX hardware
acceptance.

## Compatibility and rollout

- SQLite schemas, existing reservations, retention deadlines, acknowledgement
  rules, native run IDs and transcript provenance remain unchanged.
- Existing pairing JSON layouts and migration paths remain readable. Old
  `revoke()` and `clear_pending()` callers retain their contracts. Static grants
  outside the requested paired users are preserved.
- Ordinary dotenv reads, interpolation, sanitization and process-environment
  updates retain their defaults. The literal format is opt-in through the
  launcher's `HERMES_ENV_LITERAL_VALUES=1`.
- Older publication acknowledgements that omit `registered` still succeed.
  Their opted-in visible context is now null, matching the documented contract.
  Unopted delivery keeps its existing context behavior.
- Log cursor and endpoint response schemas remain unchanged.

Deploy with the normal gateway restart procedure. No data conversion or cleanup
is needed. A code rollback must retain the existing database, pairing files and
environment files; deleting state would defeat recovery. Reverting this
follow-up restores the known profile-isolation and decoding defects, so a
forward correction is preferable if a regression is found.
