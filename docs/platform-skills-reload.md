# Hosted Skill Store reload

`POST /internal/platform/skills/reload` is an internal platform control-plane
operation authenticated with the existing `API_SERVER_KEY`. It fails closed
when no key is configured. It is not a public skill-management API.

The optional JSON `skill` is the installed directory slug (including a
merchant namespace such as `merchant:tool`). When supplied, the directory must
contain `SKILL.md` and pass the existing CertiK/runtime trust gate. Rejection
returns 422; malformed input returns 400; an unavailable runner or reload
failure returns 503. Authentication failures return 401.

The operation reuses `agent.skill_commands.reload_skills()`, removes rejected
commands, refreshes adapter-owned skill menus, and queues the existing
next-turn skill-discovery hint for cached gateway sessions. Skills remain
available through `skills_list`/`skill_view`; a core slash-command name
collision does not make a valid skill unavailable. It does not change cached
prompts, inject a synthetic conversation event, interrupt a running turn, or
request a Gateway restart. Normal invocation-time security checks still run.

Success returns `ok`, `added`, `removed`, `total`, `blocked`,
`adapterRefreshFailures`, and `existingSessionCachesInvalidated: false`.
Counts describe the slash-command catalog; individual adapter menu failures
are reported without undoing catalog activation or skipping other adapters.
Reload requests are serialized, including cancellation while the catalog's
worker thread is running. Hosted activity ownership lasts through completion.

The platform client must treat unsupported endpoints and reload failures as
installed-but-not-automatically-activated, persist the installed files, and
show: **Skill installed. Type /reload-skills in your chat to activate it.**
The client must never automatically restart the Gateway as a fallback.
