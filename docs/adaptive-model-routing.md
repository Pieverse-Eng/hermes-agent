# Native adaptive task recovery

The Message App TurnRunner resolves `auto/adaptive` before constructing or
reusing an inference agent. Scoring uses the current Pieverse key/base URL;
this adapter does not own the scoring policy or add a billing operation.

The native inbound message ID identifies a new task independently of the reply
anchor. Telegram topic replies may have no anchor, and Feishu messages may
share a parent anchor; neither changes task identity. Turns without a native ID
receive a UUID identity saved with the original request before scoring.
Normally completed queued turns start new tasks. Interrupted recursion retains
the selected task snapshot.

An explicit fresh `resume_pending` marker for the same live session also
retains the original request and decision when a real user message resumes
work. Freshness uses the same transcript-or-marker window as native recovery.
A stale marker, suspended/replaced session, or completed queued turn cannot
reuse that marker to inherit the previous task. Blank startup restoration
uses that same explicit marker and replays a saved receipt only for the same
session. Empty text alone never identifies recovery: a captionless native image
starts a new task with image modality and a neutral image-input goal. Existing
voice transcription and audio/video attachment text preparation stay unchanged.

Adaptive metadata writes opt into authoritative SQLite persistence. If the
primary request write fails, scoring does not start. If the decision write
fails, inference does not start and in-memory metadata is restored, so a later
save cannot publish the failed decision. A successful SQLite commit is durable
even if the legacy JSON mirror fails. General session metadata retains its
existing legacy fallback behavior. Once successfully saved, both concrete
choices and the local scoring-unavailable `auto/paid` fallback replay across
restart without a second scoring attempt.
