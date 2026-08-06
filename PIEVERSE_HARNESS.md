# Pieverse Harness

This fork is based on upstream Hermes Agent commit
`863e31318553cda8ad61df681d08175364d4164b`.

The Pieverse harness is intentionally limited to hosted-platform integration:

- additive managed configuration for platform-owned plugin and skill lists;
- hosted-tenant onboarding behavior;
- internal platform control APIs for runtime sync, pairing, reload, status, and
  session prewarming;
- compatibility between bundled messaging plugins and Pieverse
  channel-gateway, including LINE, Telegram proxying, and the managed
  WhatsApp plugin;
- the hosted `/pieverse-byok` command and its plugin-command dispatch support;
- CertiK-backed security checks for user-installed and external skills while
  trusting image-managed platform skills.

Photon lifecycle and health monitoring use the upstream implementation. The
fork does not carry the retired core LINE adapter or old Photon watchdogs.

Future upstream refreshes should start from the selected upstream commit and
reapply the current harness as a curated overlay, rather than merging the
historical fork graph. Resolve conflicts in favor of the new upstream
architecture, then port only the hosted-platform behavior described above.
