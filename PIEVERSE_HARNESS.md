# Pieverse Harness

This fork is based on upstream Hermes Agent commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`.

The Pieverse harness is intentionally limited to:

- additive managed configuration for platform-owned plugin and skill lists;
- hosted-tenant onboarding behavior;
- compatibility between the bundled LINE plugin and Pieverse channel-gateway;
- the hosted `/pieverse-byok` command and its plugin-command dispatch support.

Photon lifecycle and health monitoring use the upstream implementation. The
fork does not carry the retired core LINE adapter, old Photon watchdogs, or
unrelated third-party skill-scanning and skill-gating patches.

Future upstream refreshes should start from the selected upstream commit and
reapply this small harness diff, rather than merging the historical fork graph.
