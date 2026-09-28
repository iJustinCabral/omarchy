# Resume here: permanent T2 hibernation

Checkpoint date: September 27, 2026. **Goal unfinished. No new physical test is currently needed.** This is the short current handoff; older journal entries describe historical states, not instructions to replay them.

## Reconcile before doing anything

1. Read this file and repository `AGENTS.md`.
2. Inspect `git status --short`, `git log -5 --oneline` and `/proc/sys/kernel/random/boot_id`. Do not assume a restored snapshot contains the latest remote commits.
3. Read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json`, especially the latest checkpoint fields, then [the investigation status](HIBERNATION.md) and [production plan](HIBERNATION-PRODUCTION-PLAN.md).
4. Compare installed runtime, pending markers and durable cycle evidence before any privileged action. Local handoff state is not in GitHub. A missing local file is not permission to reconstruct authority from these notes or rerun a consumed action.

Last observed boot: `0f909934-0ecf-4407-863d-6822c81cb2df`. Last fully verified implementation checkpoint before this handoff: `4f13201071ca68cd41e2d465453a703eb1ee82af`, pushed to `iJustinCabral/omarchy`, branch `fix-t2-vintage-mac-support`.

## What actually works, and what remains

| Area | Verified state |
| --- | --- |
| Normal hibernation | Two AC-powered normal-logind S4 cycles and one battery-only cycle restored the original session on this MacBookAir9,1. |
| Battery | Successful cycle `0b8fa4cf-7055-45a5-aa9f-99538a02564e`, ADP1 offline before/after; user reported a working desktop. The 30% threshold is provisional, not measured reserve/endurance policy. |
| Installed runtime | `e489bab70e13bfcbbfacc8811a6f6093e7973dd0`; battery-aware prototype. New update integration is NOT deployed. |
| Package updates | Installed all-package guard STILL BLOCKS updates while enabled. Do not delete or bypass it. |
| Source validation | 206 focused tests passed at `4f132010`; real owner-lifetime and real pacman disposable VM cases passed. These do not establish native maintenance admission. |
| Remaining goal | Safely integrate normal updates, compatible generation rebuilding/reactivation, measured battery policy, and maintainable support/qualification for other T2 models. |

Battery cycle archive: `/var/lib/omarchy/t2-hibernate-product/archives/cycle-0b8fa4cf-7055-45a5-aa9f-99538a02564e`. Completion SHA-256 `d6f31ae7eb113f4cd7fc3c746e164269012c6a879a3ea749036aa4f6e89936cf`. The cycle is consumed, not a test to rerun.

## Current implementation direction — do not restart the broker detour

Separate permission to update the OS from permission to reactivate hibernation:

1. Under exclusion, prove no saved image, establish verified stock fallback, disable hibernation admission and durably retain `package-maintenance.pending`.
2. Allow ordinary authorized package transactions when the inactive-maintenance evidence is valid. The marker remains a veto for both sleep routes and activation; it is not a single-use package grant.
3. Evaluate compatibility separately. Reactivate only a coherent qualified generation. Unknown compatibility leaves hibernation unavailable, not OS updates indefinitely prohibited.

The optional client/coordinator/broker experiments remain useful evidence, but are NOT prerequisites for this simpler path. Do not intentionally kill an already-admitted ALPM transaction because a client disappears. Do not spend another session expanding broker ancestry or grants before integrating the finite inactive-state transition.

Plain existing `deactivation` is insufficient: removing opt-in selects stock `systemd-sleep`, and direct product admission can still accept the old qualified artifacts. The durable maintenance marker is needed to veto both routes and reactivation after updates.

## Exact next implementation tasks

These tasks were inspected, then frozen for the user's weekly-limit checkpoint. Native publisher and guard tasks have **no new edits or tests** yet. The runtime-upgrade task finished its bounded source change in commit `039e87402d4fe4cde01ac2b60c3c412be6d936a0`: 22 deployment and 16 native-adapter tests passed, independently rerun by the orchestrator. It is **not independently audited, approved or deployed**; review it before preparing installation. There is no archived WIP patch.

1. **Marker-aware runtime upgrade:** independently review the new source-only v2→v2 support in `runtime_deployment.py` and `runtime_upgrade_native.py` plus their tests. It preserves exact config bytes, uses fresh UUID4 approval and transaction identities, durably consumes approval, rejects an existing maintenance marker, retains prior authority, and binds veto recovery to consumed approval. The new native adapter rejects historical v1 approval; the core retains the old fixture path. Never replay consumed v1→v2 deployment `4125726a-4847-4802-a821-953e6abe995a`. Prepare fresh external pins only after review; ensure qualification, policy, opt-in, hook and boot artifacts remain unchanged. This is not deployment approval.
2. **Finite native publisher:** extend fixed reviewed `boot_policy_native.py` / `boot_policy_transition.py` with a maintenance action, reusing deactivation mechanics and existing DB/physical locks plus real inhibition. No package runner, client or broker is needed for this finite operation. A no-argument fixed native wrapper should supply its own verified prechecks; keep the public fixture transition unable to accept live roots or arbitrary live callbacks. Internal Python tokens are not security against hostile root.
3. **Publisher prerequisites:** before writes, verify the full private reviewed inventory, actual installed hibernate drop-in/effective ExecStart and sleep-entry bytes, and maintenance-aware product/sleep/activation vetoes. Installed `e489bab7` does not recognize the new marker, so it must be upgraded first. Check actual saved-image absence before and after, current stock default and actual production UKI BLAKE2b against its boot entry before retiring the compatible deactivation pending marker. Failure must retain a durable sleep veto.
4. **Native ALPM guard:** own `update_guard.py` and its tests separately. Reuse the existing exact inactive validator behind fixed installed/root-isolated/reviewed-inventory authentication before lazy imports. Keep the public fixture wrapper rejecting `/` and aliases. Actual pacman already owns `db.lck`; do not require it absent. Check current stock bytes, private canonical archived chain, idle ledger, visible EFI, no other pending state/policy/opt-in, and required physical-lock/race contract. Repeated transactions must work without deleting the marker or issuing qualification.
5. **Recovery and re-entry:** preserve foreign/partial records; never silently delete or replay them. Re-entry after updates must not require obsolete product qualification. The marker currently binds runtime-review bytes: a later runtime deployment needs an explicit reviewed migration/rebind, not silently weakened equality.
6. **Verify before deployment:** focused unprivileged fixtures, independent audit, then actual native-boundary tests in the existing diskless/networkless VM harness. Previous VM ALPM tests called the fixture validator, not native `main`. Only after these pass should a fresh reviewed installation/deployment be prepared. No new laptop S4 test until final operator OK.

Use Astra medium as orchestrator and explicitly overridden Sol high agents with bounded context and disjoint file ownership. Keep physical boot, EFI, module loads and power transitions serialized under the orchestrator. Do not start parallel hardware tests.

## Evidence locations and limits

Local durable record: `/home/jjc/.local/state/codex-mba-autonomous/maintenance-inactive-vm-20260927.json`. `/tmp` directories below may disappear after reboot; scripts and bounded results are committed.

| Evidence | Result and SHA-256 |
| --- | --- |
| Owner VM `/tmp/mba-logind-vm-9aav0wg4/serial.log` | PASS; `679d5a32c0550aa0833a0b2984f79eb117002c2c02015d89af64effd05b71310` |
| ALPM VM `/tmp/mba-logind-vm-sxbnae35/serial.log` | PASS; `b78528b1522ed584a8ebeef6a23bfcc51120f1ae2e4cf6aa4d395891dd8f2a8e` |
| ALPM public dependency manifest | All 211 entries independently matched repo and guest; `e76d74ddfcf8225b5106553df0ab8ff808d1c21368033ce032245e7c9f6b4528` |

Owner VM: actual parent death and TERM/HUP/INT retained the owner inhibitor and synthetic locks until explicit safe release after a simulated veto boundary. It did not prove actual coordinator settlement or ALPM failure recovery.

ALPM VM: real pacman installed tiny v1; forged-marker v2 failed in its pre-hook before mutation, leaving v1 payload/database intact. The real database lock, physical lock and owner inhibitor were observed. Native guard still refused both cases. No real saved image, kernel/module update, host package, boot or power operation was involved.

## Never repeat these mistakes

- Do not restage replacement `.linux` images. Private UKIs must preserve production `.linux` and `.cmdline` byte-for-byte. The rejected image SHA `974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd` and earlier v1/v2 images must not be booted again.
- Ordinary boot, diagnostic abort or EFI witness alone is not successful S4 restoration. Preserve all consumed guards and failed vectors.
- Do not run privileged Python from the writable workspace. Only separately reviewed fixed private snapshots may perform host transitions.
- Do not copy embedded unlock assets into GitHub, logs or test guests. The sensitive local extracted source tree is not a source-code snapshot.
- Do not claim completion from green fixture tests. Battery restore is proven on this exact machine; production updates, reserve policy and other-model support remain unfinished.

## Reading map and pasteable resume prompt

[Guide](HIBERNATION-GUIDE.md): human/agent overview. [Mechanism](HIBERNATION-MECHANISM.md): problem and solution diagrams. [Production plan](HIBERNATION-PRODUCTION-PLAN.md): requirements and implementation limits. [Investigation](HIBERNATION.md): detailed historical evidence. Research resource: <https://github.com/macintog/t2-platform-research>; use its actual contents when investigating new hardware paths, not assumptions from its title.

> Resume the permanent T2 hibernation goal. Read docs/t2-suspend/RESUME.md first and reconcile current boot and repository state against the local handoff. Review the source-only runtime upgrade in 039e8740 before deployment. Use Astra medium orchestration with bounded Sol high implementation/audits. Continue the native inactive-maintenance and marker-aware deployment path; do not expand optional broker work or repeat consumed hardware tests. No new physical test without my final OK.
