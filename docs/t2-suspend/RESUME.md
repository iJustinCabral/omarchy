# Resume here: permanent T2 hibernation

Checkpoint date: September 29, 2026. **Battery milestone COMPLETE; update-survival path implemented in source and independently audited; overall goal unfinished. No new physical test is currently needed.** The September 27 battery-only normal-logind S4 restored the original session on the exact MacBookAir9,1 with installed runtime `e489bab7`, the tested source image and the v16 restore image; that evidence is unchanged. The September 29 work is source-only: nothing was deployed, staged or power-tested. Older journal entries describe historical states, not instructions to replay them.

## Reconcile before doing anything

1. Read this file and repository `AGENTS.md`.
2. Inspect `git status --short`, `git log -5 --oneline` and `/proc/sys/kernel/random/boot_id`. Do not assume a restored snapshot contains the latest remote commits.
3. Read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json`, especially the latest checkpoint fields, then [the investigation status](HIBERNATION.md) and [production plan](HIBERNATION-PRODUCTION-PLAN.md).
4. Compare installed runtime, pending markers and durable cycle evidence before any privileged action. Local handoff state is not in GitHub. A missing local file is not permission to reconstruct authority from these notes or rerun a consumed action.

Last observed boot: `a45522fe-3787-4d06-a53e-2e6b896ea210` (September 29, hibernation source image `EFI\Linux\mba_t2_hibernation_source.efi`). Latest independently audited source checkpoint: `ddaca8da`, in `iJustinCabral/omarchy`, branch `fix-t2-vintage-mac-support`. This source checkpoint is **not installed**; the live runtime remains `e489bab7`.

## What actually works, and what remains

| Area | Verified state |
| --- | --- |
| Normal hibernation | Two AC-powered normal-logind S4 cycles and one battery-only cycle restored the original session on this MacBookAir9,1. |
| Battery milestone COMPLETE | Attended normal-logind cycle `0b8fa4cf-7055-45a5-aa9f-99538a02564e`, ADP1 offline before/after; user reported a working desktop. The 30% threshold is provisional, not measured reserve/endurance policy. |
| Installed runtime | `e489bab70e13bfcbbfacc8811a6f6093e7973dd0`; battery-aware prototype. New update integration is NOT deployed. |
| Package updates | Installed all-package guard STILL BLOCKS updates while enabled. Do not delete or bypass it. |
| Source validation | Update-survival path at `ddaca8da`: update guard 49, maintenance publisher 37 transition + 39 native, package maintenance 21, runtime upgrade 43 tests passed; every piece passed an independent audit, then a whole-path integration audit. No VM or host run of the native path yet. |
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

Status at `ddaca8da` (source only, each piece independently audited, then a whole-path integration audit that walked publish → update → kernel update → further updates → re-entry and found no step that blocks after a legitimate coherent update). **Deployment is NOT approved**, and installed `e489bab7` does not recognize any of it.

Done in source:

- **Runtime-upgrade locks** (`686b4988`): the native adapter owns `db.lck` and the physical-cycle flock instead of calling installed `e489bab7`'s lock API, which lacks `check_physical`. Foreign or altered pacman locks are never modified and fail closed; recovery is unbounded until the compatible veto is verified in the current attempt, then bounded (`RECOVERY_BOUND`, 300 s) and exits non-zero with the veto retained.
- **Finite native maintenance publisher** (`47d9d88e`, `91657faf`, `ddaca8da`): `boot_policy_native.py maintenance` moves the machine into inactive maintenance under DB lock, physical lock and real inhibition. It checks saved-image absence, the stock fallback and production UKI BLAKE2b, the installed drop-in, effective ExecStart (no extra Exec hooks) and behavioural marker vetoes, then writes the deactivation veto first and archives the audited resume tuple (`maintenance-resume.json`), intent and marker in that order. Re-entry reuses the update guard's exact validator and returns `already_inactive` after coherent kernel/UKI updates.
- **Native ALPM update guard** (`19a5ca02`, `875c0779`, `ddaca8da`): with a valid marker, admits ordinary package transactions from the authenticated fixed runtime (pinned-byte execution, no stale bytecode), under the physical lock, after the exact inactive validator and a saved-image check against the archived resume tuple. It never re-derives qualified artifacts, so updates keep working after kernel changes. Without the marker it is the old blanket guard, now also blocking runtime-upgrade pending state.
- **S3 on the hibernation source image** (`8628d5a5`, `314e0454`): ordinary suspend froze or lost the T2 bridge because patch 0005's hibernation DMA gate ran on S3 resume. Patch 0015 limits the gate and 0011's syscore early wake to hibernation phases. Source-only: it needs a rebuilt candidate stack and a new source UKI before it helps the live machine.

Next tasks, in order:

1. **Bootstrap from installed `e489bab7`:** the new adapter is not directly runnable against that generation, which lacks `image_state.py`. Design and review the separately pinned bootstrap/helper path, then prepare fresh external pins for a runtime containing the guard, publisher and marker-aware `sleep_entry.py`/`product.py`. Never replay consumed v1→v2 deployment `4125726a-4847-4802-a821-953e6abe995a`. Parent-owned inhibitor death, default SIGKILL and power-loss durability remain documented limits.
2. **VM harness against native code:** run the guard's native `main` and the publisher's native maintenance action in the existing diskless/networkless VM harness with real pacman, including a kernel-package update between two transactions. Earlier VM ALPM tests called the fixture validator, not native `main`.
3. **Operator runbook for fail-closed stuck states** found by the integration audit: a crash between marker write and deactivation-pending retirement (guard and re-entry both refuse; manual review); a swapfile relocated or resume cmdline lost after maintenance began (every guard run blocks); a kernel transaction that failed halfway leaving the UKI and `limine.conf` incoherent (fix by rebuilding the UKI, not through pacman).
4. **Reactivation after updates:** evaluate compatibility separately and reactivate only a coherent qualified generation. Unknown compatibility leaves hibernation unavailable, not updates blocked. The marker binds runtime-review bytes; a later runtime deployment needs an explicit reviewed rebind.
5. **Unvetoed kernel routes:** suspend-then-hibernate, hybrid-sleep and direct `/sys/power/state` writes are outside the marker vetoes; the guard's image check is the backstop. Decide whether to veto them explicitly.
6. **Deploy the S3 fix:** rebuild the candidate stack with patch 0015, build a new source UKI that keeps production `.linux` and `.cmdline` byte-for-byte via the pair stager, then ordinary-boot, physical-input and real S3 tests and S4 requalification. Until then do not use S3 on the source image; the stock `Omarchy linux-t2` entry is the S3-safe choice.
7. **Deployment:** only after the above, a fresh reviewed installation. No new laptop S4 test and no boot-image change until final operator OK.

Claude Opus orchestrates and delegates to explicitly overridden Claude Sonnet sub-agents with bounded context and disjoint file ownership; every implementation gets a separate sub-agent audit before integration (see [AGENTS.md](../../AGENTS.md) and [automation](AUTOMATION.md)). Keep physical boot, EFI, module loads and power transitions serialized under the orchestrator. Do not start parallel hardware tests.

## Evidence locations and limits

Recovery follow-up in source: runtime-upgrade failure recovery now stays inside the entered physical-lock scope until it proves unchanged prepublication state or verifies the exact durable compatible veto. Partial publication no longer treats missing completion as success. Recovery preserves foreign evidence, retries creation/readback/file-fsync/directory-fsync faults with paced backoff, settles package-lock release, and reraises the original error without replaying the upgrade. Synthetic tests hold a real competing flock out during repeated repair faults. All 23 native and 22 deployment tests passed, independently rerun by the orchestrator and Sol high auditor; source-only review passed. Unsupported old lock callbacks fail before publication or recovery. This addresses Python-level repair failure, **not parent-owned inhibitor death, default SIGTERM/SIGKILL, context-manager exit/descriptor-close faults or storage power-loss durability**. Whole-path deployment remains unqualified; do not interpret this patch as permission to install.

Additional upgrade audit: repository inspection of deployed generation `e489bab7` confirms it lacks `image_state.py` and its old `_locks` release callback lacks `check_physical`. The new source adapter is therefore **not directly runnable against that generation**. Do not bypass these checks or try deployment to discover the failure. A separately pinned, reviewed bootstrap/helper and lock-compatibility strategy is required. This was source-history inspection, not a host deployment attempt.

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

> Resume the permanent T2 hibernation goal. Read docs/t2-suspend/RESUME.md first and reconcile current boot and repository state against the local handoff. The attended battery milestone is complete; installed runtime remains e489bab7. The update-survival path (runtime-upgrade locks, native maintenance publisher, native ALPM guard) and the S3 fix are implemented and independently audited in source through ddaca8da, not deployed. Claude Opus orchestrates bounded Claude Sonnet implementation and audit sub-agents. Continue with the e489bab7 bootstrap path and native VM harness tests; do not repeat consumed hardware tests. No new physical test without my final OK.
