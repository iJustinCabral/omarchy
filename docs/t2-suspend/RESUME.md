# Resume here: permanent T2 hibernation

Checkpoint date: September 29, 2026 (evening). **Battery milestone COMPLETE. The update-survival path, the upgrade bootstrap from installed `e489bab7` and interrupted-maintenance recovery are implemented, independently audited and VM-tested in source; deployment is a written, gated procedure awaiting operator approval. Reactivation after updates is not implemented yet.** The September 27 battery-only normal-logind S4 evidence is unchanged. Nothing from September 29 is deployed on the host. Older journal entries describe historical states, not instructions to replay them.

## Reconcile before doing anything

1. Read this file and repository `AGENTS.md`.
2. Inspect `git status --short`, `git log -5 --oneline` and `/proc/sys/kernel/random/boot_id`. Do not assume a restored snapshot contains the latest remote commits.
3. Read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json`, especially the latest checkpoint fields, then [the investigation status](HIBERNATION.md) and [production plan](HIBERNATION-PRODUCTION-PLAN.md).
4. Compare installed runtime, pending markers and durable cycle evidence before any privileged action. Local handoff state is not in GitHub. A missing local file is not permission to reconstruct authority from these notes or rerun a consumed action.

Last observed boot: `a45522fe-3787-4d06-a53e-2e6b896ea210` (September 29, hibernation source image `EFI\Linux\mba_t2_hibernation_source.efi`). Latest independently audited source checkpoint: `28774823` (code), in `iJustinCabral/omarchy`, branch `fix-t2-vintage-mac-support`. This source checkpoint is **not installed**; the live runtime remains `e489bab7`.

## What actually works, and what remains

| Area | Verified state |
| --- | --- |
| Normal hibernation | Two AC-powered normal-logind S4 cycles and one battery-only cycle restored the original session on this MacBookAir9,1. |
| Battery milestone COMPLETE | Attended normal-logind cycle `0b8fa4cf-7055-45a5-aa9f-99538a02564e`, ADP1 offline before/after; user reported a working desktop. The 30% threshold is provisional, not measured reserve/endurance policy. |
| Installed runtime | `e489bab70e13bfcbbfacc8811a6f6093e7973dd0`; battery-aware prototype. New update integration is NOT deployed. |
| Package updates | Installed all-package guard STILL BLOCKS updates while enabled. Do not delete or bypass it. |
| Source validation | At `370c323c`: update guard 53, transition 45, native publisher 40, package maintenance 21, runtime upgrade 51, image state 13, runtime deployment 22 tests, and every other hibernation suite, pass. Each piece had an independent audit; the update path also had a whole-path integration audit. A disposable KVM guest ran the native guard with real pacman through four transactions including a kernel update (evidence below). |
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

Done in source (each independently audited):

- **Runtime-upgrade locks** (`686b4988`): the adapter owns `db.lck` and the physical-cycle flock; foreign pacman locks are never modified; recovery is unbounded until the veto is verified in the current attempt, then bounded, exiting non-zero with the veto retained.
- **Upgrade bootstrap from `e489bab7`** (`26d428ac`): the only old-generation call that failed was loading `image_state.py`. Root now stages the reviewed `image_state.py` as `runtime-upgrade-image-state.py` (0600); the adapter checks it against the approval's seventh pin `new_image_state` and the new review, executes those exact bytes, and loads the swap-header parser pinned to the old review. A regression test upgrades a real `git archive e489bab7` tree to the new runtime; a replayed approval is refused before any lock.
- **Native maintenance publisher** (`47d9d88e`, `91657faf`, `ddaca8da`) and **interrupted-publication completion** (`4aa30c4f`, `370c323c`): `boot_policy_native.py maintenance` publishes inactive maintenance, or, if a crash left the marker and the deactivation pending together, proves the pending is the one the marker chains to and retires it under the final gate, using the guard validator's strict `ignore`.
- **Native ALPM update guard** (`19a5ca02`, `875c0779`, `ddaca8da`): admits ordinary package transactions from the authenticated runtime under valid maintenance evidence, checking saved-image absence against the archived resume tuple, and keeps working after kernel/UKI updates.
- **S3 on the hibernation source image** (`8628d5a5`, `314e0454`): patch 0015 limits the hibernation DMA gate and syscore early wake to hibernation phases. Needs a rebuilt candidate stack and new source UKI to reach the host.
- **Generation baseline and read-only assessment** (`fcb307ec`, `97e36b33`): entering maintenance archives `generation-baseline.json` (kernel, UKIs, module stack, manifest, config, qualification, driver modules, firmware, root control files, ESP bootloaders, stock Limine projection) before the intent and marker. `boot_policy_native.py assess` compares the current machine with it and reports `unchanged`, `requalification-required` or `unknown` without writing or holding locks while hashing. Baseline capture accepts this Mac's hardlinked Apple firmware and out-of-scope limine hook symlinks.
- **Snapshot churn** (`b2dbf51f`): `limine-snapper-sync` rewrites the snapshot region of `/boot/limine.conf` on every `omarchy update`. The maintenance checks never read that region, so updates keep flowing (fixture and VM tests). In source (not installed) the ACTIVE-path Limine comparisons now ignore exactly that region (`limine_canonical`, see the 2026-09-29 snapshot-policy entry in [HIBERNATION.md](HIBERNATION.md)); the installed runtime still requires the staged bytes exactly, so no snapshot may be created before H3.
- **Operator documents:** [maintenance runbook](MAINTENANCE-RUNBOOK.md) for fail-closed stuck states, and the [deployment procedure](DEPLOYMENT.md) with operator gates H0-H4.

Next tasks, in order:

1. **Deploy (operator-approved gates, see [DEPLOYMENT.md](DEPLOYMENT.md)):** H0 root read-only inspection, H1 stage the six files, H2 run the runtime upgrade, H3 enter maintenance (hibernation becomes unavailable and `/boot/limine.conf` returns to stock), H4 first package updates. No boot image, UKI, EFI, kernel or S4 change is involved.
2. **Reactivation after updates (operator decision pending):** the design is to reactivate only when `assess` reports `unchanged`, and to require an attended requalification (new UKI pair, offline verification, physical tests, real S4) for any kernel, module, firmware or bootloader change. The snapshot-region blocker is addressed in source by `limine_canonical` (audit pending); `prepare` still expects the exact staged bytes, so a reactivation must build on the canonical helpers. Until reactivation exists, hibernation stays off after H3 by design and updates are not blocked. The marker binds runtime-review bytes; a later runtime deployment needs an explicit reviewed rebind.
3. **Unvetoed kernel routes:** suspend-then-hibernate, hybrid-sleep and direct `/sys/power/state` writes are outside the marker vetoes; the guard's image check is the backstop. Decide whether to veto them explicitly.
4. **Deploy the S3 fix:** rebuild the candidate stack with patch 0015, build a new source UKI that keeps production `.linux` and `.cmdline` byte-for-byte via the pair stager, then ordinary-boot, physical-input and real S3 tests and S4 requalification. Until then do not use S3 on the source image; the stock `Omarchy linux-t2` entry is the S3-safe choice.
5. **Remaining limits:** parent-owned inhibitor death, default SIGKILL and storage power-loss durability of the upgrade; first-publication native precheck not VM-tested (needs a real qualified artifact pair).

Claude Opus orchestrates and delegates to explicitly overridden Claude Sonnet sub-agents with bounded context and disjoint file ownership; every implementation gets a separate sub-agent audit before integration (see [AGENTS.md](../../AGENTS.md) and [automation](AUTOMATION.md)). Keep physical boot, EFI, module loads and power transitions serialized under the orchestrator. Do not start parallel hardware tests.

## Evidence locations and limits

Recovery follow-up in source: runtime-upgrade failure recovery now stays inside the entered physical-lock scope until it proves unchanged prepublication state or verifies the exact durable compatible veto. Partial publication no longer treats missing completion as success. Recovery preserves foreign evidence, retries creation/readback/file-fsync/directory-fsync faults with paced backoff, settles package-lock release, and reraises the original error without replaying the upgrade. Synthetic tests hold a real competing flock out during repeated repair faults. All 23 native and 22 deployment tests passed, independently rerun by the orchestrator and Sol high auditor; source-only review passed. Unsupported old lock callbacks fail before publication or recovery. This addresses Python-level repair failure, **not parent-owned inhibitor death, default SIGTERM/SIGKILL, context-manager exit/descriptor-close faults or storage power-loss durability**. Whole-path deployment remains unqualified; do not interpret this patch as permission to install.

Additional upgrade audit: repository inspection of deployed generation `e489bab7` confirms it lacks `image_state.py` and its old `_locks` release callback lacks `check_physical`. The new source adapter is therefore **not directly runnable against that generation**. Do not bypass these checks or try deployment to discover the failure. A separately pinned, reviewed bootstrap/helper and lock-compatibility strategy is required. This was source-history inspection, not a host deployment attempt.

Native maintenance VM (2026-09-29): `~/.local/state/codex-mba-autonomous/maintenance-native-vm-20260929/serial.log`, SHA-256 `c9da9a020d18c9469af95af65e3197236997ee7a12b4157193e5c5a3c16ccfc1`, run by `run-logind-disposable-vm.py --maintenance-native` at `bb1f5a89`: real pacman, native guard hook, native re-entry, four admitted transactions including a kernel update, six refused negatives. Simulated: EFI variables, dm-crypt, Btrfs swap mapping tools, UKI bytes and limine regeneration, and the first marker publication.

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

> Resume the permanent T2 hibernation goal. Read docs/t2-suspend/RESUME.md first and reconcile current boot and repository state against the local handoff. Installed runtime remains e489bab7. The update-survival path, e489bab7 upgrade bootstrap, interrupted-maintenance recovery and S3 fix are implemented, audited and VM-tested in source through 370c323c; deployment follows docs/t2-suspend/DEPLOYMENT.md gates, each needing my explicit OK. Next source work: reactivation after updates. Claude Opus orchestrates bounded Claude Sonnet implementation and audit sub-agents. Do not repeat consumed hardware tests.
