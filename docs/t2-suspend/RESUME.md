# Resume here: permanent T2 hibernation

**Current state (2026-09-30, source of truth for the top of this file; everything below the "History" marker is dated and superseded where it says so).** Map of all documents: [README.md](README.md). Hardware record: [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md). Procedure for the next kernel update: [REQUALIFICATION.md](REQUALIFICATION.md).

- Hibernation is **ACTIVE** on linux-t2 `7.2.7-arch1-Watanare-T2-2-t2`, generation `f4025add13d1` (source `b70b77cd`, restore `8ef56bab`), on the MacBookAir9,1. The source entry is the Limine default and the stock `Omarchy.linux-t2` entry is the fallback.
- The 7.2.7 requalification is complete: source ordinary boot, test_resume, restore boot, S4 vector `ef9f9683`, slot cleanup, generation trial `3ab69461`, qualification `bdadff1b`, `rebind`, and routine S4 cycle `53ac1f92` (`qualified-product-cycle-reconciled`, 2026-09-30 12:28).
- Installed runtime is `ecb35dac` (radio package 1.6). The `omarchy update` integration (`omarchy-update-t2-hibernation pre|post`) is merged in source at `8c2b0976` but is not a runtime file; its prompts have not yet run on the laptop.
- While ACTIVE the update guard refuses bare pacman. `omarchy update` (or the `maintenance` action) pauses hibernation, and `assess` then `reactivate` (or requalification after a kernel change) turns it back on.
- Open observation: lock-screen input did not respond at 2026-09-30 12:56, cause unknown; logind shows an owner-initiated reboot at 12:56:55 (see [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md)). Not proven: other T2 models, battery-only cycle on 7.2.7, long soak.
- Next: (1) take draft PRs #1 to #6 (andrew-boyd/omarchy, #6 is `intel-mac/p10/t2-hibernation`) out of draft with the 7.2.7 result; (2) upstream the t2bce hibernation patches (experiments 0005 to 0017 and `patches/bce`, on t2bce `6780d522`) to linux-t2 so stock kernels hibernate; (3) optionally turn the gen-7.2.7 operator scripts into in-repo tooling.
- Last recorded boot when this block was written: `f46e17c1-a6f0-41e5-9f69-dfd934031c6c` (started 12:57 after the session that performed the routine cycle). Always reconcile with the live boot and the local handoff before acting.

## History

The sections from here on are dated checkpoints kept for the record. Where a statement says hibernation is off, unqualified or not deployed, it describes the date it was written, not now.

Checkpoint date: September 29, 2026 (night) (historical, superseded above). **Runtime `d64069bb` deployed; the machine was in inactive package maintenance on linux-t2 7.2.7 with radio package 1.6 (radio-only). Ordinary S3 passed on the stock entry. Hibernation stayed OFF until a requalification on 7.2.7, which has since completed.** The first `omarchy update` (7.2.6 to 7.2.7) exposed and fixed a driver-package defect; see the incident record below. Older journal entries describe historical states, not instructions to replay them.

## Reconcile before doing anything

1. Read this file and repository `AGENTS.md`.
2. Inspect `git status --short`, `git log -5 --oneline` and `/proc/sys/kernel/random/boot_id`. Do not assume a restored snapshot contains the latest remote commits.
3. Read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json`, especially the latest checkpoint fields, then [the investigation status](HIBERNATION.md) and [production plan](HIBERNATION-PRODUCTION-PLAN.md).
4. Compare installed runtime, pending markers and durable cycle evidence before any privileged action. Local handoff state is not in GitHub. A missing local file is not permission to reconstruct authority from these notes or rerun a consumed action.

Last observed boot: `a45522fe-3787-4d06-a53e-2e6b896ea210` (September 29, hibernation source image; the next reboot selects the stock entry). Installed runtime: `d64069bb` (review `c31e1a43…`). Source branch `fix-t2-vintage-mac-support` in `iJustinCabral/omarchy`.

## What actually works, and what remains (state at 2026-09-27, historical)

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

## Requalification on linux-t2 7.2.7 (completed September 30, 2026)

**Hardware result, September 29, 2026, night.** The new 7.2.7 pair passed every attended gate so far. The source is `b70b77cd`, the restore is `8ef56bab`, and the manifest is `f4025add13d1`. Evidence lives under `~/.local/state/codex-mba-autonomous/gen-7.2.7/h6e/logs/` and `/var/lib/omarchy-t2-hibernation-pair/{test-resume-vectors,s4-vectors}/`.

- The runtime was upgraded under maintenance to `ecb35dac`. The first live attempt failed safely on the adapter's own barrier; that was fixed in `77b293c6` and the leftover was adopted. A second upgrade then deployed the retire kernel-comment fix `ecb35dac`.
- The old 7.2.6 pair was retired. The new pair was built, audited twice, and staged.
- The source ordinary boot passed on boot `442c90c5`. Keyboard, trackpad, Wi-Fi, Bluetooth, and audio all worked, and physical input evidence was captured.
- The source `test_resume` returned and cleaned up on boot `442c90c5`.
- The restore ordinary boot passed on boot `54ad1561`.
- The real attended cold-power S4 vector `ef9f9683` succeeded on boot `10f1df5e`. The result was `returned-and-cleaned` with stages 4/7/2, a cold-PCI restored source witness, and physical input confirmed.
- **Completed, September 30, 2026.** Every gate after that also passed:
  - H6e-clean cleared the V3/V2 stage slots with `cleanup-successful-pair-slots.py` (`6d569778`, fixed in `4c5842ba`). It ran from a root-owned export of the reviewed commit.
  - H6f: the generation trial (cycle `3ab69461`) reconciled with a cold-power S4 on boot `37208ef7`.
  - H6g: the qualification was issued with evidence `bdadff1b`, after an independent review.
  - H6h: `rebind` made generation `f4025add13d1` ACTIVE and made the source entry the Limine default.
  - H6i: one routine S4 through `omarchy-system-hibernate` completed, with result `qualified-product-cycle-reconciled` (cycle `53ac1f92`). The ledger chains it to the last 7.2.6 cycle `0b8fa4cf`.
  - Permanent hibernation is qualified and active on linux-t2 7.2.7.
- Next work:
  - An `omarchy update` integration: prompt to publish maintenance before updating, then assess and reactivate, or explain that requalification is needed.
  - A full documentation and evidence pass.
  - Update PR #6 and take PRs #1–#6 out of draft.
  - Upstream the t2bce hibernation patches to linux-t2.
- Superseded list: remaining steps: H6e-clean (clear the V3/V2 stage slots with `cleanup-successful-pair-slots.py`, `6d569778`), H6f generation trial, H6g qualification, H6h `rebind`, and H6i one routine S4. The update guard refuses pacman until the slots are cleared.

(Historical, written before H6a.) All source work for a new generation was done, each piece independently audited and integrated. At that time nothing had been executed on the machine: it is still on stock 7.2.7 in inactive package maintenance with runtime `d64069bb`, the old 7.2.6 pair still staged, and `assess` reporting `requalification-required`.

- **t2bce rebase** (`a2f5db3b`..`7ea330d7`): patches rebased onto t2linux t2bce `6780d522`, whose unpatched srcversions equal the installed stock modules; pins in `t2bce-source.json` (radio `manifest.json` untouched). See [T2BCE-7.2.7-REBASE.md](T2BCE-7.2.7-REBASE.md).
- **Hardening** (`5469e1b2`, `b6babd8a`): patch 0016 (idempotent mailbox channel pause, refuse suspend after a skipped resume) and 0017 (bounded command-queue idle wait). The candidate is `candidate-7.2.7-h1`.
- **Helpers** (`0807b7d7`): the cold-PCI guard, restore marker v2 and postwrite marker v3 were rebuilt for 7.2.7 with unchanged srcversions and re-pinned. See [HELPERS-7.2.7.md](HELPERS-7.2.7.md).
- **Retire** (`8eea6ec3`, `bf3bb152`): the stager's `retire-after-production-change` removes the old pair after a production kernel change and leaves custody files.
- **Rebind** (`7261f646`..`1500f105`): moves maintenance onto a new generation, with a runtime upgrade under maintenance, a per-generation trial root, and a qualification bound to the generation trial's reconciled cycle. See [REBIND-DESIGN.md](REBIND-DESIGN.md) and DEPLOYMENT gate H6.
- **Operator inputs** for H6a (runtime `0807b7d7`, review `14107eed`) and H6c (pair build and audit) are prepared and audited in `~/.local/state/codex-mba-autonomous/gen-7.2.7/` (`README-gen-7.2.7.md`, `h6a-*.sh`, `h6c-*.sh`). The H6a approval pins the current boot id; after a reboot, regenerate it with `h6a-regen-approval.sh` and re-review it.
- **Next:** H6a, then H6b retire, then H6c build and audit (no power actions), then H6d stage, then the attended H6e and H6f hardware steps, then H6g issue, H6h `rebind` and H6i a routine S4. Claude Code's permission classifier blocked the agent from running the root H6a stage, so the owner runs it or grants a rule.
- **PR:** the curated hibernation product is draft andrew-boyd/omarchy#6 (`intel-mac/p10/t2-hibernation`), stacked on #5. Update it with the 7.2.7 hardware result.

## Exact next implementation tasks (historical, as of 2026-09-29 before the requalification)

Status at `ddaca8da` (source only, each piece independently audited, then a whole-path integration audit that walked publish → update → kernel update → further updates → re-entry and found no step that blocks after a legitimate coherent update). **Deployment is NOT approved**, and installed `e489bab7` does not recognize any of it.

Done in source (each independently audited):

- **Runtime-upgrade locks** (`686b4988`): the adapter owns `db.lck` and the physical-cycle flock; foreign pacman locks are never modified; recovery is unbounded until the veto is verified in the current attempt, then bounded, exiting non-zero with the veto retained.
- **Upgrade bootstrap from `e489bab7`** (`26d428ac`): the only old-generation call that failed was loading `image_state.py`. Root now stages the reviewed `image_state.py` as `runtime-upgrade-image-state.py` (0600); the adapter checks it against the approval's seventh pin `new_image_state` and the new review, executes those exact bytes, and loads the swap-header parser pinned to the old review. A regression test upgrades a real `git archive e489bab7` tree to the new runtime; a replayed approval is refused before any lock.
- **Native maintenance publisher** (`47d9d88e`, `91657faf`, `ddaca8da`) and **interrupted-publication completion** (`4aa30c4f`, `370c323c`): `boot_policy_native.py maintenance` publishes inactive maintenance, or, if a crash left the marker and the deactivation pending together, proves the pending is the one the marker chains to and retires it under the final gate, using the guard validator's strict `ignore`.
- **Native ALPM update guard** (`19a5ca02`, `875c0779`, `ddaca8da`): admits ordinary package transactions from the authenticated runtime under valid maintenance evidence, checking saved-image absence against the archived resume tuple, and keeps working after kernel/UKI updates.
- **S3 on the hibernation source image** (`8628d5a5`, `314e0454`): patch 0015 limits the hibernation DMA gate and syscore early wake to hibernation phases. Needs a rebuilt candidate stack and new source UKI to reach the host.
- **Generation baseline and read-only assessment** (`fcb307ec`, `97e36b33`): entering maintenance archives `generation-baseline.json` (kernel, UKIs, module stack, manifest, config, qualification, driver modules, firmware, root control files, ESP bootloaders, stock Limine projection) before the intent and marker. `boot_policy_native.py assess` compares the current machine with it and reports `unchanged`, `requalification-required` or `unknown` without writing or holding locks while hashing. Baseline capture accepts this Mac's hardlinked Apple firmware and out-of-scope limine hook symlinks.
- **Snapshot churn** (`b2dbf51f`, `a5ffea03`, `52064349`): `limine-snapper-sync` rewrites the snapshot region of `/boot/limine.conf` on every snapshot. Maintenance checks never read that region, and every ACTIVE-path Limine comparison now uses one strict canonicalization (`boot_policy.limine_canonical`) that removes only a recognized snapper region; the default entry, the pair block, the `//linux-t2` entry and all global options stay byte-exact, and snapshot sub-entries may not reuse a top-level entry name. Snapshots no longer silently disable hibernation.
- **Reactivation** (`cf907542`): `boot_policy_native.py reactivate` returns inactive maintenance to ACTIVE source-default hibernation only when the assessment core reports the qualified generation unchanged and every qualified digest still agrees; it changes one `default_entry` line on the current Limine bytes, writes a durable reactivation pending first, and recovers by re-running (rollback before completion, never forward past the boot-config write). Any change requires requalification; anything unknown refuses. The same commit fixes deactivation on a snapshot-churned host (the intent records the approved `after` hash the guard chain pins).
- **Operator documents:** [maintenance runbook](MAINTENANCE-RUNBOOK.md) for fail-closed stuck states, and the [deployment procedure](DEPLOYMENT.md) with operator gates H0-H4.

## Deployment record (September 29, 2026)

| Gate | Result |
| --- | --- |
| H0 | Pass. All old pins matched the prior approval; `/boot/limine.conf` equalled the boot policy's `after_limine_sha256`. |
| H1/H2 (first) | Pass. Runtime `e489bab7` → `cf907542` (approval `43f9b849…`, review `83f8a1a8…`); tree verified. |
| H3 (first) | Refused before any write: the generation baseline required root-owned ancestors, but the qualified source/restore artifacts are operator-owned under `~/.local/state`. Machine verified unchanged. Fixed in `d64069bb` (artifact-mode reader pinned to the manifest), audited. |
| H1/H2 (second) | Pass. Runtime `cf907542` → `d64069bb` (approval `d0d4d176…`, review `c31e1a43…`); tree verified. |
| H3 (retry) | Pass. Transition `f5be4683-011d-40ca-85b2-815508a9bdb1`; marker binds review `c31e1a43…`; policy, opt-in and pendings absent; `default_entry: 2`; archive includes `generation-baseline.json` and `maintenance-resume.json`; update guard exits 0; `assess` reports `unchanged` with no unknown items. |

Evidence (local, not in git): `~/.local/state/codex-mba-autonomous/runtime-upgrade-cf907542/` and `runtime-upgrade-d64069bb/` (exports, staged files, approvals, `h2.log`, `h3.log`, `assess-after-h3.json`), and `claude_deployment` in the handoff.

## Incident and recovery (September 29, 2026)

The first `omarchy update` after H3 upgraded linux-t2 7.2.6.arch2-2 → 7.2.7.arch1-2. The update guard admitted it as designed. DKMS then rebuilt radio package 1.5, which replaced only `t2bce_core` and `t2bce_audio` with hibernation-era builds from pinned 7.2.4-era source, while `t2bce_dma`/`t2bce_vhci` came from 7.2.7 (all four stock srcversions changed in 7.2.7). The split family broke the internal keyboard and trackpad (`t2bce_dma: CQ registration failed (2)`, `t2bce_vhci: module init failed -22`). Nothing on the stock boot or hibernation path needed the DKMS BCE copies: the hibernation images carry their own private BCE stack.

Fix (audited): radio package 1.6 (`c0bb551d`, `bb43fefe`, `45c7684e`) is radio-only, refuses any boot image with a non-stock or mixed BCE family, and only builds for kernels whose stock radio srcversions match a qualified row (7.2.6 and 7.2.7 are identical). The qualification gate reads DKMS's archive of moved stock modules after install; the first live install attempt refused and rolled back cleanly because of that gap, which `45c7684e` fixed. Also `1d1528fb` keeps volatile `/run` state out of the generation baseline (source only until the next runtime deployment).

Recovery, run from Snapper snapshot 4 through a chroot of `@`: installer rollback of 1.5 and transactional install of 1.6 for 7.2.7, rebuilt production UKI (`omarchy_linux-t2.efi`, Limine binds its BLAKE2b), hibernation images byte-identical, maintenance marker intact. After reboot: stock BCE family loaded with no errors, radio from 1.6 (Wi-Fi `1D85357E…`, Bluetooth `4DF58889…`), update guard exits 0, `assess` reports `requalification-required` (kernel, production UKI and control inventory changed; driver items unknown under the installed runtime's older inventory), and a real ACPI S3 lid-close cycle passed (16:44:55 → 16:45:07). Evidence: `~/.local/state/codex-mba-autonomous/recovery-7.2.7-*/`.

Next tasks, in order (historical; items 1 and 3 are done and item 2 is now documented in REQUALIFICATION.md, see the current state above):

1. **Requalification on 7.2.7 (hardware campaign, owner-attended):** rebuild the private candidate stack (patch set through 0015, which also fixes S3 on the source image) and the source/restore UKI pair from the 7.2.7 production UKI, verify offline, then ordinary-boot, physical-input and real S4 qualification, issue a new qualification, deploy a runtime containing `1d1528fb` and a reviewed marker rebind (runtime upgrade is refused while the maintenance marker exists; design needed). Until then hibernation stays off and updates keep working.
2. **Requalification after kernel updates (hardware campaign):** when `assess` reports `requalification-required`, rebuild the candidate stack (patch set through 0015) and the source/restore UKI pair from the new production UKI, verify offline, then attended ordinary-boot, physical-input and real S4 qualification, issue a new qualification, and rebind the maintenance marker to the new generation (not implemented; design first). Until then hibernation stays off after kernel updates while updates keep working.
3. **Deploy the S3 fix:** part of the next UKI pair rebuild (patch 0015); do not use S3 on the source image until then; the stock `Omarchy linux-t2` entry is S3-safe.
4. **Unvetoed kernel routes:** suspend-then-hibernate, hybrid-sleep and direct `/sys/power/state` writes are outside the marker vetoes; the guard's image check is the backstop. Decide whether to veto them explicitly.
5. **Remaining limits:** parent-owned inhibitor death, default SIGKILL and storage power-loss durability of the upgrade; runtime rebind while in maintenance is not implemented (do every runtime upgrade before H3); userspace packages outside the UKI are not generation items.

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

[Overview](HIBERNATION-OVERVIEW.md): plain-language explanation. [Evidence](EVIDENCE-7.2.7.md): the 7.2.7 hardware record. [Requalification](REQUALIFICATION.md): procedure after a kernel update. [Guide](HIBERNATION-GUIDE.md): evidence register and agent contract. [Mechanism](HIBERNATION-MECHANISM.md): problem and solution diagrams. [Production plan](HIBERNATION-PRODUCTION-PLAN.md): requirements and implementation limits. [Investigation](HIBERNATION.md): detailed historical evidence. Research resource: <https://github.com/macintog/t2-platform-research>; use its actual contents when investigating new hardware paths, not assumptions from its title.

> Resume the permanent T2 hibernation goal. Read docs/t2-suspend/README.md, then RESUME.md (the top block is the current state) and reconcile the current boot and repository against the local handoff. Hibernation is ACTIVE on 7.2.7 generation f4025add13d1 and the omarchy update integration is merged (8c2b0976). Next: take PRs #1 to #6 out of draft, then upstream the t2bce hibernation patches to linux-t2. Claude Opus orchestrates bounded Claude Sonnet implementation and audit sub-agents; read agents/skills/t2-hibernation.md. Do not repeat consumed hardware vectors and do not run a boot, EFI or power step without the owner's explicit go.
