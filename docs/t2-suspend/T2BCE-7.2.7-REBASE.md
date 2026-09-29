# T2 BCE hibernation candidate rebased onto linux-t2 7.2.7 (t2bce 6780d522)

Kernel 7.2.6 to 7.2.7 replaced the t2bce driver stack. This records the parity proof, how each experiment patch was carried over, the semantic decisions that need an independent audit, and what the offline checks cannot show. Nothing here was installed, loaded, staged or booted; this is source and module-build work only, and it does not change the hardware-safety position in [HIBERNATION.md](HIBERNATION.md): a candidate that builds and passes offline checks is not evidence that S4 or cold restoration works.

## Parity proof

The upstream commit is `t2linux/linux-t2-patches@6780d522fc19bde5230a1bdef94672d26f0cfc2d` ("Update t2bce for kernel v7.2.7"). Its `1001-Add-t2bce-driver-stack.patch` has sha256 `41e01f7cc0a5cc6b067470b941c7bbe385f6594731e8f234089e4143cb71c50f`. The patch was applied to an empty tree and the unpatched t2bce modules were built against `/usr/lib/modules/7.2.7-arch1-Watanare-T2-2-t2/build` with the same make variables as `build_modules` in `verify-hibernation-candidate.py` (W=1, all five CONFIG_T2BCE_* set to `m`). `modinfo -F srcversion` of each built module was compared with the installed stock module of the same name:

| module | version | built srcversion | installed srcversion |
| --- | --- | --- | --- |
| t2bce_core | 0.09 | CBF33E85F104C4314E57C19 | CBF33E85F104C4314E57C19 |
| t2bce_dma | 0.01 | 836F3E3B99248AC8A592CF9 | 836F3E3B99248AC8A592CF9 |
| t2bce_vhci | 0.02 | 8630FA551D18DCE6116A58E | 8630FA551D18DCE6116A58E |
| t2bce_audio | 0.04 | EAF58ADA196FC5479496750 | EAF58ADA196FC5479496750 |
| t2bce_ave | 0.01 | B7A7D4BE56B793669E65F33 | B7A7D4BE56B793669E65F33 |

All five match, so 6780d522 is the source of the running kernel's BCE modules. The fallback commit 9e773c88 was not needed. srcversion is a hash of the module source files and their headers, so it establishes source identity for the compiled files; it does not establish that the compiler, config or flags were identical (see [radio fingerprint notes](HIBERNATION.md) for the same caveat).

The previous pin (`fea00748`, patch sha256 `f0f77f2d...d7ec`) was rebuilt as the comparison base for the rebase; the differences it has against 6780d522 are the rewrite described below.

## Where the pins live

The new commit, patch digest and the `base`/`patched` tables are in `packages/t2-suspend/t2bce-source.json`. `prepare-source.py` and `fetch-source.py` read that file when it exists and fall back to the manifest keys otherwise. `manifest.json` is deliberately unchanged: its digest is recorded in the provenance of every prepared source, including the radio-only DKMS source, and the radio profile must stay byte-identical. The radio-profile source (`wifi-reenable`, `include_bce=False`) was prepared with the package before and after this change and compared with `diff -r`: identical, including `provenance.json`. The `t2bce_source` and `t2bce_patched` keys still present in `manifest.json` are stale 7.2.6 pins kept only for that reason; the pins file supersedes them for any BCE-inclusive preparation. Treat those two manifest keys as superseded by `t2bce-source.json`: do not edit them (radio parity) and do not read them as the current BCE pin; [INSTALLATION.md](INSTALLATION.md) records the same rule. The audio `timing.h` header, new upstream, was added to both pinned tables. Patch application in `prepare-source.py` now passes `--no-backup-if-mismatch` because `patches/bce/0001-0002` apply with line offsets on the new base; the patches themselves are untouched, and the radio output is unaffected.

## What upstream changed that matters here

Core 0.09 gained a DMA submission gate (`t2bce_dma_disable/enable`, waiting for the command queue to drain), a `dma_completion_lock` mutex serialising the completion thread against resume, explicit disable/enable of the completion interrupt around suspend (`dma_irq_disabled`), a reworked no-state fallback (`bce_pm_suspend_no_state_fallback`: reopen the transport, mark clients, `pm_prepare_no_state` now returning `int`, re-quiesce, `SLEEP_NO_STATE`), a resume that keeps the engine reopening on failure, an hrtimer-driven XHCI PM tick using `ktime_get()`, and `BCE_MB_RESTORE_STATE_AND_WAKE` moving from 0x18 to 0x1B with a state-buffer grow protocol replacing the reject reply. VHCI now resumes its event queues before removing the HCD in `pm_prepare_no_state` and pauses them again. Audio was rewritten around a PCM I/O workqueue and a new timing header.

## Per-patch status

`patches/bce/0001` and `0002`, and experiments `0009` and `0013`, apply unchanged and were not touched. The other seven were regenerated against the new base; each header carries a "Rebased for linux-t2 7.2.7 (t2bce 6780d522)" note. The chain applies in order with `--fuzz=0` and the resulting tree is identical to the working tree the rebase was done in.

**0005 shared-link DMA block: rebased.** Only the probe unwind changed: upstream dropped the segment-list-pool label and left `fail_dev0` inside the NVMe-patch conditional, so the sibling references are now released at a `fail_dev0` label outside it. The new interrupt disable and submission gate are software gates; they do not stop a bus master, so the PCI-level block is kept and nothing is duplicated.

**0006 queue-graph rebuild: rebased, the substantive one.** The no-state suspend fallback is now upstream's, extended with the can-rebuild refusal, the local queue-graph drop after `SLEEP_NO_STATE` and the rebuild in resume. Decisions:

- Ordering is upstream's (reopen the transport, then client teardown, then re-quiesce and send the sleep), because the new submission gate returns `-ESHUTDOWN` while the engine is quiesced and HCD removal sends firmware commands. The old order, teardown while quiesced, would fail under the gate.
- The rebuild runs after `dma_completion_lock` is released. Queue registration completes through the MSI0 thread, which takes that lock, so rebuilding under it would deadlock. The wake, engine enable and finish steps run under the lock as upstream requires.
- Failure exits in resume call `bce_pm_resume_finish_locked()` rather than the old unlocked abort, which would take `dma_completion_lock` again.
- Suspend is refused with `-ENODEV` when a failed rebuild left no command queue, and the idle wait tolerates a missing queue. Upstream's `t2bce_dma_wait_command_queue_idle()` dereferences the command queue and would otherwise crash on the second freeze after a failed thaw rebuild.
- The cold-epoch fallback in restore now also opens the DMA engine (`bce_dma_engine_enable`) before queue registration, since the gate is new.
- The abandoned `-EAGAIN` fallback for a rejected state save is kept for the stateful branch, but upstream's state save no longer produces it; it is dead code, retained to keep the diff minimal.
- The transport `pm_prepare_no_state` hook keeps upstream's `int` signature. Clients add `pm_abort`, `pm_drop_no_state_queues` and `pm_rebuild_no_state_queues`.

**0007 serialise shared PCI PM: rebased.** Context and layout only.

**0009 AVE idle certificate: unchanged.**

**0010 block DMA before queue drop: rebased.** The bus-master block still follows `SLEEP_NO_STATE` and precedes the drop, and the resume-side restore runs before `pci_set_master()` under the completion lock. Upstream's gate stops host submission only, not the device writing into freed rings, so this is not redundant.

**0011 syscore early wake: rebased.** Behaviour is unchanged. Upstream's ordinary resume now enables the completion interrupt before the wake command. The early wake cannot: syscore resume runs with interrupts off and before PCI configuration restore, which is the reason it exists. It polls the mailbox as before and the interrupt is enabled later in `t2bce_resume_mode`. That ordering difference is a risk with no 7.2.7 evidence.

**0013 VHCI command timeout quarantine: unchanged.** Applies with offsets. Upstream's new endpoint-destroy pause confirmation and reset-resume port handling sit alongside it; the reset-resume handling only affects stateful resume.

**0014 remove VHCI before queue pause: reduced to a residual.** Its purpose, HCD removal while event queues are still running so that command replies arrive, is now provided by upstream's VHCI `pm_prepare_no_state` (resume event queues, remove HCD, pause) running after the transport reopen. Keeping the old hook would run HCD removal twice. What remains is the fail-early refusal for a hibernation whose clients cannot rebuild, before any client or transport state is touched. The file name is unchanged so the patch identity in the candidate list stays stable, but its content is a small refusal, not the original reordering. This is a decision an independent audit should confirm rather than trust.

**0015 limit the gate to hibernation: rebased.** Context and offsets only; S3 keeps `.resume = t2bce_resume` and no noirq gate.

## Hardening patches 0016 and 0017 (post-audit)

An audit of the rebase found a hang risk and a lock-pairing hazard. Both are fixed by stacked patches appended after 0015, which the candidate verifier applies with `--fuzz=0` and covers with new offline harnesses. Neither has run on hardware.

**0016 idempotent mailbox channel pause (`t2bce_main.c`, `t2bce.h`).** The channel lock is held from a successful freeze until resume, and `mailbox_channel_active` is false exactly while it is held. `bce_pm_channel_pause()` now returns without locking when the flag shows the channel is already held, and `bce_pm_channel_resume()` returns without unlocking when it is not. This also removes a latent double unlock: the no-state fallback calls `bce_pm_suspend_abort()` once to reopen the transport and again on later failures when the channel is not paused. Separately, `t2bce_resume_with_shared_dma()` and `t2bce_restore()` set a new `resume_skipped` flag on their early `-EIO` return when the noirq step latched `pci_dma_restore_failed`, and `t2bce_resume_mode()` clears it under `pm_lock`. `t2bce_suspend_common()` refuses with `-EBUSY` while it is set, before touching clients, the engine or the channel. After a skipped thaw the device is still frozen with its queue graph dropped, so it is already quiescent and a `.poweroff` must not quiesce it again. In this tree that `.poweroff` already failed with `-ENODEV` because the freeze had dropped the command queue, so the deadlock the audit described was masked by ordering rather than guarded; the refusal and the idempotent pair remove the dependence on that accident. Choice of fix: releasing the lock in the failure path was rejected because the failed thaw deliberately leaves DMA blocked and the device unresumed, and a lock release there would let mailbox traffic reach a stateless firmware. Harness: `tests/test-mailbox-channel-pairing.py`.

**0017 bounded command-queue idle wait (`t2bce_dma/queue.c`, `t2bce_dma_queue.h`, `t2bce_main.c`).** `t2bce_dma_wait_command_queue_idle()` uses `wait_event_timeout()` with `T2BCE_DMA_IDLE_TIMEOUT_MS` (5000) and returns `-ETIMEDOUT`. Its only caller `bce_dma_engine_disable()` now returns `int`, and its only caller `bce_pm_suspend_prepare()` reopens the submission gate, reaps visible completions and returns the error before pausing the channel or stopping the XHCI PM doorbell. Both users of `bce_pm_suspend_prepare()` unwind: `t2bce_suspend_common()` aborts the client prepare and returns without disabling the interrupt, and `bce_pm_suspend_no_state_fallback()` runs `bce_pm_suspend_abort()`, which relies on 0016 for the not-paused channel. For S3, a lost completion now fails the suspend with `-ETIMEDOUT` and the machine stays awake in its running state instead of hanging under `pm_lock`; for hibernation the freeze or poweroff callback fails and the attempt is aborted. `t2bce_dma` is now a patched module: it was identical to stock before. Harness: `tests/test-command-queue-idle-timeout.py`, which also runs the real suspend prologue functions, including the second-quiesce timeout inside the fallback.

Both harnesses compile the real extracted functions with non-recursive mutex stubs (a second lock or a release of a free mutex fails an assertion). Removing the two guards in 0016 makes both tests fail. Shared code is in `tests/t2bce_pm_harness.py`.

## Risks and decisions for independent audit

- The single most important semantic call is 0006's resume ordering and locking, together with 0014's retirement in favour of upstream's VHCI hook.
- Two upstream hooks act on the shared interrupt: `bce_dma_irq_disable()` at the end of every successful suspend and `bce_dma_irq_enable()` at the start of resume. In hibernation, the image is written and read while the vector is disabled; the syscore wake and PCI restore-noirq run in that window. This is untested.
- Upstream's XHCI PM timestamp now uses `ktime_get()`, which does not advance across suspend. Across a hibernation image restore the host monotonic clock is that of the image while the firmware has cold booted; a new epoch should tolerate it, but it is unproven.
- Audio was rewritten. The candidate drops and rebuilds audio queues through 0006, but the new PCM I/O workqueue, timing state and `pm_abort` interaction with the rewrite have not been run.
- Stateful S3 behaviour changed upstream (new wake message, grow protocol, reset-resume ports). 0015 keeps the noirq gate off S3, but the S3 path is now a different upstream implementation from the one qualified on 7.2.6, and hibernation is disabled until requalification anyway.
- The fail-early refusal in 0014 and the fallback's own can-rebuild check both run for hibernation; the duplicate evaluation is harmless.

## Verification performed

`verify-hibernation-candidate.py --kernel-release 7.2.7-arch1-Watanare-T2-2-t2` ran end to end without privileges and published `candidate-7.2.7` under `/home/jjc/.local/state/codex-mba-autonomous/t2bce-7.2.7-rebase/`. It fetches the pinned inputs, prepares the active source, runs the active regressions, applies the candidate patches with `--fuzz=0`, runs the candidate regressions and builds the modules with W=1. The only warning in the build output was the environmental "pahole version differs from the one used to build the kernel" line, which the unpatched parity build also produces; no new compiler warnings appeared.

Candidate module srcversions (patched, 7.2.7): t2bce_core 0.09 2872B359423EB3B2DDC108F, t2bce_dma 0.01 836F3E3B99248AC8A592CF9 (identical to stock, unpatched), t2bce_vhci 0.02 D6A4F0C4742C9FD289568DF, t2bce_audio 0.04 5D7F99F76022CA6E84DFB8C, t2bce_ave 0.01 3B8513911A86C7A1E4FEE5A. The module sha256 values are recorded in the candidate `provenance.json`.

Tests re-anchored: `test-cold-s4-rebuild.py` was the only pattern test that failed after the rebase. Its extracted-function harness now models `bce_pm_suspend_no_state_fallback`, `bce_pm_resume_finish_locked`, the completion lock, the absent-command-queue refusal, `prepare_no_state` failure and the cold-path engine enable. The old assertion that HCD removal precedes the client prepare was replaced by the invariant it protected (transport reopened first, VHCI hook resumes the event queues before removing the HCD). New checks assert the queue rebuild never runs under `dma_completion_lock` and the wake and finish steps do. `test-dma-quiesce.py`, `test-syscore-early-wake.py`, `test-vhci-command-timeout.py`, `test-shared-pci-pm-serialization.py`, `test-ave-hibernation-idle.py`, `test-bce-hibernate-pm.py` and `test-bce-audio-hibernate-pm.py` pass unchanged. `test-preparation.py` gained two cases for the pins file. Counts are recorded at the end of this document.


### Candidate `candidate-7.2.7-h1` (patches 0005 to 0017)

`verify-hibernation-candidate.py --kernel-release 7.2.7-arch1-Watanare-T2-2-t2` ran end to end without privileges from the pinned input and published `candidate-7.2.7-h1` under `/home/jjc/.local/state/codex-mba-autonomous/t2bce-7.2.7-hardening/`. All regression programs passed (23 PASS lines, up from 21 with the two new harnesses), all patches applied with `--fuzz=0`, the ten `W=1` module builds produced no compiler warning (only the environmental pahole line). Module srcversions: t2bce_core 0.09 `E6502516231074FB1ADB781`, t2bce_dma 0.01 `D8292CC3FFC947C39023071` (was stock `836F3E3B99248AC8A592CF9`, now patched), t2bce_vhci 0.02 `D6A4F0C4742C9FD289568DF`, t2bce_audio 0.04 `5D7F99F76022CA6E84DFB8C`, t2bce_ave 0.01 `3B8513911A86C7A1E4FEE5A` (the last three unchanged from `candidate-7.2.7`). The radio-only source (`wifi-reenable`, `include_bce=False`) prepared with this tree is byte-identical to the one prepared at 7ea330d7, `provenance.json` included.

**Module sha256 is not reproducible across builds.** `t2bce_vhci`, `t2bce_audio` and `t2bce_ave` have the same srcversion in `candidate-7.2.7` and `candidate-7.2.7-h1` (same source) but different file sha256 (`c4c0723d...` against `9188a95f...`, `f157e572...` against `a87fbcae...`, `dac42c89...` against `589fde2d...`), because the out-of-tree build embeds its random temporary path. Verify that a rebuild matches a previous candidate by `modinfo -F srcversion`, not by file hash. The `candidate_module_sha256` values in `provenance.json` identify one build's files only. Searched the repository: the sole consumer is `validate_candidate()` in `experiments/build-hibernation-candidate-uki.py`, which compares a candidate directory's files with that same directory's provenance; no pin or verification compares candidate `.ko` sha256 across independent builds. The hard-coded module hashes elsewhere (`SOURCE_MODULE_SHA256` in `audit-cold-pre-cpu-return.py`, `GUARD_SHA256` in `cold-pci-restore-protocol.py`) are for cold-abort diagnostic modules and marker artifacts, not the t2bce family; those must be pinned to their specific binaries and are used only against a staged copy of that binary.

## What offline checks cannot prove

Every check here reads source text or runs a small C model of extracted functions with stubbed hardware. None runs the driver, the interrupt paths, the mailbox, DMA, the locking under real concurrency, USB re-enumeration, audio streams, the syscore wake in a real image restore, or the interaction with the cold PCI guard and restore initramfs. Matching srcversions prove source identity of the stock modules only. A clean W=1 build shows that the code compiles against the 7.2.7 headers; it does not show the patched core is correct. The earlier failures of replacement kernels and the record that ordinary boots do not establish S4 safety still apply: this candidate needs the full serialised requalification sequence, under the hardware rules in AGENTS.md, before any claim of hibernation support, and a private image must keep the production `.linux` and `.cmdline` byte-for-byte.

## Test results

- `verify-hibernation-candidate.py` end to end: PASS, 21 offline regression programs including the seven t2bce candidate tests, all reporting PASS.
- `test-preparation.py`: 9 tests OK (7 existing, 2 new for the pins file).
- `test/shell.d/t2-suspend-installer-unit.py`: 18 tests OK. `test/shell.d/t2-suspend-radio-gate-unit.py`: 52 tests OK (the two counts were swapped in an earlier revision of this line).
- `test/shell.d/t2-suspend-installer-test.sh`: the stale fixture was fixed after this rebase (the modinfo stub now resolves `t2bce_*` from the stock tree, and `error`/`warning` are defined), so the script runs to completion with 4 ok and 0 not ok, including a case that refuses a `t2bce_*` module resolved from `updates/dkms` and one for a missing `t2bce_vhci`. The earlier stop at "test did not reach module verification" was caused by radio 1.6's BCE coherence loop, not by this rebase.
- After patches 0016 and 0017: `test-mailbox-channel-pairing.py` and `test-command-queue-idle-timeout.py` PASS; `t2-suspend-installer-unit.py` 18 tests OK, `t2-suspend-radio-gate-unit.py` 52 OK, `test-preparation.py` 9 OK, `test-cold-s4-rebuild.py` PASS on the h1 tree.
