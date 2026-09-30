# T2 hibernation in plain language

This is the explanatory overview of the MacBookAir9,1 hibernation work: what was broken, what was changed, why the design looks the way it does, how it is kept safe, how `omarchy update` treats it and where it is going. It is written for Omarchy users, maintainers and t2linux contributors. The map of all documents is [README.md](README.md); hard evidence is in [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md) and the investigation journal (on branch `fix-t2-vintage-mac-support`: docs/t2-suspend/HIBERNATION.md, the lab journal); the existing guide (on branch `fix-t2-vintage-mac-support`: docs/t2-suspend/HIBERNATION-GUIDE.md) remains the evidence register and agent contract and mechanism (on branch `fix-t2-vintage-mac-support`: docs/t2-suspend/HIBERNATION-MECHANISM.md) remains the detailed failure chain. This overview replaces neither, and it does not authorise any hardware action.

Status as of 2026-09-30: hibernation is ACTIVE on linux-t2 7.2.7 (generation `f4025add13d1`) on the tested MacBookAir9,1 and has completed a routine normal-logind S4 cycle on that kernel. It is an opt-in, single-model product. Why this is a new file and not a rewrite of the guide: the guide's status text, reading map and agent contract are organised around the earlier prototype and are still useful as an evidence index, so they are kept and corrected, while this page gives a single readable narrative.

## The problem

S3 suspend keeps RAM powered. S4 hibernation writes RAM to disk, powers off, and on the next boot a second kernel reads the image and hands execution back to the saved kernel. The saved kernel therefore wakes up believing the hardware is exactly as it left it, but the T2 chip, which runs its own firmware and owns the keyboard, trackpad, audio, storage controller and Secure Enclave transport, went through a cold start. Three things break:

- **T2 BCE, VHCI and audio.** The BCE transport keeps command and event queues whose rings the firmware knows about. After a cold start the firmware knows nothing of the rings in the restored memory. Virtual USB (VHCI) then resumes with stale submissions and command timeouts, and the internal keyboard and trackpad, which sit behind it, are lost. The BCE parent also had ordinary suspend and resume callbacks but not the hibernation-image callbacks, and audio had the same gap.
- **Shared PCI link.** The T2 exposes storage (ANS), BCE, SEP and audio as four functions of one PCI slot. While the restore kernel is overwriting memory, a bus master that is still enabled can write into memory that is being replaced. The restore kernel has no BCE driver loaded, so nothing there closes that gate.
- **BCM4377 Wi-Fi and Bluetooth power management.** Wi-Fi lacked paired hibernation callbacks, and restored packet identifiers and rings desynchronised from the firmware. A function-level reset at restore time was tried and rejected: it caused an abrupt reboot. The Wi-Fi transport is instead detached before hibernation and rebound afterwards.

The long record of failed vectors and what each taught is in the journal (on branch `fix-t2-vintage-mac-support`: docs/t2-suspend/HIBERNATION.md, the lab journal); the causal story, with its limits, is in mechanism (on branch `fix-t2-vintage-mac-support`: docs/t2-suspend/HIBERNATION-MECHANISM.md). None of it isolates a single universal cause, and a successful return is evidence for the tested combination only.

## Why a private source and restore image pair

Two private boot images (UKIs) are staged next to the production image:

- The source image boots the normal desktop with the patched T2 driver stack in its initramfs. It is the session that gets saved.
- The restore image cold-boots, unlocks storage, loads the cold PCI guard, reads the saved image and transfers into the saved session. Per the builder design (`--minimal-restore-devices`; the pair's `provenance.json`), its initramfs deliberately leaves BCE and the radio drivers out, so no new peripheral queue graph is built before the older memory image is applied. On an ordinary boot without a pending image it behaves like a normal boot and loads the candidate drivers late.

Both keep the production `.linux` (kernel) and `.cmdline` sections byte-for-byte. Earlier attempts that replaced the kernel repeatedly failed to mount the physical encrypted root (`/dev/mapper/root`) even when offline and VM checks passed, so a replacement kernel is excluded from the design and the pair stager enforces that policy. Only the initramfs differs. The consequence is that every production kernel update changes `.linux`, so the pair must be retired and rebuilt from the new production image and requalified.

Why the stock image cannot hibernate today: it has the unpatched t2bce modules, and its initramfs has no cold PCI guard or restore-side resume handling, so the failures above apply to it. The patched modules exist only in the private images, which is what makes the product fragile across kernel updates and is the reason for the upstream goal below.

## The patch set

All hibernation patches are rebased on the t2linux t2bce commit `6780d522`, whose unpatched module srcversions equal the stock 7.2.7 modules (see [the rebase record](T2BCE-7.2.7-REBASE.md)). `patches/bce/0001` and `0002` are the two stateful-path patches from the earlier series; the numbered experiments are applied on top in order. Paths are under `packages/t2-suspend`.

| Patch | What it does |
| --- | --- |
| `patches/bce/0001` | Runs the stateful BCE handshake for hibernation images so the parent coordinates its children |
| `patches/bce/0002` | Pairs the audio driver's hibernation image callbacks |
| `experiments/0005` | Blocks PCI bus mastering on the shared link before the atomic image restore |
| `experiments/0006` | Drops and rebuilds the BCE command and client queue graph on the no-state hibernation path; the substantive patch |
| `experiments/0007` | Serialises PCI power management across the shared functions |
| `experiments/0008` | Not a kernel patch: a systemd drop-in and helper that detach the Wi-Fi transport before hibernation and rebind it after |
| `experiments/0009` | Lets the AVE client certify an idle state for the rebuild |
| `experiments/0010` | Blocks DMA before dropping the queue graph so the device cannot write into freed rings |
| `experiments/0011` | Wakes the no-state firmware early, before device noirq resume (syscore) |
| `experiments/0012` | Diagnostic EFI stage marker hooks that record the last completed S4 boundary |
| `experiments/0013` | Quarantines the VHCI command queue after a command timeout |
| `experiments/0014` | Residual after the rebase: refuses hibernation early if a client cannot rebuild |
| `experiments/0015` | Limits the DMA gate and early wake to hibernation phases so S3 on the source image is unaffected |
| `experiments/0016` | Makes the mailbox channel pause idempotent and refuses suspend after a skipped resume |
| `experiments/0017` | Bounds the command-queue idle wait on the suspend path |

Beside the kernel patches, the cold PCI guard (`experiments/hibernate-cold-pci-guard`) is an out-of-tree module in the restore initramfs that clears bus mastering on the four Apple functions before memory is replaced, and two EFI marker modules record source and restore stages. All helper modules are kernel-bound and must be rebuilt for each kernel; see [HELPERS-7.2.7.md](HELPERS-7.2.7.md).

## The safety model

The aim is that a failure always leaves a bootable stock system and never repeats a vector that already failed.

- **Qualification.** An image pair is usable for routine hibernation only after a chain of attended hardware results: an ordinary boot of each image, a source `test_resume`, a real cold-power S4 vector, then a one-use generation trial that reconciles, then a qualification bound to the trial's exact cycle record, then a first routine cycle. Offline checks, VM runs and ordinary boots never count as S4 proof.
- **Generations.** A generation is the coherent set (production kernel and UKI, module stack, manifest, config, firmware, control files, bootloader projection) that was qualified. It is identified by the first 12 hex digits of the manifest digest (`f4025add13d1` on 7.2.7). `assess` compares the live machine against the stored baseline and reports `unchanged`, `requalification-required` or `unknown`.
- **One-use vectors and guards.** Every hardware vector (test_resume, S4, generation trial) creates a durable guard before the power write. A failed, hung or ambiguous attempt is terminal for that vector and is preserved as evidence; a consumed guard is never edited, deleted or reused. The runtime ledger chains each routine cycle to the previous terminal cycle.
- **Update guard.** An ALPM hook refuses package transactions while hibernation is ACTIVE, or while an unfinished transition or an EFI override exists. It admits transactions in inactive maintenance when the saved-image and stock-fallback evidence is valid. It is part of the byte-pinned runtime and must not be removed or bypassed.
- **Maintenance, assess, reactivate.** `maintenance` proves no saved image, restores the stock boot default, removes the opt-in and retains a durable marker that vetoes both sleep routes. Packages can then update. `assess` (read-only) decides whether a qualified generation is unchanged. `reactivate` returns to ACTIVE only when it is. Anything changed or unknown stays off. See [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md).
- **Requalify and rebind.** After a kernel update the pair is retired and rebuilt, requalified through the attended gates, and `rebind` moves the maintenance marker onto the new generation and makes it ACTIVE. [REQUALIFICATION.md](REQUALIFICATION.md) is the procedure and [REBIND-DESIGN.md](REBIND-DESIGN.md) the rationale.
- **Fail-closed stuck states.** Interrupted transitions leave pendings that veto updates and sleep. Recovery is re-running the same reviewed action or following the runbook; nothing under the state directory is deleted by hand.

## What "hibernation on" means for boot

ACTIVE means three things together: the routine opt-in file `/etc/omarchy/t2-hibernate-product.enabled` exists, the boot policy is published, and `/boot/limine.conf` has exactly one line changed, `default_entry` now names the source entry (`MBA-T2-hibernation-source-<first 16 hex of the source image digest>`, `b70b77cd0b58dd1e` on 7.2.7) instead of `2`. The laptop then boots the production kernel and command line with the source initramfs by default. The stock `Omarchy.linux-t2` entry is still in the Limine menu (3 second timeout), so holding a key at boot and choosing it is the fallback, and a hung or failed pair boot recovers by a power cycle followed by choosing the stock entry. Pausing hibernation for an update puts `default_entry` back to the stock value. S3 on the stock entry is the known-good path; S3 on the source image on 7.2.7 has not been separately recorded in the evidence reviewed for this document.

## How `omarchy update` handles it

On a MacBookAir9,1 with the product installed, `omarchy update` runs `omarchy-update-t2-hibernation pre` before packages and `post` afterwards; elsewhere the helper exits silently.

- Before: if hibernation is on, it explains that hibernation must pause and asks. Yes runs the reviewed `maintenance` action. No cancels the update with nothing changed and prints the manual command. `-y` never pauses on its own and stops instead. An unreadable state (no sudo), a loader override or any unfinished transition also stops the update before anything changes and points at the runbook.
- After: while paused, it runs the read-only `assess`. If nothing qualified changed it offers to turn hibernation back on (`reactivate`). If the kernel or drivers changed it says hibernation stays off until requalified and that suspend still works. It never requalifies and never fails the update.

The integration landed in `7eaefa2a` and `8c2b0976`. It is covered by the shell tests (`test/shell.d/update-t2-hibernation-test.sh`). It has not yet been exercised by a real `omarchy update` on the laptop: the 7.2.6 to 7.2.7 update on 2026-09-29 was run by hand under maintenance before the hook existed, so the interactive prompts are unproven on hardware.

## Path to upstream

The real goal is that stock kernels hibernate on T2 Macs, without a private image pair and without per-kernel requalification. The private pair is a stopgap: every kernel update invalidates the qualified generation, which is what the requalification procedure exists to manage. Proposed, not started:

1. Split experiments 0005 to 0017 and the two `patches/bce` patches into reviewable series against t2linux `linux-t2-patches` (t2bce), following their contribution norms, with the evidence from [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md) per patch.
2. Decide which behaviour belongs in t2bce (queue rebuild, DMA gates, callbacks), which in brcmfmac and Bluetooth PM, and which in generic hibernate support (the restore-side bus-master gate currently lives in an out-of-tree module because the restore kernel has no BCE driver).
3. Retire diagnostic-only pieces (EFI stage markers, abort probes) from the series.
4. Re-run the attended campaign with upstream modules on a stock image. Only then can the stock image, and other T2 models with their own hardware qualification, be claimed.

Until then, other T2 models are unqualified and the guard explicitly matches the MacBookAir9,1.
