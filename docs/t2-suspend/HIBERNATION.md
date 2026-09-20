# T2 hibernation investigation

Hibernation is not yet fixed or enabled by the T2 suspend driver package. This document separates the observed MacBookAir9,1 entry failure from the later restore problem predicted by the T2 driver architecture, and provides a guarded way to test each kernel power-management boundary.

## Current MacBookAir9,1 failure boundary

The failed hibernation boot ended after these events:

1. systemd successfully froze `user.slice`.
2. `systemd-sleep` requested `hibernate`.
3. The kernel logged `PM: hibernation: hibernation entry`.
4. The kernel never logged `Filesystems sync` or image allocation.
5. The next boot reported `PM: Image not found (code -22)`.

The resume device, Btrfs swap-file offset and initramfs `resume` hook were present. The surviving evidence therefore places this failure before image creation, in console preparation, a hibernation prepare notifier, or the initial filesystem-sync boundary. It does not implicate image restoration yet.

The Bluetooth HCI power-management notifier was an early T2-specific suspect because it handles `PM_HIBERNATION_PREPARE` by synchronously quiescing the controller, and the BCM4377 transport has shown command timeouts after S3. Both `freezer` variants returned, however, so an active HCI controller is not a deterministic cause of the entry failure.

## Guarded diagnostic command

Inspect the active configuration without changing it:

```bash
omarchy debug t2-hibernate check
```

The first live test should be:

```bash
omarchy debug t2-hibernate test freezer --bluetooth-off
```

The command explains the risk and asks for confirmation. It temporarily powers Bluetooth down without setting a persistent rfkill block, selects the kernel PM test level, writes `disk` to `/sys/power/state`, and restores the prior PM mode and Bluetooth power if the kernel returns. A hard reset also clears these sysfs-only selections, while BlueZ restores its normal boot policy.

Even the `freezer` test can hang when the fault occurs in an early notifier. Save work before running it. The command never runs automatically during setup, update or boot.

`--disk-mode shutdown` temporarily changes `/sys/power/disk` while retaining the requested PM test depth. At the `platform` level this still exercises device late/noirq callbacks, but skips the ACPI S4 global preparation used by `platform` disk mode. The original mode is restored when the test returns.

`--wifi-unbind` isolates Wi-Fi transport state by detaching the single bound BCM4377 PCI function before entering the kernel test and rebinding it after return, including a rejected transition. It refuses ambiguous or unsupported PCI targets and verifies that the binding disappeared before entering PM. Rebind failure is reported as failure rather than a successful test. Network access is interrupted, so run from a local terminal or a durable local job, not a network-dependent command chain. A hard reset uses the normal boot probe; no persistent driver blacklist is created. This is a diagnostic, not a validated hibernation workaround: the current `.restore` queue rewind is removed from the experiment, while the BCE image-restore path remains under test. First validate the detach/rebind lifecycle at `freezer` depth; only advance to image restoration after networking and input are verified. The known-bad 1.3 module rejection remains active even with this option.

## MacBookAir9,1 staged results on September 19–20, 2026

Boot `087573321047465480d6a9884483235c` produced the first controlled boundary:

| Test | Result | Evidence |
| --- | --- | --- |
| `freezer --bluetooth-off` | Passed | Filesystem sync, both freezer phases, task restart and hibernation exit completed |
| `freezer` | Passed | Same boundary completed with Bluetooth powered |
| `devices --bluetooth-off` | Passed | BCE VHCI suspend/resume returned status 0; five queues resumed with pending submissions |
| `devices` | Passed with recovered fault | HCI opcode `0x0c01` timed out during resume; the controller was operational afterward |
| `platform --bluetooth-off` with `platform` disk mode | Failed | Display returned but the session remained unresponsive and required a forced restart; no return marker or image survived |
| `platform --bluetooth-off --disk-mode shutdown` | Passed | Device late/noirq callbacks, EC interrupt block/unblock, BCE VHCI resume and task restart completed; Wi-Fi and Bluetooth remained operational |
| `processors --bluetooth-off --disk-mode shutdown` | Passed | CPUs 1–3 went offline and returned; all four CPUs, BCE VHCI, Wi-Fi and Bluetooth were operational afterward |
| `core --bluetooth-off --disk-mode shutdown` | Passed | Snapshot memory was allocated, syscore suspend/resume returned, CPUs 1–3 were restored, and BCE VHCI, Wi-Fi and Bluetooth remained operational |
| `test-resume --bluetooth-off`, stock hibernation callback set | Failed after image reload | The image was written and loaded completely; the second device-freeze pass failed when `brcmfmac` attempted a D3 mailbox send while its bus was already down |
| `test-resume --bluetooth-off`, complete `brcmfmac` callback set | Failed after two display cycles | The display blanked and returned for image creation, then blanked and returned again for image restoration; the visible session was unresponsive and required a forced restart. Wi-Fi appeared restored in the panel and Bluetooth remained intentionally off. Only hibernation entry and the start marker were durable. |
| `test-resume --bluetooth-off --pm-trace`, complete `brcmfmac` callback set | Kernel returned; BCE VHCI and Wi-Fi failed restoration | The kernel exited hibernation and the command emitted its return marker. BCE VHCI resumed with stale pending submissions, every queue-control command timed out, the USB host controller died and `usb_dev_restore` returned `-110`. The lock screen ran, but the internal keyboard and trackpad were unusable. Wi-Fi also entered a packet-ID/ring desynchronization and remained unusable until reboot. |
| `devices --bluetooth-off`, complete `brcmfmac` callbacks and BCE freeze/thaw/restore callbacks | Passed | The BCE VHCI child suspended before the BCE parent, the parent completed its stateful suspend/resume handshake, and the parent resumed before VHCI. All callbacks returned status 0; internal input, Wi-Fi and the desktop remained operational. |
| `test-resume --bluetooth-off --pm-trace`, BCE callbacks and restore-time Wi-Fi function-0 FLR | Failed with an abrupt reboot | The guarded command logged its start marker and the kernel logged hibernation entry, but neither a return marker nor a later callback survived. The next boot reported an RTC PM-trace magic number without a device hash match and `Image not found (code -22)`. The prior boot was recorded as a crash and no pstore report was available in the collected evidence. |

The failed platform test started at monotonic time `922.370559`; the final durable kernel line was `PM: hibernation: hibernation entry` at `922.402052`. The next boot reported `PM: Image not found (code -22)`. This proves that no image was left behind, but not that execution stopped at the last durable line: device and filesystem logging was already being quiesced, and the display returning before input suggests a failure during rollback or resume is possible.

Boot `e180e61481f0417b847d7079470eec2b` then repeated the `platform` PM depth while skipping ACPI S4 preparation:

```bash
omarchy debug t2-hibernate test platform --bluetooth-off --disk-mode shutdown
```

That test returned successfully. The result isolates the failure to the ACPI S4 platform global path selected by `platform` disk mode, rather than device late/noirq freeze/thaw. The next stage kept the working shutdown-mode path and added non-boot CPU offlining:

```bash
omarchy debug t2-hibernate test processors --bluetooth-off --disk-mode shutdown
```

The processor test also returned successfully. The final test before writing an image added syscore suspend/resume with interrupts disabled:

```bash
omarchy debug t2-hibernate test core --bluetooth-off --disk-mode shutdown
```

The core test returned successfully. It allocated approximately 3.0 GiB of snapshot memory, passed the syscore boundary, restored CPUs 1–3, resumed BCE VHCI with the same five pending-submission warnings, and left all CPUs and both radios operational. The next stage was `test-resume`, which writes and immediately restores a real hibernation image without entering ACPI S4:

```bash
omarchy debug t2-hibernate test test-resume --bluetooth-off
```

The image path advanced much farther than the original hibernation attempt. The kernel wrote 2,563,692 KiB, found the image signature, read the entire image and reported `Image successfully loaded`. During the second device-freeze pass, `brcmfmac` found its bus down, failed `HOST_D3_INFORM` with `-EIO`, and caused the kernel to abort restoration and recover the running system. Wi-Fi then continuously failed to reserve common-ring space until the machine was rebooted.

The first attempt isolated its `test_resume` failure to Broadcom Wi-Fi PM state between the first thaw and the second freeze. The callback patch below addressed that boundary. It did not make the complete test return, so real hibernation remains blocked.

The matching Linux PCI PM implementation only invokes a driver's `.thaw` callback when that member is present; it does not substitute `.resume` when the driver supplies a PM operations table. The pinned `brcmfmac` source defines `.freeze` and `.restore`, but not `.thaw` or `.poweroff`. Patch `0006-brcmfmac-complete-hibernation-pm-callbacks.patch` pairs the existing D3 transition with freeze and poweroff, and the existing D0 transition with thaw and restore. Both pinned source profiles accept the patch, the callback invariant test passes, and all five modules compile against the current T2 kernel headers.

Boot `a0e3860f49b04ff39bed04100d493069` tested that rebuilt callback set. Unlike the first attempt, no `brcmfmac` bus-down, mailbox `-EIO`, or common-ring failure survived in the journal. The two display blank/return cycles and the visible Wi-Fi state were consistent with crossing the earlier Wi-Fi failure boundary, but did not prove that Wi-Fi traffic was functional.

Boot `3f2fb10db77847b3a4878e0f5a6919cf` repeated the test with PM trace enabled and preserved the complete callback tail. The image path returned to the running kernel and the command logged its return marker, but BCE VHCI immediately reported pending submissions on restored queues. Every endpoint resume command timed out, `t2bce_vhci` reported `HC died; cleaning up`, and `usb_dev_restore` failed with `-110`. The desktop progressed to a lock screen, confirming that the apparent system freeze was specifically the loss of the internal keyboard and trackpad carried by the BCE virtual USB controller. The user had to force a reboot because no internal input remained.

The same trace confirms the active `t2bce_core` lifecycle gap. Its PM table defines `.suspend` and `.resume`, but not the hibernation-specific `.freeze`, `.thaw`, `.poweroff`, or `.restore` callbacks. USB froze and restored the VHCI child, but the PCI PM core never invoked the parent BCE `SAVE_STATE_AND_SLEEP` and `RESTORE_STATE_AND_WAKE` handshake. Restoring the memory image therefore rewound Linux queue indices without restoring matching bridgeOS queue state. This is now an observed ordering failure rather than only a source-level hypothesis. A minimal freeze/thaw callback pairing can exercise the existing stateful handshake during `test_resume`; cold S4 still requires a distinct no-state reconstruction path.

Patch `0001-t2bce-run-stateful-handshake-for-image-restore.patch` adds `.freeze`, `.thaw` and `.restore` aliases to the existing stateful suspend/resume implementation. It deliberately leaves `.poweroff` unset because a cold S4 boot cannot reuse the stateful bridgeOS contract. The base source was extracted from the hash-pinned linux-t2 patch set used by the installed kernel; before modification, its executable module text matched the installed `t2bce_core` byte-for-byte.

Boot `20825168-b671-4969-bc5d-6b4963bf782b` loaded the resulting `t2bce_core` source version `2394814A96D483B58C48501` from DKMS package `omarchy-t2-radio/1.2`. Its September 20 `devices --bluetooth-off` test validated the intended parent/child ordering. BCE VHCI suspended first, then `t2bce_core` completed `SAVE_STATE_AND_SLEEP` with `stateful_valid=1`. On thaw, `t2bce_core` completed the stateful `RESTORE_STATE_AND_WAKE` path before BCE VHCI resumed. Every instrumented callback returned status 0, the guarded command emitted its return marker, and the user confirmed that internal input, Wi-Fi and the desktop remained operational. The journal contains none of the pending-submission warnings, queue-control timeouts, `HC died`, `usb_dev_restore` failures or Wi-Fi packet-ID errors seen in the prior image-restore attempt.

This pass validates the new BCE freeze/thaw boundary without writing or restoring an image. It does not yet validate `test-resume`: the known `brcmfmac` message-buffer rewind remains an independent blocker that should be addressed before another image-restore attempt.

Wi-Fi did not survive this traced run either. Immediately after image restoration, `brcmfmac` flooded invalid packet-ID errors, later timed out firmware commands and left the bus down. Pairing freeze/thaw fixed the earlier missing D0 transition but did not make its message-buffer rings safe across memory rewind. Wi-Fi restore remains a separate blocker after BCE ordering is corrected.

Patch `0003-brcmfmac-rebuild-transport-after-image-restore.patch` separated `.restore` from the ordinary `.resume` and `.thaw` paths. Thaw retained the stateful D0 notification needed to write the image. Restore selected the existing MacBookAir9,1-scoped function-0 FLR path to stop DMA and rebuild firmware, message-buffer rings and packet-ID tables; systems without that explicit opt-in retained the upstream hot-resume behavior. The patch and callback invariant passed, and the complete Wi-Fi module set built cleanly against the running T2 kernel.

Hardware validation of that restore-time FLR failed on DKMS package `omarchy-t2-radio/1.3`. Boot `86077aebaa564e98b77f09ad4a91382c` logged the test start at monotonic time `138.762812` and `PM: hibernation: hibernation entry` at `138.793062`, then ended without the guarded command's return marker or an orderly shutdown. Boot `8f5916e8027d417b90e0eb829c71d355` found RTC PM-trace magic `6:18:238`, but no device hash match, and reported `PM: Image not found (code -22)`. No pstore crash report was available in the collected evidence. The trace cannot prove which instruction triggered the reset because logging was quiesced, but the regression from the preceding image-restore run strongly implicates the newly introduced restore-time function-0 FLR. Do not repeat `test-resume` with this implementation; remove the FLR restore path before further hardware testing.

DKMS package `omarchy-t2-radio/1.4` removes that restore patch from the active series and the guarded diagnostic refuses `test-resume` when it detects the known-bad 1.3 Wi-Fi module still loaded. Installing 1.4 does not replace the running module; rebooting is required to leave the unsafe implementation. The retained stateful restore path is expected to reproduce the earlier Wi-Fi ring desynchronization, so this rollback is a safety correction rather than a hibernation fix.

The second forced restart lost the callback tail because device and console logging had already been quiesced. The guarded command therefore supports the kernel's [RTC-backed PM trace](https://github.com/torvalds/linux/blob/master/Documentation/power/s2ram.rst#using-trace_resume) for the next diagnostic attempt:

```bash
omarchy debug t2-hibernate test test-resume --bluetooth-off --pm-trace
```

PM trace writes a device hash into the hardware clock so the next boot can report the last callback through `omarchy debug t2-hibernate check`. It can temporarily disturb the clock and must only be enabled explicitly. Reboot promptly after a hang so the RTC signature remains useful.

## Test sequence

### Recovery boot after package 1.4 installation

The continuity reboot from checkpoint `9ee92a79` reached a Limine EFI hash mismatch on the normal entry. The operator selected snapshot 1; the resulting root was a temporary overlay and loaded older drivers, so this was not a successful 1.4 boot. The primary root's receipt still reported 1.4 installed, and extraction of the normal UKI confirmed Wi-Fi source version `1D85357EB5E65B246EDEE20`.

The host-local verification command had used `objcopy --dump-section` on the live UKI without an explicit output file. Repeating that invocation on a private copy changed its BLAKE2 hash, demonstrating that the supposed read-only verification could rewrite the boot image. The bootstrap now supplies a separate output destination. The normal menu entry's hash was repaired after image inspection; both normal and snapshot EFI hashes then matched their files. Automatic reboot is blocked from snapshot-overlay sessions. A successful normal boot and autonomous continuation remain unvalidated; this recovery did not exercise hibernation.

Normal boot `d192588b-31a0-44b6-a694-c689083c0aff` subsequently reached the primary `@` root on kernel `7.2.6-arch2-Watanare-T2-2-t2`. Loaded Wi-Fi source version `1D85357EB5E65B246EDEE20`, BCE `2394814A96D483B58C48501`, and Bluetooth `4DF58889A43B9AC7E9E3E8C` match the 1.4 module set. Wi-Fi was connected, NetworkManager/SDDM/Bluetooth were active, no migration remained pending, and both the embedded-key argument and hibernation resume target/offset survived. UWSM launched the named Foot window and its Codex child with the `mba-autonomous` profile, configured for `gpt-6-astra` and medium reasoning. The active goal resumed work. This validates normal boot and session relaunch after the menu repair; the initial unattended transition required operator snapshot recovery and is not an end-to-end unattended success. Hibernation remains unvalidated.

### Validated unattended reboot continuity

The next controlled cycle returned automatically from boot `d192588b-31a0-44b6-a694-c689083c0aff` to `25f6b949-99b3-4d7b-9073-bc7c5a56cee4` at unchanged checkpoint `c24fbcdf57cc306f3b48e2def91b391f5c130a91`. The source-boot journal records the delayed reboot service at 11:13:05 on September 20, 2026; the returned journal records SDDM autologin at 11:13:16 and UWSM launching the named Foot/Codex window at 11:13:21. The launcher consumed its continuation marker and resumed the exact pinned thread with the reconciliation prompt. The resumed turn metadata confirms `gpt-6-astra` and medium reasoning. No snapshot recovery or manual client launch was required for this cycle.

The primary `@` root, kernel, all three module source versions listed above, and the hibernation resume target/offset were unchanged. NetworkManager, SDDM and Bluetooth were active, Wi-Fi was connected, Bluetooth was powered, and no delayed reboot unit remained active. The read-only hibernation check reported PM test `none`, PM trace `0`, and live resume target `253:0` at offset `1923214`. The diagnostic regression suite and installer/source-preparation tests passed after the return, including rejection of the known-bad 1.3 Wi-Fi module and cleanup after a failed transition. No hardware hibernation test was repeated.

The host-local entry point is `~/.local/bin/codex-mba-reboot`: it requires a clean, remotely checkpointed branch, rejects snapshot recovery and conflicting operations, writes `~/.local/state/codex-mba-autonomous/handoff.json`, arms continuation, and schedules one delayed reboot. A plain reboot relaunches the pinned thread but does not supply a new continuation prompt. The launcher uses the host-local `mba-autonomous` profile rather than changing the global model. These host files and authentication material are not distributed as part of Omarchy. SSH was not enabled because this host has no configured recovery key; this workflow proves local automatic continuation, not remote rescue or recovery from a broken boot image. The operator accepted the embedded LUKS-key confidentiality tradeoff during setup; the original recovery passphrase remains available. Unlike the reference-machine runbook, this setup retains hibernation configuration and EFI hash verification.

Reboot continuity and the 1.4 safety rollback are verified. Hibernation remains blocked by the previously observed Wi-Fi message-buffer rewind; cold BCE reconstruction remains a separate S4 requirement. Do not treat the successful ordinary reboot as permission to repeat the known-failing image-restore test unchanged.

Advance only after the preceding stage returns successfully.

| Stage | Kernel boundary | ACPI S4 entered | Image written |
| --- | --- | --- | --- |
| `freezer` | Prepare notifiers and freeze processes | No | No |
| `devices` | Suspend devices | No | No |
| `platform` | Exercise platform preparation | No | No |
| `processors` | Disable non-boot CPUs | No | No |
| `core` | Exercise core/CPU and low-level platform path | No | No |
| `test-resume` | Write and immediately restore the image in the running boot | No | Yes |
| Real hibernation | Firmware power-off and cold restore | Yes | Yes |

For example, after `freezer` passes:

```bash
omarchy debug t2-hibernate test devices --bluetooth-off
```

`test-resume` is deliberately last because it allocates and restores a real image:

```bash
omarchy debug t2-hibernate test test-resume --bluetooth-off
```

The diagnostic emits `omarchy-t2-hibernate-test` journal markers immediately before the kernel transition and after a successful return. If a stage requires a forced restart, the missing return marker identifies the failed boundary.

After a forced restart, inspect the prior boot's markers and kernel tail with:

```bash
journalctl -b -1 -t omarchy-t2-hibernate-test --no-pager
journalctl -b -1 -k --no-pager | tail -100
```

## How to interpret the first result

| Result | Meaning | Next action |
| --- | --- | --- |
| `freezer --bluetooth-off` returns | The early kernel path can complete without an active HCI controller | Repeat `freezer` with Bluetooth powered normally to test the notifier hypothesis |
| Bluetooth-off returns but Bluetooth-on hangs | The HCI prepare path is isolated | Patch or bypass BCM4377 hibernation preparation, then repeat the staged sequence |
| Both freezer tests hang | Bluetooth is not sufficient to explain entry failure | Trace the remaining PM notifiers and console preparation before touching BCE restore |
| Both freezer tests return | The prior entry hang is later than the freezer boundary or intermittent | Continue with `devices`, then the remaining stages |
| `test-resume` fails | Image creation or in-kernel restoration is broken independently of ACPI S4 | Fix this before a real hibernation attempt |
| `test-resume` passes but real S4 fails | The cold firmware/device reconstruction path is broken | Implement the BCE S4 restore work described below |

## Separate BCE cold-restore problem

The [T2 platform research](https://github.com/macintog/t2-platform-research) makes an important distinction: ordinary S3 uses BCE `SAVE_STATE_AND_SLEEP` and `RESTORE_STATE_AND_WAKE`, while hibernation is a firmware cold-boot policy. The current Linux T2 BCE driver has suspend/resume callbacks but no explicit freeze, thaw, poweroff or restore callbacks. Generic PM fallback can therefore carry the in-memory `stateful_suspend_valid` flag across an S4 image even though bridgeOS cold boot discarded the matching device state.

The current no-state VHCI resume path reuses the existing command and event queues. It does not reconstruct the full BCE queue graph required after a firmware cold boot. A durable restore implementation will likely need all of the following:

1. Explicit BCE hibernation callbacks that distinguish freeze/thaw from poweroff/restore.
2. No use of the ordinary stateful S3 restore contract after S4.
3. Cold reconstruction of the BCE command and VHCI event queues, or a controlled full-function reprobe.
4. Coordination with ANS2, SEP, audio and DART because the T2 functions share one link and reset domain.

The public [t2linux hibernation report](https://github.com/t2linux/kernel/issues/22) reaches image creation and then fails in stateful VHCI restore, which is consistent with this second problem. It is useful cross-model evidence, but it does not replace the MacBookAir9,1 entry-stage result.

The staged procedure follows the kernel's [power-management debugging guidance](https://docs.kernel.org/power/basic-pm-debugging.html). A real S4 attempt should not be repeated until the earlier stages and `test-resume` pass.
