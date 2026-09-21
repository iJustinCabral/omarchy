# T2 hibernation investigation

Hibernation is not yet fixed or enabled by the T2 suspend driver package. The MacBookAir9,1 now passes snapshot creation, image writing, integrity-checked image readback, both device-quiesce phases, secondary-CPU disable, IRQ disable, all syscore callbacks, processor-state save, temporary page-table construction and restore-code relocation. The unresolved failure is confined to `restore_image()` or the restored execution it enters. This document records the boundary evidence, the restore problem predicted by the T2 driver architecture and the guarded tests used to distinguish them.

## Current MacBookAir9,1 failure boundary

Six one-shot boundary probes on the production kernel progressively completed main device quiesce, late/noirq device quiesce and platform preparation, balanced secondary-CPU disable, IRQ disable and all syscore suspend callbacks, processor-state save, temporary mapping construction, and restore-code relocation. The final source boot `9bb52121-0564-4366-adf2-0ff45d6d0899` emitted `mba-hibernate-post-relocate: temporary mappings and restore-code relocation complete; aborting before restore_image`, then returned through the kernel's failure cleanup. Every probe has a durable no-repeat guard and must not run again.

On x86-64, the next instruction path switches to the temporary CR3, flushes the TLB, copies every restore PBE page to its original physical address, switches to the saved image kernel's CR3 and jumps to its restore entry. There is no recoverable C boundary after `restore_image()` begins. The failure is therefore no longer attributed to image creation, readback, ordinary device callbacks or restore-code setup.

Source and live PCI evidence identify an unqualified DMA-quiesce candidate. Both T2 IOMMU groups use identity domains under `intel_iommu=on iommu=pt`; Intel's syscore suspend callback disables translation before `restore_image()`. The PCI hibernation `freeze_noirq` path saves configuration but does not generically clear bus mastering. On a healthy boot, the BCE and Bluetooth functions retain `PCI_COMMAND_MASTER`; BCE also keeps an extra enable reference to ANS function 0, and the unbound SEP function 2 has bus mastering enabled without any Linux driver callback. This permits T2 functions to remain capable of direct DMA while the restore assembly overwrites physical memory.

Experimental patch `packages/t2-suspend/experiments/0005-t2-block-shared-dma-before-restore.patch` gates the complete ANS/BCE/SEP/audio function set from BCE's noirq callback and gates Bluetooth after its firmware quiesce callback. Review against the exact upstream `v7.2.6` callback order showed that physically clearing sibling functions was insufficient because a PCI function processed before BCE could retain saved configuration with bus mastering enabled. The revised candidate saves all four functions again after clearing, verifies that they remain blocked throughout noirq recovery, latches an unexpected re-enable, and delays restoration of the prior mask until the ordinary BCE recovery handshake has succeeded. The image-restore path leaves the unbound SEP function blocked, while Bluetooth verifies bus-master restoration after its vendor windows are valid. Wi-Fi remains deliberately outside this candidate, so Wi-Fi unbinding is still required for any later diagnostic. The patch builds and passes an offline fault harness but is neither installed nor hardware-qualified, and it does not solve the separate cold-S4 reconstruction problem.

Hardware testing is paused. The operator reported that the warm reboot after each recent boundary probe produced an unresponsive machine and required a forced power-off plus manual production-entry selection. Runner status 0 proves only that the source kernel reached its controlled return and requested an orderly reboot; it does not prove recovery usability. No future transition may rely on automatic warm reboot, and no new hardware test is authorized until a separate cold-power recovery design is documented and explicitly accepted.

The earliest failed boot, recorded below for history, had only an entry marker and initially suggested a notifier or filesystem-sync failure. Later creation, readback and boundary probes supersede that localization. Bluetooth remains relevant as a DMA-capable PCI function, but both freezer variants returning showed that its HCI prepare notifier was not a deterministic entry blocker.

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

### Creation-only boundary

After the Wi-Fi-isolated reset, the logs could not distinguish snapshot creation from image restoration. The laboratory `snapshot-create` stage isolates that boundary using the kernel's [userspace snapshot interface](https://docs.kernel.org/power/userland-swsusp.html). Build `packages/t2-suspend/tools/snapshot-create.c` with `cc -O2 -Wall -Wextra -Werror` into a host-local executable and set `OMARCHY_T2_SNAPSHOT_HELPER` to its absolute path. The guarded command then supports `test snapshot-create --wifi-unbind --bluetooth-off`; it retains the model, confirmation, radio-isolation and cleanup guards.

The helper locks memory before opening `/dev/snapshot` read-only, freezes userspace, creates an image and checks the creation flag and image size. It closes the device to discard the image and thaw processes before printing a result. It does not read or save image data, allocate swap pages, request atomic restoration or power-off, or enable platform S4 support. Opening the device itself runs PM notifiers, so even this narrower test can hang or reset faulty hardware. Offline syscall fault tests verify order, exactly-once descriptor cleanup, and failures at each boundary; they cannot prove hardware safety. A pass qualifies snapshot creation only. BCE live module teardown was not attempted: the core command-queue freeing path does not establish a complete peer-DMA quiescence contract, so unloading it is not an assumed-safe workaround.

On boot `d7ef5050-6deb-4e41-88fb-bced2968e4fb`, checkpoint `ad44485f` passed `snapshot-create --wifi-unbind --bluetooth-off`. Unit `mba-hibernate-create-only` reported a 2,682,290,176-byte image created and discarded at September 20 11:42:27, then exited 0 after radio cleanup at 11:42:30. The boot ID was unchanged, Wi-Fi reconnected and Bluetooth was powered. BCE stateful freeze/thaw and VHCI suspend/resume returned status 0. This proves snapshot creation for this configuration without image writing, reading or atomic restore; it does not prove those later boundaries or establish the reset's precise cause. The test did not enable PM trace, unlike the preceding failed full image experiment, so that difference also remains unisolated.

The PM-trace difference was subsequently tested on production boot `e689dceb-5503-44cf-8245-4eee7173a52f`, checkpoint `cbca8c84`, after the separate BCE restore-abort experiment also reset without surviving callback evidence (see `packages/t2-suspend/experiments/README.md`). Unit `mba-hibernate-create-trace` ran `snapshot-create --wifi-unbind --bluetooth-off --pm-trace`, created and discarded 2,701,656,064 bytes at September 20 12:03:42, and exited 0 after cleanup at 12:03:46. Boot ID remained unchanged, Wi-Fi was connected, Bluetooth was powered, and PM trace returned to 0. Thus enabling trace did not prevent this creation-only run. This strengthens the distinction between creation and the later write/readback/restore path, but is not proof against intermittent creation failure or against other differences between the snapshot-device and sysfs interfaces. No failed full restore was repeated.

The next experiment used a separately built `7.2.6-arch2-mba-readback-t2` diagnostic kernel to stop after a successful hibernation-image readback, before device quiescence and memory replacement. Its build, staged module installation, exact-release DKMS radio build, extracted UKI provenance and isolated Limine entry passed the deployment gates recorded in `packages/t2-suspend/experiments/README.md`. The first one-shot boot reached only the read-only service preflight, where a missing project command path prevented hardware-test invocation; no hibernation transition occurred. The corrected runner exported the required environment and separated per-boot evidence from an atomic guard created only after preflight, immediately before the sole hardware attempt.

The corrected one-shot attempt on boot `eef0671c-2c5b-46ff-aa44-5a1c2cac2772` passed its intended boundary. It wrote and then read 2,716,000 KiB, emitted the diagnostic readback-complete marker, freed the rejected image, restarted tasks and exited hibernation. The apparent `Operation canceled` and command status 1 are the designed `-ECANCELED` stop; the marker-aware runner classified the attempt `readback-complete`, saved logs and rebooted orderly to production. This qualifies image writing, readback, decompression and integrity checks. It does not validate `hibernation_restore()`, atomic memory replacement, ACPI S4 or usable hibernation. The earlier resets are now localized after successful readback, beginning at the device-quiesce and atomic-restore path.

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
| Diagnostic readback stop with Wi-Fi unbound and Bluetooth off | Passed intended boundary | The kernel wrote and read 2,716,000 KiB, emitted the readback-complete marker before `hibernation_restore()`, unwound cleanly and rebooted orderly. This rules out image write/readback and localizes the unresolved reset to the later quiesce/atomic-restore path. |
| `devices --wifi-unbind --bluetooth-off --pm-trace --disk-mode shutdown`, package 1.5 audio callbacks | Passed | Audio suspended with status 0 before VHCI and BCE, BCE resumed statefully before VHCI, audio entered its stateful resume and completed the deferred path. The command returned, PM controls were restored, and internal input, T2 audio, Wi-Fi and Bluetooth remained available. No image was written or restored. |

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

The successful diagnostic readback later moved the failure boundary beyond image I/O and into `hibernation_restore()`. A source audit against the T2 platform research found that `t2bce_audio` owns coherent DMA buffers and BCE queues but registers only ordinary suspend/resume callbacks. The BCE client prepare hook revokes bridgeOS remote access during hibernation, yet the audio PCI function is not disabled during `.freeze` and its matching resume path is not called for `.thaw` or `.restore`. Patch `0002-t2bce-audio-pair-hibernation-callbacks.patch` maps those in-place image callbacks to the existing stateful audio paths while deliberately leaving cold-S4 `.poweroff` unset. Package 1.5 adds the patched audio module to the verified DKMS set without loading it early from the initramfs. Pinned source preparation, callback invariants, a full seven-module build, transactional installation and ordinary boot all passed on `7.2.6-arch2-Watanare-T2-2-t2`.

Boot `191306cf-2dc6-4ba5-b6b8-568a7167b179` loaded package 1.5 audio source version `151173D6F9EEF5E4612915D` and ran the guarded `devices --wifi-unbind --bluetooth-off --pm-trace --disk-mode shutdown` boundary at checkpoint `329fe224`. The journal records `t2bce_audio` suspend status 0, VHCI suspend status 0, BCE stateful suspend status 0, BCE stateful resume status 0, VHCI resume status 0, audio stateful resume and `resume deferred path complete`. The service returned successfully in 11.920 seconds. PM test, disk mode and trace were restored; Wi-Fi reconnected, Bluetooth was powered, the Apple T2 ALSA card and PipeWire sinks remained present, and internal keyboard devices remained enumerated. The transition contained no pending-submission, queue-timeout, dead-controller, `usb_dev_restore`, invalid-packet-ID or audio-resume failure markers. This validates the changed device freeze/thaw path but not image restoration.

The subsequent single guarded package 1.5 image-restore attempt on the same boot did not return. The command detached Wi-Fi, powered down Bluetooth, enabled PM trace and logged `starting stage=test-resume` at monotonic time `649.713124`; the kernel logged `PM: hibernation: hibernation entry` at `649.725031`, after which the boot ended without a return marker, callback tail, panic record or orderly shutdown. Production boot `54880aff-262e-4fcb-8665-abbc773df03e` returned on the primary root with all four expected 1.5 module source versions and both radios operational. It reported RTC magic `6:394:105` and `PM: Image not found (code -22)`, but no file or device hash matched and `/sys/power/pm_trace_dev_match` was empty. No pstore record exists. This establishes that the audio callback pairing is not sufficient to make image restoration viable; never repeat this package 1.5 vector unchanged.

The next distinct localization boundary is an opt-in diagnostic kernel that completes image readback and the second `dpm_suspend_start(PMSG_QUIESCE)` pass, then deliberately unwinds with `PMSG_RECOVER` before `resume_target_kernel()` can disable CPUs, suspend syscore devices or replace memory. A successful return would move the failure boundary past ordinary device quiesce; a reset would localize it within that pass. This is a rejected diagnostic transition, not successful hibernation, and it must use a separate one-shot image with an atomic no-repeat guard.

The second forced restart lost the callback tail because device and console logging had already been quiesced. The guarded command therefore supports the kernel's [RTC-backed PM trace](https://github.com/torvalds/linux/blob/master/Documentation/power/s2ram.rst#using-trace_resume) for the next diagnostic attempt:

```bash
omarchy debug t2-hibernate test test-resume --bluetooth-off --pm-trace
```

PM trace writes a device hash into the hardware clock so the next boot can report the last callback through `omarchy debug t2-hibernate check`. It can temporarily disturb the clock and must only be enabled explicitly. Reboot promptly after a hang so the RTC signature remains useful.

## Test sequence

### Wi-Fi image isolation qualification

On boot `25f6b949-99b3-4d7b-9073-bc7c5a56cee4`, checkpoint `27208506` ran `freezer --wifi-unbind --bluetooth-off` through the durable local unit `mba-hibernate-wifi-freezer.service`. The September 20 11:20:20–11:20:27 journal records Wi-Fi unbinding, freezer entry/return, and successful rebinding with service exit 0. Firmware initialization completed at 11:20:28 and NetworkManager reconnected Wi-Fi automatically. This validates the basic detach/reprobe lifecycle without an image or device suspend. Firmware logged a P2P-interface creation error (`-52`), despite the normal station connection returning; do not interpret this result as validation of every Wi-Fi mode. Deeper isolation tests remain pending.

Post-test inspection found Bluetooth `Powered: no` and a BlueZ `Failed to set mode` message, despite service exit 0. The old cleanup swallowed Bluetooth power-on errors. A subsequent ordinary `bluetoothctl power on` succeeded and `Powered: yes` was verified; no reset or reboot was needed. Cleanup now attempts Wi-Fi rebinding before Bluetooth power restoration, verifies the powered state, and propagates failure. The off-state wait also requires an explicit `Powered: no`, rather than treating a missing controller as off. Fault tests cover cleanup failure. The reordered cleanup still requires hardware qualification; the original freezer result is not an all-devices restoration pass.

The reordered cleanup at checkpoint `ca3e937d` returned from freezer at 11:24:14 but correctly reported Bluetooth restoration failure at 11:24:16. A later normal power-on again succeeded without resetting hardware. Cleanup now allows at most three power-on attempts, separated by one second after failure, records each failed attempt, and requires a verified powered state. Offline tests cover both transient recovery and persistent failure. This handles the observed recovery behavior without claiming its underlying timing cause is known.

Checkpoint `3f38b113` passed all five non-image stages with `--wifi-unbind --bluetooth-off` on the same boot: freezer returned at 11:27:45, devices at 11:28:12, platform at 11:28:56, processors at 11:29:30, and core at 11:30:15. Platform/processors/core used `--disk-mode shutdown`, preserving the exclusion of the previously failing ACPI S4 preparation. Each durable service exited 0 after cleanup; each initial Bluetooth power-on failed but the bounded retry restored `Powered: yes`. Wi-Fi reconnected after each test, and CPUs `0-3` remained online. BCE stateful suspend/resume and VHCI callbacks returned status 0, with no matching queue-timeout, pending-submission, dead-controller, `usb_dev_restore`, or invalid-packet errors in this interval. These results qualify the isolated non-image path, not actual input events or image restoration.

The next distinct experiment was `test-resume --wifi-unbind --bluetooth-off --pm-trace`, under the durable unit `mba-hibernate-wifi-image`. It removed Wi-Fi from the image before freezing and kept the corrected BCE handshake; it did not invoke the rejected restore-time FLR or enter ACPI S4.

This experiment failed with a reset. The source boot `25f6b949-99b3-4d7b-9073-bc7c5a56cee4` records verified Wi-Fi detachment at September 20 11:31:53 and the test start, but no return marker or callback tail. The automatically returned boot `d7ef5050-6deb-4e41-88fb-bced2968e4fb` loaded the normal primary root and unchanged checkpoint `06d5da71`, Wi-Fi `1D85357EB5E65B246EDEE20`, and BCE `2394814A96D483B58C48501`. The previous boot ended without an orderly service exit. No pstore record existed in either `/sys/fs/pstore` or `/var/lib/systemd/pstore`; the kernel's EFI pstore backend is disabled by default, so that absence cannot rule out a kernel panic.

The new result weakens the earlier attribution of the reset to Wi-Fi restore-time FLR: that implementation was absent, and Wi-Fi was unbound. The BCE hibernation callbacks were introduced before the first reset-producing image test and remain an unisolated change, but this is a lead, not proof that BCE caused the reset. The last surviving userspace log does not locate the failure within image creation or restoration. Do not repeat this exact test unchanged or restore the rejected Wi-Fi FLR patch.

The returned boot printed RTC magic `6:883:393` without a file/device match, and `/sys/power/pm_trace_dev_match` was empty. Its early RTC read was `1970-01-01 19:23:55`, making the trace unqualified evidence rather than a usable callback identification. Wall-clock timestamps across this transition are unreliable. Further work must distinguish image-restoration state from ordinary freeze/thaw and obtain reliable failure localization before another image test. All five non-image passes remain valid only for their tested boundaries.

### Recovery boot after package 1.4 installation

The continuity reboot from checkpoint `9ee92a79` reached a Limine EFI hash mismatch on the normal entry. The operator selected snapshot 1; the resulting root was a temporary overlay and loaded older drivers, so this was not a successful 1.4 boot. The primary root's receipt still reported 1.4 installed, and extraction of the normal UKI confirmed Wi-Fi source version `1D85357EB5E65B246EDEE20`.

The host-local verification command had used `objcopy --dump-section` on the live UKI without an explicit output file. Repeating that invocation on a private copy changed its BLAKE2 hash, demonstrating that the supposed read-only verification could rewrite the boot image. The bootstrap now supplies a separate output destination. The normal menu entry's hash was repaired after image inspection; both normal and snapshot EFI hashes then matched their files. Automatic reboot is blocked from snapshot-overlay sessions. A successful normal boot and autonomous continuation remain unvalidated; this recovery did not exercise hibernation.

Normal boot `d192588b-31a0-44b6-a694-c689083c0aff` subsequently reached the primary `@` root on kernel `7.2.6-arch2-Watanare-T2-2-t2`. Loaded Wi-Fi source version `1D85357EB5E65B246EDEE20`, BCE `2394814A96D483B58C48501`, and Bluetooth `4DF58889A43B9AC7E9E3E8C` match the 1.4 module set. Wi-Fi was connected, NetworkManager/SDDM/Bluetooth were active, no migration remained pending, and both the embedded-key argument and hibernation resume target/offset survived. UWSM launched the named Foot window and its Codex child with the `mba-autonomous` profile, configured for `gpt-6-astra` and medium reasoning. The active goal resumed work. This validates normal boot and session relaunch after the menu repair; the initial unattended transition required operator snapshot recovery and is not an end-to-end unattended success. Hibernation remains unvalidated.

### Validated unattended reboot continuity

The next controlled cycle returned automatically from boot `d192588b-31a0-44b6-a694-c689083c0aff` to `25f6b949-99b3-4d7b-9073-bc7c5a56cee4` at unchanged checkpoint `c24fbcdf57cc306f3b48e2def91b391f5c130a91`. The source-boot journal records the delayed reboot service at 11:13:05 on September 20, 2026; the returned journal records SDDM autologin at 11:13:16 and UWSM launching the named Foot/Codex window at 11:13:21. The launcher consumed its continuation marker and resumed the exact pinned thread with the reconciliation prompt. The resumed turn metadata confirms `gpt-6-astra` and medium reasoning. No snapshot recovery or manual client launch was required for this cycle.

The primary `@` root, kernel, all three module source versions listed above, and the hibernation resume target/offset were unchanged. NetworkManager, SDDM and Bluetooth were active, Wi-Fi was connected, Bluetooth was powered, and no delayed reboot unit remained active. The read-only hibernation check reported PM test `none`, PM trace `0`, and live resume target `253:0` at offset `1923214`. The diagnostic regression suite and installer/source-preparation tests passed after the return, including rejection of the known-bad 1.3 Wi-Fi module and cleanup after a failed transition. No hardware hibernation test was repeated.

The host-local entry point is `~/.local/bin/codex-mba-reboot`: it requires a clean, remotely checkpointed branch, rejects snapshot recovery and conflicting operations, writes `~/.local/state/codex-mba-autonomous/handoff.json`, arms continuation, and schedules one delayed reboot. A plain reboot relaunches the pinned thread but does not supply a new continuation prompt. The launcher uses the host-local `mba-autonomous` profile rather than changing the global model. These host files and authentication material are not distributed as part of Omarchy. SSH was not enabled because this host has no configured recovery key; this workflow proves local automatic continuation, not remote rescue or recovery from a broken boot image. The operator accepted the embedded LUKS-key confidentiality tradeoff during setup; the original recovery passphrase remains available. Unlike the reference-machine runbook, this setup retains hibernation configuration and EFI hash verification.

Reboot continuity, the 1.4 safety rollback, the image-readback boundary, package 1.5 installation/boot and its changed audio device-freeze path are verified. The package 1.5 in-place image restore reset and must not be repeated. The next distinct boundary is the guarded quiesce-only diagnostic described above. Cold BCE reconstruction remains a separate S4 requirement. Do not repeat any earlier image-restore test with an unchanged kernel and module set.

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

Experiment `0006-t2bce-rebuild-queues-for-hibernation.patch` implements an offline version of the transport reconstruction part after the shared-DMA gate from experiment 0005. Its hibernation freeze path removes VHCI, sends `SLEEP_NO_STATE`, discards the VHCI, audio and BCE command queues locally, and therefore records a transport-absent snapshot. Thaw and restore perform a firmware handshake and rebuild core queues before client queues; VHCI adds the HCD and audio reconnects only after that graph exists. The real-S4 restore callback may treat a failed `RESTORE_NO_STATE` command as a new firmware epoch, while ordinary resume and hibernation unwind remain fail-closed. Any loaded BCE client without queue-reconstruction callbacks rejects the transition before queue destruction.

The patch and its compiled harness are source-level evidence only. Validation uses the post-0005 source with the pinned package-1.5 audio hibernation callbacks and explicitly rejects a source tree missing those mappings. All three affected modules build against the production kernel, but none has been installed or loaded. It does not yet solve the platform-wide DART reload, ANS cold-restore, or SEP hibernation-boot contracts. Hardware transitions are paused because the prior diagnostic boots were unusable and required a cold power-off plus manual selection of the production image. Do not produce or boot another diagnostic image from this candidate without a separately reviewed cold-power recovery design and explicit operator approval.

The public [t2linux hibernation report](https://github.com/t2linux/kernel/issues/22) reaches image creation and then fails in stateful VHCI restore, which is consistent with this second problem. It is useful cross-model evidence, but it does not replace the MacBookAir9,1 entry-stage result.

The staged procedure follows the kernel's [power-management debugging guidance](https://docs.kernel.org/power/basic-pm-debugging.html). A real S4 attempt should not be repeated until the earlier stages and `test-resume` pass.
