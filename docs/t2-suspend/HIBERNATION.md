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

The Bluetooth HCI power-management notifier is the strongest T2-specific entry suspect currently identified. It handles `PM_HIBERNATION_PREPARE` by synchronously quiescing the controller, and the BCM4377 transport has already shown command timeouts after S3. This remains a hypothesis until the isolated `freezer` result is captured.

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

## MacBookAir9,1 staged results on September 19, 2026

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

The failed platform test started at monotonic time `922.370559`; the final durable kernel line was `PM: hibernation: hibernation entry` at `922.402052`. The next boot reported `PM: Image not found (code -22)`. This proves that no image was left behind, but not that execution stopped at the last durable line: device and filesystem logging was already being quiesced, and the display returning before input suggests a failure during rollback or resume is possible.

Boot `e180e61481f0417b847d7079470eec2b` then repeated the `platform` PM depth while skipping ACPI S4 preparation:

```bash
omarchy debug t2-hibernate test platform --bluetooth-off --disk-mode shutdown
```

That test returned successfully. The result isolates the failure to the ACPI S4 platform global path selected by `platform` disk mode, rather than device late/noirq freeze/thaw. The next stage kept the working shutdown-mode path and added non-boot CPU offlining:

```bash
omarchy debug t2-hibernate test processors --bluetooth-off --disk-mode shutdown
```

The processor test also returned successfully. The final test before writing an image adds syscore suspend/resume with interrupts disabled:

```bash
omarchy debug t2-hibernate test core --bluetooth-off --disk-mode shutdown
```

## Test sequence

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
