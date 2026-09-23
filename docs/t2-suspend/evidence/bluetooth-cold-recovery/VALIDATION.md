> Historical laboratory snapshot at commit `68bf7e0`. Relative tool paths and earlier next-step/merge statements refer to the lab, not this Omarchy checkout. See `docs/t2-suspend/README.md` for current consolidated status and `packages/t2-suspend/README.md` for runnable source preparation.

# S3 recovery validation on MacBookAir9,1

Kernel7.2.4-arch1-Watanare-T2-1-t2; BT4DF58889A43B9AC7E9E3E8C;
Wi-Fi16D3C1E5CA6ACF4C3917E4C. No full-kernel rebuild for these tests.

| Cycle | ResumeDelay | Recovery result | Automatic reconnect |
| --- | --- | --- | --- |
| 1 | default2sec | FLR/RTI and Wi-Fi returned; AirPods later connected; user confirmed audible music | Failed initially |
| 2 | default2sec | FLR/RTI returned; user confirmed connection after case cycle | Failed with AirPods kept in ears |
| 3 | 5sec | FLR/RTI returned; Wi-Fi HTTPS204; AirPods connected and active stereo stream routed | **First successful automatic reconnect**, user confirmed |
| 4 (fresh boot) | 5sec | FLR/RTI returned; Wi-Fi HTTPS204; active AirPods stereo; user reports everything working | **Second successful automatic reconnect**; transient profile refusal before audio recovered |
| 5 | 5sec | FLR/RTI returned; Wi-Fi HTTPS204; AirPods stereo active; user reports perfect result | **Third successful automatic reconnect**; transient profile errors before audio recovered |
| 6 (longer sleep) | 5sec | 778.410sec actually asleep; Wi-Fi HTTPS204; active AirPods stereo; user reports success | **Fourth successful automatic reconnect**; strict15min duration not yet reached |
| 7 (Bluetooth initially off) | 5sec | 1307.789sec asleep; Bluetooth stayed off; manual enable rebuilt firmware/RTI; active AirPods stereo; Wi-Fi HTTPS204 | Off-state preservation and deferred recovery **PASS** |

## Cycle3 exact timing

Capture /var/log/stock-mailbox-_1ntj88y, same boot
1d491d47-b15e-49b7-b21e-fdae5e4259e8. Bluetooth monitor relative times:

| Event | Capture time | Since Controller Resumed |
| --- | --- | --- |
| Controller Resumed | 71.418076 | 0 |
| New Settings: Powered | 74.696942 | 3.278866sec |
| Host Create Connection to bonded AirPods | 77.071332 | 5.653256sec |
| Connect Complete: Success | 78.388288 | 6.970212sec |
| MGMT Device Connected, locally initiated | 78.407339 | 6.989263sec |

The connection attempt now occurs2.374390sec AFTER controller readiness.
The earlier2sec resume policy attempted connection before readiness and failed
with Network is down100. The5sec configured timer is not an exact deadline;
measured dispatch here was5.65sec. This cycle supports the timing diagnosis.

User reports automatic connection under instructions to keep AirPods in ears
and avoid case cycling, Connect or toggles. Read-only checks confirm existing
bond/trust, Connected=yes, default AirPods sink and active cliamp stereo outputs.
Wi-Fi interface-bound HTTPS returned204 in0.080628sec. Agent issued no connection
command, radio toggle, service restart or power transition during this cycle.

Inherited PTB opcode0xfd98 timeout still appears before successful initialization;
its ignored-error behavior is documented in RECONNECT_TIMING.md. This success
does not establish that all diagnostic warnings have been eliminated.

Capture completed successfully with cleanup_errors=[].

## Remaining gates before integration

- Initially-off Wi-Fi state preservation and later enable/connect behavior.
- Review isolated driver packaging and supported Omarchy integration; retain
  working trackpad/startup fixes and omit machine-specific capture/boot artifacts.

The user authorized merging into fix-t2-vintage-mac-support after validation.
No merge is performed yet. This evidence applies to this MacBookAir9,1 and S3;
other T2 models and disk-image hibernation remain unvalidated.

## Cycle4: repeat on fresh candidate boot

Boot fdca8881-c2a0-42ea-8af2-c403d9bebb71, capture
/var/log/stock-mailbox-vkmmjguu. User reports everything working after instructions
to keep AirPods in ears and avoid manual Connect/case cycling. Verified same bond,
Connected=yes, active cliamp stereo to AirPods, interface-bound Wi-Fi HTTPS204.

HCI relative timestamps: Controller Resumed82.416224, Powered83.759955,
Create Connection87.958691, Connect Complete Success88.218245, MGMT Device
Connected88.233487 (locally initiated). Readiness1.344sec; attempt5.542sec;
link success5.802sec after resume. No agent connection/reset/power command.

BlueZ logged an AVDTP Connection refused error before audio became ready;
raw trace contains L2CAP security-block and no-resources refusals. The later
active audio stream and user result demonstrate recovery, but do not erase
these intermediate errors. Monitor whether profile retries remain reliable.
The PTB0xfd98 timeout appears at boot, not in this captured resume sequence.
Capture finalization/cleanup status is recorded in BOOT_SESSION.md.

## Cycle5: third automatic reconnect pass

Same boot fdca8881-c2a0-42ea-8af2-c403d9bebb71. Capture
/var/log/stock-mailbox-bxmnlsuj. User reports perfect result following instructions
to keep AirPods in ears and avoid case/Connect/toggle intervention. Verified
Connected=yes, existing bond, active cliamp stereo to AirPods and Wi-Fi HTTPS204.

HCI relative times: Controller Resumed102.421876, Powered105.744336,
Create Connection108.307120, Connect Complete Success112.947406, MGMT Device
Connected112.962627 (locally initiated). Readiness3.322sec; attempt5.885sec;
link success10.526sec after resume. Inherited PTB0xfd98 timeout remains.
BlueZ logged transient A2DP I/O/session errors before its audio transport-ready
message and confirmed playback. Keep those errors visible during integration
review; functional recovery does not mean every diagnostic is clean.

Three successful automatic reconnect cycles now recorded with final config.
Longer sleep and initially-off radio cases remain untested.

Cycle5 capture completed with cleanup_errors=[].

## Cycle6: measured12min58sec sleep with automatic reconnect

Same boot fdca8881-c2a0-42ea-8af2-c403d9bebb71, capture
/var/log/stock-mailbox-eilolbs2. User reported returning after15minutes with all
working. Difference in CLOCK_BOOTTIME minus CLOCK_MONOTONIC across697 PCI samples
records778.410sec of actual sleep (12min58.410sec). Preserve both the user report
and measured duration; do not mark the >=15min gate met. Time preparing/entering
sleep is not counted as actual sleep by that measurement.

HCI times: Controller Resumed820.424261; Powered821.763559; host Create
Connection825.721532; Connect Complete Success829.629624; MGMT locally initiated
Device Connected829.647502. Link success9.205sec after resume. Read-only checks:
AirPods Connected=yes, bond preserved, active cliamp stereo to AirPods; Wi-Fi
HTTPS204. User confirms successful recovery without reporting intervention.

Capture finished with54/54 trace entries, no capture error, cleanup_errors=[],
btmon exit0. summarize-capture.py computes sleep duration from saved clocks.
This is a successful longer powered-on-radio sleep, but below the stated15min
minimum. Next combine an interval of at least20min with initially-off Bluetooth,
verify actual sleep>=900sec, Bluetooth remains off until user enables it, and
Wi-Fi traffic survives. Record that duration check used initially-off Bluetooth;
the longest powered-on Bluetooth case remains778.410sec unless separately tested.
Initially-off Wi-Fi and final integration review also remain. No merge yet.

## Cycle7: initially-off Bluetooth,21min48sec sleep, successful manual enable

Capture /var/log/stock-mailbox-rky4nwjk measured1307.789sec actually asleep;
54/54 trace entries,697 samples,no errors,cleanup_errors=[],btmon exit0.
After wake Bluetooth Powered=no/PowerState=off-blocked, Wi-Fi HTTPS204.
Only vendor-window restoration ran then; no automatic Bluetooth FLR while off.

User subsequently enabled Bluetooth under capture
/var/log/stock-mailbox-rhwd6zhd and reported audio working. Kernel records
Bluetooth FLR at1852.177064 and firmware/RTI ready1852.956059. Verified
Powered=yes, same AirPods bond, Connected=yes, active cliamp stereo to AirPods,
and Wi-Fi HTTPS204. No module unload or agent-triggered system transition.
The deferred recovery path and initial power-state preservation pass this test.
Enable capture cleanup is recorded in BOOT_SESSION.md when finalized.

The >=15min duration requirement is met with Bluetooth initially off. Longest
powered-on-radio sleep tested is778.410sec. Preserve this distinction in claims.
Final hardware case: Wi-Fi initially off, Bluetooth on. Passive rfkill sampling
will preserve pre/post-wake state while chat is offline. User will leave Wi-Fi
off briefly after wake, then enable and verify traffic/audio. No merge yet.

## Cycle8: initially-off Wi-Fi FAILED; no actual sleep

Boot fdca8881-c2a0-42ea-8af2-c403d9bebb71. Passive archive
/var/log/stock-mailbox-joxnhiab: 671 samples, 60/60 trace records,
no capture error, cleanup_errors=[], btmon exit0. Measured sleep0.000sec.
User reports slow entry, Wi-Fi returning after enable, AirPods appearing
connected without audible audio, and subsequent connection attempts failing.

Monotonic timeline (journal records can be delayed by suspended consoles;
use trace.txt for precise PM callback intervals):

- 2053.038: first sampled Wi-Fi soft block; Bluetooth remains unblocked.
  Wi-Fi flow-ring deletion already timed out at2053.016/2053.110.
- 2080.507: firmware query/MAC-address reset fails before PM entry.
- 2080.610: deep attempt. Wi-Fi sends D3 control message but no ACK arrives;
  returns -5. Bluetooth unwind has 0x0c01/0x0c1a HCI timeouts.
- 2087.987: systemd automatically attempts s2idle; Wi-Fi D3 fails again.
  No machine sleep; systemd-suspend.service exits failure.
- 2130.136: first sampled Wi-Fi unblock, still Bluetooth unblocked.
- 2140.568: installed omarchy-t2-wifi-recovery logs RESET_BEGIN after
  firmware command timeouts. Driver console dump reports TRAP4. Dump time
  is not proof of the exact firmware crash time.
- 2142.395: trace observes brcmf_pcie_reset_device. Source uses ChipCommon
  watchdog reset. Wi-Fi rfkill disappears2142.496 and returns2143.252.
- 2147.193: recovery service reports RECOVERED; live HTTPS204 verified.
- 2183.483 onward: Bluetooth 0x2005 command timeouts; AirPods disconnected,
  no Bluetooth audio sink. User did not hear audio during apparent reconnect.

All sampled Bluetooth vendor windows remain valid and unchanged (70=1810c000,
74=18011000,80=1800b000,84=19000000,88=00018000), including across Wi-Fi reset.
There is no new Bluetooth cold-recovery/FLR record. The candidate detects loss
in resume_noirq from changed vendor windows; neither that predicate nor callback
covers this observed failure. Merely checking/restoring these windows cannot
resolve this case. A causal link from Wi-Fi watchdog reset to later Bluetooth
failure remains a hypothesis: Bluetooth also timed out earlier during abort.

Merge gate FAILED. Earlier successful S3 cases remain valid but do not establish
initially-off Wi-Fi support. Next work: isolate Wi-Fi radio-off firmware stall
and evaluate Bluetooth abort/command-timeout recovery beyond vendor-window loss.
Do not blindly increase ResumeDelay, unload drivers, or repeat the power test.
No driver/config changes, radio resets, or power transitions were initiated by
the agent while inspecting this failure. Raw HCI/audio captures remain private.
