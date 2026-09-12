> Historical laboratory snapshot at commit `68bf7e0`. Relative tool paths and earlier next-step/merge statements refer to the lab, not this Omarchy checkout. See `docs/t2-suspend/README.md` for current consolidated status and `packages/t2-suspend/README.md` for runnable source preparation.

# Second S3 cycle: reconnect races controller initialization

2026-09-12, same boot1d491d47-b15e-49b7-b21e-fdae5e4259e8 and unchanged
BT4DF58889A43B9AC7E9E3E8C. User kept AirPods in ears throughout suspend/wake:
automatic reconnect failed again. User then explicitly cycled the case and
reported connection restored. This is a second transport-recovery observation,
not an automatic-reconnect pass.

Capture /var/log/stock-mailbox-wbpcq3oc completed with cleanup_errors=[]. It
includes bluetooth.btsnoop, bluetooth-monitor.txt and BlueZ journal in report.
Raw HCI capture includes audio payload and nearby device addresses; keep private.

## Measured sequence

Bluetooth monitor relative timestamps (same clock within this list):

| Time | Event |
| --- | --- |
| 100.411711 | MGMT Controller Resumed |
| 100.812827 | Core-generated Hardware Error initiating recovery |
| 100.812857 | New Settings without Powered |
| 101.593106 | HCI transport reopened |
| 101.593459 | PTB vendor command sent |
| 103.597039 | Read BD ADDR, after PTB timeout |
| 103.597911 | Address response success |
| 103.601384 | HCI Reset response success |
| 103.668683 | New Settings with Powered restored |

Readiness takes3.257sec after Controller Resumed. BlueZ journal separately
records reconnect failure Network is down100 at1555.001581, approximately2.13sec
after its Controller resume log at1552.868410. No HCI Create Connection command
was found after recovery in this capture; there are normal successful command
responses and advertising traffic. Reserved legacy advertising event types
(e.g.0x23) appear in actual HCI payload, not just a menu artifact.

## Source match and experiment

[BlueZ5.87 policy.c](https://raw.githubusercontent.com/bluez/bluez/5.87/plugins/policy.c)
defaults ResumeDelay to2sec and schedules the reconnect timer on adapter resume.
reconnect_timeout calls btd_device_connect_services; an immediate negative return
resets reconnect tracking and ends that attempt. This matches the observed early
Network-is-down failure. It supports a readiness race, but does not prove that
all later paging/reconnection issues are eliminated by delaying the attempt.

The installed /etc/bluetooth/main.conf documents [Policy] ResumeDelay. Its prior
value was commented, so the default2sec applied. Test change: ResumeDelay=5,
allowing margin beyond the measured3.257sec. This is a bounded configuration
experiment, not a general proof that a fixed delay handles all recovery times.
A readiness-driven retry remains a possible upstream improvement.

resume-delay.py prepare/ install/ rollback preserves all other config text,
checks exact before/after hashes, gates installation to the loaded candidate,
and backs up the original. Backup:
/var/backups/t2-bt-resume-delay-lstqi0lg/main.conf.
Root-readable rollback metadata: resume-delay-installed.json. Generated full
config and metadata are not committed. Setting is global/persistent while the
experiment is installed, including stock boots; remove it if rejected.

Bluetooth service restarted once to load the setting. Result=success/active,
new PID35272. No driver unload or power transition. Wi-Fi still HTTPS204.
AirPods disconnected during service restart and startup reconnect reported Host
is down; restore audible baseline before any new suspend. ResumeDelay applies
to resume reconnection, not to service-startup reconnection.

Rollback (review config hash first; helper refuses concurrent drift):

```sh
pkexec /usr/bin/python3 /home/jjc/Projects/MBA_9_1/hibernate_test/v2/stock-resume/bluetooth-cold-recovery/resume-delay.py rollback
pkexec /usr/bin/systemctl restart bluetooth.service
```

Next: user restores AirPods baseline, then capture one manual S3 with headphones
kept in ears. Verify reconnect starts AFTER Powered returns and audible audio
recovers without case cycling. If it fails, inspect HCI paging/authentication
status rather than increase delays blindly. No merge yet.
