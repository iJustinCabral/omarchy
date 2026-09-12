# T2 hardware validation — September 10, 2026

This record consolidates the deployment and acceptance evidence for `fix-t2-vintage-mac-support`. The machine is MacBookAir9,1 with BCM4377b, running stock `7.2.4-arch1-Watanare-T2-1-t2`. Source integration and automated tests are on the branch; raw diagnostics and machine-specific experiment managers remain in the separate laboratory repository.

## Wi-Fi saved-off boot: passed

The corrected recovery helper passed an in-session reproduction and a real saved-off stock boot. During the latter, NetworkManager recorded saved-off startup, the user enabled Wi-Fi after more than a minute, and connectivity returned automatically in approximately 18 seconds using one recovery attempt. The user confirmed success.

| Seconds since boot | Journal event |
| --- | --- |
| 17.542 | Wi-Fi disabled by saved state and killswitch |
| 92.966 | Wi-Fi enabled |
| 95.443 | Recovery waits for enabled-state settlement |
| 103.481 | Recovery resets Wi-Fi |
| 110.761 | NetworkManager activates the connection |
| 111.072 | Watcher verifies the replacement interface is connected |

The underlying firmware stall still occurs. The tested workaround recovers it without another reboot. Waiting eight seconds before reset avoids the observed stale radio-state restoration race; it is not a formal persistence acknowledgement from systemd. Sleep/recovery lock hardware validation remains separate.

## Consolidated Bluetooth installation and boot: passed

The exact installer inputs from `a05953df` were verified against committed source. The retired MPC test package was removed through its own verified manager, including its test boot entry and Bluetooth override. Stock boot-file preservation and restoration of the original boot menu passed. Backups and ownership receipts were retained locally.

The consolidated installer then adopted the qualified Bluetooth setup. Installation, boot-image inspection, unit validation, and installed-file verification passed. No live module unload, radio toggle or Bluetooth restart was needed for that handoff.

On the subsequent user-operated stock boot, the gate had no override, exited successfully, and established the intended ordering:

| Seconds since boot | Journal event |
| --- | --- |
| 15.689 | Wi-Fi netdev and PHY ready |
| 16.556 | Explicit Bluetooth module load returned |
| 16.600 | BlueZ started |
| 16.742 | User sessions permitted |

The user reported “working perfect” after being asked to check the icon, Bluetooth off/on and AirPods reconnect/audio. These are user-reported functional results, not an independently measured audio stream. Wi-Fi was connected, Bluetooth and Wi-Fi recovery services were active, and zero system units failed at inspection.

## Automated checks

The consolidated branch passed the focused trackpad, T2 hardware, Broadcom supplicant, sleep, Wi-Fi recovery and Bluetooth suites. Bluetooth installation adds 17 transaction/model/image tests plus shell setup/migration routing and failure propagation tests. The original six Bluetooth gate fixtures remain. Wi-Fi recovery has 31 Python cases plus shell integration coverage. Bash/Python syntax, CLI metadata and systemd unit analysis passed. An earlier full CLI run passed with an unrelated sandbox theme-lock warning. This record does not claim a new full aggregate test run.

## Remaining work

- Resolve Wi-Fi D3 suspend failure without the withdrawn unload workaround, then verify Bluetooth audio across actual sleep.
- Fresh ISO installation of the automatic Bluetooth setup.
- Other T2 models and kernel releases before broadening automatic eligibility.
- Hibernation boot-loop investigation, which is not resolved by these radio fixes.

The trackpad fix remains. The Wi-Fi unload sleep workaround was withdrawn on September 11 after Bluetooth failures; disabling it exposes the original Wi-Fi D3 suspend abort. No failed MPC policy, experimental kernel, or hibernation implementation was promoted as a verified fix.

## September 11 retirement of the Wi-Fi sleep workaround

The Wi-Fi unload helper, unit, installer leaf and enabling migration have been removed. A new migration disables only the exact unit written by the retired installer, preserves administrator changes, and defers while a sleep transaction is active. The separate Wi-Fi recovery and Bluetooth startup integrations remain.

Stock tests showed Bluetooth failure with Wi-Fi teardown; bypassing teardown exposed the original D3 suspend abort. An isolated Wi-Fi disconnect/reconnect retained audible AirPods playback. This supports withdrawing the teardown workaround, not claiming a replacement suspend fix.

Focused retirement migration, Wi-Fi recovery (31 Python cases plus shell integration), Bluetooth installer (17 cases plus integration), Bluetooth gate (6 cases), trackpad and T2 hardware tests passed after removal. Migration and installer syntax checks and git diff whitespace checks passed. No live sleep operation was run for this source change.
