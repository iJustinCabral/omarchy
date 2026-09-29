# Wi-Fi hibernation isolation candidate

The MacBookAir9,1 Wi-Fi firmware and Linux message-buffer rings remain synchronized across ordinary D3 suspend, but hibernation rewinds the Linux ring and packet-ID state. A restore-time function-level reset was rejected after it caused an abrupt reboot. Leaving Wi-Fi bound is also incompatible with the restore-image DMA gate because the PCI function retains bus-master capability after its freeze callback.

This candidate removes the Wi-Fi transport from the hibernation image instead. A drop-in for `systemd-hibernate.service` runs the helper as a required `ExecStartPre`; a failed identity check, detach, or detach verification prevents `/usr/lib/systemd/systemd-sleep hibernate` from starting. `ExecStopPost` runs for a successful return and for failed service startup, and rebinds only when the root-owned marker proves that this helper detached the exact `0000:73:00.0` BCM4377 function. A function that was already unbound remains unbound.

The state marker is created before detach, uses exclusive and no-follow creation under a root-only runtime directory, and is removed only after the device is verified bound to `brcmfmac`. A stale marker blocks another hibernation attempt and remains available for cleanup. The helper never resets either BCM4377 function, never changes Bluetooth, and does not communicate with a user session.

`python3 packages/t2-suspend/tests/test-wifi-hibernate-isolation.py` exercises the helper against a synthetic sysfs tree. It covers unsupported hardware, an intentionally unbound device, a successful detach/rebind cycle, detach failure cleanup, bind failure retention, a wrong-driver refusal, a stale marker and a corrupt marker. No real PCI driver or power state is touched.

This is an offline experiment. It is not installed by package 1.5, does not authorize a hibernation test and does not qualify the BCE cold-S4 or shared-link restoration candidates.
