# Wi-Fi recovery on T2 Macs

Some T2 Macs with BCM4377b Wi-Fi stop finding networks when Wi-Fi was off at boot and is enabled later. Automatic recovery detects the firmware timeout and reinitializes Wi-Fi so the saved network can reconnect. Recovery briefly interrupts Wi-Fi; it does not turn Bluetooth off or change your saved Wi-Fi preference.

On the tested MacBookAir9,1, enable it with:

```bash
omarchy setup t2-wifi-recovery
```

The recovery mechanism has restored this failure without rebooting during development. A saved-off stock boot passed on the tested MacBookAir9,1; see the [deployment record](../docs/t2-validation.md). It is a recovery workaround, not a confirmed repair of the firmware defect.

Other T2 models with the same BCM4377b chip can explicitly opt in for testing:

```bash
omarchy setup t2-wifi-recovery --allow-untested-model
```

BCM4364 and non-T2 machines are not supported. A model opt-in does not make other chips eligible.

To stop automatic recovery:

```bash
omarchy setup t2-wifi-recovery --disable
```

Recovery makes at most three attempts per boot, at least two minutes apart. If it still cannot connect, inspect its status and retain its logs when reporting the failure:

```bash
systemctl status omarchy-t2-wifi-recovery.service
journalctl -b -u omarchy-t2-wifi-recovery.service
```
