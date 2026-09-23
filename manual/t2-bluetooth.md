# T2 Bluetooth startup

On supported MacBookAir9,1 systems, Omarchy loads Bluetooth after the Wi-Fi device initializes and before desktop login. Wi-Fi may remain turned off. This addresses Bluetooth startup failures and the missing Bluetooth icon caused by the adapter arriving too late.

Fresh installation and upgrades set this up automatically on supported hardware. You can also run:

```bash
omarchy setup t2-bluetooth
```

Changes apply on your next reboot. Setup does not interrupt a current Bluetooth connection or reboot for you. If setup reports conflicting local configuration or an unsupported boot image, resolve that reported conflict before retrying; your configuration is preserved.

Verify the installed files or restore the previous startup arrangement with:

```bash
omarchy setup t2-bluetooth --verify
omarchy setup t2-bluetooth --rollback
```

Rollback also applies on the next boot. Support on other T2 models and hibernation are separate work.
