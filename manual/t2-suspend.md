# Suspend on supported T2 Macs

On a supported MacBookAir9,1, fresh setup and normal Omarchy upgrade migrations install the suspend drivers automatically. Changes take effect at the next ordinary reboot. Setup preserves current Bluetooth connections and Wi-Fi power preferences while it works.

You can verify the installation or rerun setup:

```bash
omarchy setup t2-suspend --verify
omarchy setup t2-suspend
```

Driver builds are repeated automatically when the T2 kernel is updated. If setup reports an error, retain the output; a failed migration stays pending. Custom configurations may need review before setup can proceed.

To remove this driver installation and restore the previous configuration for the next boot:

```bash
omarchy setup t2-suspend --rollback
```

The trackpad fix, Wi-Fi recovery service and Bluetooth startup setup remain available independently. Support is currently scoped to the tested MacBookAir9,1 with BCM4377. Hibernation is separate from suspend and remains unresolved.
