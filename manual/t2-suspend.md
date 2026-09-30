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

The trackpad fix, Wi-Fi recovery service and Bluetooth startup setup remain available independently. Support is currently scoped to the tested MacBookAir9,1 with BCM4377.

## Hibernation

Hibernation saves your session to disk and powers the laptop off completely, so nothing is drawn from the battery while it sits. On the tested MacBookAir9,1 it now works as an opt-in extra, separate from suspend: hibernating from the menu (_System > Hibernate_, or `omarchy system hibernate` in a terminal) powers off, and pressing the power button later brings back your session with your apps exactly as you left them. The menu entry appears only when swap and resume are configured. It is tested on one machine and one kernel at a time. Other T2 Macs are not supported for hibernation, and `omarchy setup t2-suspend` does not turn it on; it is enabled by hand on the tested laptop.

While hibernation is on, the laptop starts from a special hibernation-ready boot entry by default. The normal Omarchy entry is still in the boot menu if you ever need it: press a key during the short boot menu and choose _linux-t2_ under _Omarchy_.

### Updating with hibernation on

When you run _Update > Omarchy_ (`omarchy update`), Omarchy notices that hibernation is on and asks **"Pause T2 hibernation for this update?"** Hibernation has to pause while packages change, because a kernel or driver update can leave its saved setup unusable. Suspend keeps working while it is paused. Answer yes to continue. Answer no to cancel the update with nothing changed. If you run the update with `-y`, it stops rather than pausing on its own.

When the update finishes, Omarchy checks whether anything hibernation depends on changed:

- If nothing changed, it asks **"Turn hibernation back on?"** Say yes and you are done.
- If the kernel or drivers changed, hibernation stays off and Omarchy tells you it needs to be requalified for the new kernel. Suspend still works in the meantime. Requalification is an attended procedure for the machine's maintainer and is not automatic yet.

If the update stops with a message about an unfinished or unexpected hibernation state, do not delete anything; note the message and ask for help.

### Pausing or turning hibernation off

When you update, answer yes at the `omarchy update` prompt and Omarchy pauses hibernation for you. To pause hibernation without updating, or to turn it off, see the maintainer documentation in the repository, under `docs/t2-suspend`.

### If the lock screen does not accept input

If the lock screen does not accept input, switch to a text console with `Ctrl + Alt + F2`, log in, and run:

```bash
loginctl unlock-sessions
```

Then switch back to your desktop with `Ctrl + Alt + F1` (try `F2` or `F3` if that is not where your session lives). This is a workaround for an open issue that has been seen once and is not yet explained; it has not been tried on a real occurrence yet.
