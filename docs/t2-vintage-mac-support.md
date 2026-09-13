# T2 support: reviewer guide

This branch combines independently scoped fixes for internal trackpad classification, saved-off Wi-Fi recovery, Bluetooth startup and real S3 suspend with radio recovery. Start with the [fix index](../README.md). The most recent validation is a normal stock-kernel boot with the installed DKMS drivers, followed by a short real S3 cycle with working Bluetooth and audio.

## Review by component

| Component | Runtime implementation | Installation and ownership | Tests / evidence |
| --- | --- | --- | --- |
| Trackpad | [udev rule](../install/hardware/apple/99-omarchy-t2-touchpad.rules), internal-device fallback that defers to hwdb | [setup leaf](../install/hardware/apple/fix-t2-touchpad.sh) | [scope and precedence tests](../test/shell.d/t2-touchpad-test.sh) |
| Saved-off Wi-Fi | [watcher](../install/hardware/apple/t2-wifi-recovery.py), bounded firmware-stall recovery | [design and ownership](t2-wifi-recovery.md) | [tests](../test/shell.d/t2-wifi-recovery-test.sh), [earlier stock validation](t2-validation.md) |
| Bluetooth startup | [readiness gate](../install/hardware/apple/t2-bluetooth/gate.py), Wi-Fi readiness before Bluetooth and desktop startup | [transactional manager](../install/hardware/apple/t2-bluetooth/manage.py), [design](t2-bluetooth-installer.md) | [installer tests](../test/shell.d/t2-bluetooth-installer-test.sh), [gate tests](../test/shell.d/t2-bluetooth-qualified-test.sh) |
| S3 and radio resume | [ten ordered driver patches](../packages/t2-suspend/README.md), [protocol and recovery design](t2-suspend/README.md) | [DKMS installer, firmware inclusion and rollback](t2-suspend/INSTALLATION.md) | [installer tests](../test/shell.d/t2-suspend-installer-test.sh), [normal boot and S3 validation](t2-suspend/VALIDATION.md) |
| Old sleep workaround retirement | Removes Wi-Fi unload-around-sleep behavior implicated in Bluetooth failures | [guarded retirement migration](../migrations/1789075037.sh) | [retirement tests](../test/shell.d/t2-retire-sleep-test.sh) |

The [hardware dispatcher](../install/hardware/all.sh) establishes the T2 kernel and Apple firmware, then Bluetooth ordering, then the suspend driver installation. Setup commands and migrations share the component managers. Each manager retains its own configuration ownership and rollback; rolling back the suspend drivers does not remove the trackpad or Bluetooth startup fixes.

## Scope and validation

The suspend installer is gated to Apple MacBookAir9,1, detected T2 hardware and the validated BCM4377 Wi-Fi/Bluetooth PCI identities. Earlier fixes retain their own scopes; the branch name is not a claim that all vintage Macs share this hardware. Driver validation used Omarchy 4.0.3 and stock kernel `7.2.4-arch1-Watanare-T2-1-t2`.

Normal installed-driver boot and one short S3 cycle passed. Earlier isolated driver tests cover repeated reconnects, longer sleeps and radio-off cases; their evidence is distinguished from normal-image validation. A clean OS installation, overnight battery drain, other models and arbitrary future kernel versions have not been qualified. Hibernation/S4 remains unresolved.

The Wi-Fi function-reset fallback is included and enabled on the scoped model, but the latest successful Wi-Fi-off cycle did not execute it. An earlier unexpected reboot remains unexplained. This must remain visible when deciding the scope of an upstream PR; successful Bluetooth function reset is separate evidence.

## Distribution changes versus lab repairs

| Item | Distribution behavior |
| --- | --- |
| Missing Apple Wi-Fi firmware in early boot | Fixed in the shipped initcpio hook; the installer requires the board firmware in the generated image. Firmware comes from the existing Apple firmware package, not this repository. |
| URI hash failure during verification | Caused by a separate lab script rewriting a UKI with objcopy. The shipped installer uses an explicit output for inspection through lsinitcpio. No special bootloader workaround is required. |
| Temporary Bluetooth module override | Lab-only state removed on the test machine. The installer refuses conflicting overrides rather than overwriting them. |
| Test boot entries and `noresume` | Lab safeguards; not installed by this branch. |
| Kernels, firmware binaries and captures | Not shipped here. Driver source is hash-pinned, built locally against installed headers and managed through DKMS. |

## Preparing the eventual PR

Choose the actual vintage-Mac integration target before rebasing or squashing. The local comparison against the cached `upstream/quattro` ref isolates the T2 changes; comparing against the older `upstream/master` also includes unrelated Omarchy baseline changes. Neither comparison substitutes for checking the eventual target at submission time.

Present the components above as separate review units, with the automatic installer and Apple firmware packaging included alongside the driver series. Retain Linux GPL-2.0 patch licensing and the original authors' attribution, including Hector Martin/Asahi Linux. Do not describe the work as a hibernation fix or universal T2 support.

Current test entry points are linked above. Historical investigation artifacts under [suspend evidence](t2-suspend/evidence/README.md) and the [earlier support audit](t2-support-audit-history.md) explain decisions and failures; they are not installation instructions.
