# T2 suspend driver source package

This package consolidates the driver changes tested on MacBookAir9,1, BCM4377,
Omarchy 4.0.3 and `7.2.4-arch1-Watanare-T2-1-t2`. It contains ten patches,
pinned source and patch hashes, source preparation, and extracted-C fault tests.
It is source integration: Omarchy's installer does not yet build or deploy these
modules. Existing trackpad, Wi-Fi recovery and Bluetooth startup installers remain
available. See [the branch overview](../../README.md) and
[mechanisms and validation](../../docs/t2-suspend/README.md).

## Patch series

| Series | Ordered changes | Status |
| --- | --- | --- |
| `patches/wifi/` | 0001 control-ring mailbox; 0002 host capabilities; 0003 IRQ/startup; 0004 partial-attach guard; 0005 bounded diagnostics | Combined with Bluetooth series, repeated actual S3 and audio recovery on tested machine |
| `patches/bluetooth/` | 0001 restore vendor windows; 0002 stop publishing failed rings; 0003 rebuild lost transport through HCI lifecycle and Bluetooth FLR | Repeated S3, automatic AirPods reconnect, initially-off Bluetooth recovery |
| `patches/wifi-reenable/` | 0001 propagate interface-open transport failure; 0002 explicit Wi-Fi function0 reset | Included from current test image; successful Wi-Fi-off cycle did not execute reset; earlier unexpected reboot remains unexplained |

Patch headers and copied evidence retain their original experiment status.
The current status is in this README and the consolidated validation document.
The Linux driver patches retain Linux's GPL-2.0 licensing and original author
attribution; Omarchy's MIT license does not relicense the kernel code. Mailbox
protocol adaptation credits Hector Martin/Asahi Linux in the patch itself.

## Reproduce source without building a kernel

Obtain the matching Linux source (`gregkh/linux` tag `v7.2.4` as recorded during
the experiment). Input hashes, rather than a tag name alone, determine whether
it is the reviewed baseline. No download is performed by this script.

From the repository root, with paths to your source checkout:

```sh
python3 packages/t2-suspend/prepare-source.py \
  --wifi-source /path/to/linux/drivers/net/wireless/broadcom/brcm80211 \
  --bluetooth-source /path/to/linux/drivers/bluetooth/hci_bcm4377.c \
  --output /tmp/t2-s3-source --profile s3
```

`--profile s3` reproduces the Wi-Fi protocol/diagnostic and Bluetooth recovery
source used for the repeated S3 passes. `--profile wifi-reenable` additionally
includes both Wi-Fi re-enable patches, matching the latest test image's source.
Select a new output directory for each profile. Existing output, changed input,
changed patches, or output that differs from tested source is rejected.

With the exact matching configured T2 kernel headers installed, module-only
build commands for the prepared tree are:

```sh
headers=/lib/modules/7.2.4-arch1-Watanare-T2-1-t2/build
make -C "$headers" M=/tmp/t2-s3-source/drivers/net/wireless/broadcom/brcm80211/brcmfmac W=1 KCFLAGS=-DDEBUG modules
make -C "$headers" M=/tmp/t2-s3-source/drivers/bluetooth W=1 modules
```

The tested headers have `CONFIG_BRCMDBG=y`, hence the debug flag above. A different
kernel/configuration requires a new review and build; do not reuse old binaries.
No full kernel build is necessary. The Wi-Fi output includes its vendor companion
modules. Build hashes can vary with toolchain and paths; source parity and kernel
ABI compatibility are separate checks.

## Offline tests

`python3 packages/t2-suspend/tests/test-preparation.py` tests source/patch drift,
existing-output preservation, and verified publication with temporary fixtures.

After preparing the `s3` tree above:

```sh
python3 packages/t2-suspend/tests/test-bluetooth.py /tmp/t2-s3-source/drivers/bluetooth/hci_bcm4377.c
python3 packages/t2-suspend/tests/test-open.py /tmp/t2-s3-source/drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.c
python3 packages/t2-suspend/tests/test-flr.py
```

These execute extracted C or the exact FLR helper with failure injection. They
verify state/error/DMA/IRQ behavior; they cannot prove real hardware reset safety.
`manifest.json` ties every patch to its original lab path at commit `68bf7e0`.
No generated modules, firmware, machine boot images, credentials, raw HCI/audio,
or private diagnostics are included.

## Deployment and rollback boundary

The tested machine uses a separate UKI with stock kernel and replaced driver
modules; stock boot remains available. Source consolidation does not change that
machine, install a service, regenerate an initramfs, or select a boot entry.
Distribution deployment still needs kernel package integration and boot-image
verification. Do not copy lab boot managers with machine-specific paths into an
unattended installer or enable the Wi-Fi FLR option globally.

The latest Wi-Fi FLR path requires `brcmfmac.t2_recovery_flr=1` at module load and
is restricted to Apple MacBookAir9,1 / Wi-Fi PCI14e4:4488 function0. The source's
Bluetooth recovery is chip-scoped to BCM4377, not proof that every matching model
has passed. The original sleep unload hook stays retired.

Tested companion configuration is BlueZ `[Policy] ResumeDelay = 5`, plus a scoped
NetworkManager device section with `wifi.scan-rand-mac-address=no` for
`wlp115s0f0`. The latter was an isolation experiment, persists across test boots,
and was insufficient by itself; it is not installed by this package. Disabling
scan MAC randomization changes privacy behavior. Existing connection profile MAC
policies were not changed. Neither setting is silently applied to other machines.

Rollback of a lab deployment is to manually boot its retained stock entry and
use that experiment's owned removal/backup procedure. The source package itself
has no live state to undo. Hibernate/S4 remains unresolved.
