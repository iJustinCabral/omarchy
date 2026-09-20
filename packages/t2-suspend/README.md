# T2 suspend driver source package

This package consolidates the driver changes tested on MacBookAir9,1, BCM4377, Omarchy 4.0.3 and `7.2.4-arch1-Watanare-T2-1-t2`. It contains thirteen active patches, pinned source and patch hashes, source preparation, and extracted-C fault tests. Fresh setup and an upgrade migration now build/install these modules automatically through DKMS on the supported model; see [installer lifecycle and validation](../../docs/t2-suspend/INSTALLATION.md). Existing trackpad, Wi-Fi recovery and Bluetooth startup installers remain available. See [the branch overview](../../README.md) and [mechanisms and validation](../../docs/t2-suspend/README.md).

## Patch series

| Series | Ordered changes | Status |
| --- | --- | --- |
| `patches/wifi/` | 0001 control-ring mailbox; 0002 host capabilities; 0003 IRQ/startup; 0004 partial-attach guard; 0005 bounded diagnostics; 0006 complete hibernation callbacks | Patches 0001–0005 passed repeated actual S3 and audio recovery with the Bluetooth series; 0006 cleared the missing callback failure during `test_resume`, after which image-rewound transport state remained the blocker |
| `patches/bluetooth/` | 0001 restore vendor windows; 0002 stop publishing failed rings; 0003 rebuild lost transport through HCI lifecycle and Bluetooth FLR | Repeated S3, automatic AirPods reconnect, initially-off Bluetooth recovery |
| `patches/wifi-reenable/` | 0001 propagate interface-open transport failure; 0002 explicit Wi-Fi function0 reset | Runtime recovery remains model-scoped; the restore-time use of function-0 FLR was removed after it caused an abrupt reboot during `test_resume` |
| `patches/bce/` | 0001 run the existing BCE stateful handshake for freeze/thaw/restore; 0002 pair T2 audio freeze/thaw/restore callbacks | The staged BCE and audio `devices` freeze/thaw tests passed with working internal input and audio; diagnostic `test_resume` passed image write/readback. Package 1.5 is installed and its changed audio callback path passed hardware validation without an image; image restoration remains pending. |

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
  --t2bce-source-patch /path/to/linux-t2-patches/1001-Add-t2bce-driver-stack.patch \
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
python3 packages/t2-suspend/tests/test-hibernate-pm.py /tmp/t2-s3-source/drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c
python3 packages/t2-suspend/tests/test-bce-hibernate-pm.py /tmp/t2-s3-source/drivers/staging/t2bce/t2bce_core/t2bce_main.c
python3 packages/t2-suspend/tests/test-bce-audio-hibernate-pm.py /tmp/t2-s3-source/drivers/staging/t2bce/t2bce_audio/audio.c
python3 packages/t2-suspend/tests/test-flr.py
```

These execute extracted C, source invariants or the exact FLR helper with failure injection. They
verify state/error/DMA/IRQ behavior; they cannot prove real hardware reset safety.
`manifest.json` ties the original S3 patch set to its lab path at commit `68bf7e0` and the hibernation callback patch to its captured MacBookAir9,1 evidence.
No generated modules, firmware, machine boot images, credentials, raw HCI/audio,
or private diagnostics are included.

## Automatic deployment and rollback

Fresh hardware setup and the upgrade migration invoke the shared automatic installer. It downloads hash-pinned source, builds only the driver modules, registers DKMS rebuilding for T2 kernel updates, applies the tested radio/reconnect policy and generates the normal boot image. It does not change running radios or initiate a power transition. See [installation details](../../docs/t2-suspend/INSTALLATION.md) and [user commands](../../manual/t2-suspend.md).

The supported model is MacBookAir9,1 with BCM4377. The installer chooses the `wifi-reenable` profile and load-time Wi-Fi FLR option used for runtime radio recovery. The rejected hibernation `.restore` FLR is not included: hardware validation caused an abrupt reboot, so the diagnostic command blocks `test-resume` while that module is loaded. Hibernation remains unresolved.

The seven DKMS modules include all three Wi-Fi vendor companions, Bluetooth, the BCE core and T2 audio. The initcpio guard checks the selected replacement set before publishing a boot image, while only Wi-Fi and the BCE core are explicitly added early; audio remains root-filesystem loaded and Bluetooth preserves its startup gate. The installer owns a configuration receipt and initial boot backup; `omarchy setup t2-suspend --rollback` restores its configuration and the original modules for the next boot. Other T2 fixes retain their own installers.
