# Automatic installer validation record

Current result: normal installed-driver boot and one short actual S3 suspend/resume passed on MacBookAir9,1. Bluetooth and audio were user-confirmed after resume; Wi-Fi was operationally up, without a separate traffic probe in that last checkpoint. A clean OS installation and hibernation remain unvalidated. See the [installer lifecycle](INSTALLATION.md) and [driver test ledger](README.md) for the other validation boundaries.

The dated checkpoints below preserve deployment failures and their corrections. Earlier pending statements describe the state at that checkpoint, not the current result.

### Completed integration checks

The real source fetch passed all pinned hashes. DKMS3.4.3 built all five modules in `/tmp`; their source versions matched the tested candidate, including Wi-Fi `E8C051F8EBDA8DE23852575` and Bluetooth `4DF58889A43B9AC7E9E3E8C`. Actual DKMS installation into a temporary module tree archived the copied originals. Actual removal restored all five stock files byte-for-byte and left no override modules.

A real mkinitcpio image generated under `/tmp` passed with the installed hook, all replacement Wi-Fi modules and the source-verification marker; Bluetooth was absent from early boot as intended. Missing dependencies in an earlier incomplete fixture exposed the need to terminate on accumulated build errors, which the final hook checks. No live `/boot` or system module files were modified.

Twelve installer tests and five source-preparation tests passed, along with shell setup/migration/CLI/error-routing fixtures. Existing trackpad, T2 hardware, Bluetooth installer/gate, Wi-Fi recovery and sleep-retirement suites passed. The CLI suite passed; it retained its unrelated sandbox theme-lock warning. This is isolated installation/build validation, not a fresh hardware boot of the automatic installer.

### First live deployment: ready for ordinary boot

On September12, the committed installer was run on the test MacBookAir9,1. DKMS installation and the manager's verification passed. Independent extraction of the generated normal T2 UKI confirmed the unchanged stock kernel, all four matching Wi-Fi modules, embedded policy and source marker, and no early Bluetooth module. All existing test images and their menu entries were preserved. The separate lab verifier subsequently changed the normal image, invalidating its menu hash; see the incident below.

The temporary lab Bluetooth load override was backed up and removed without unloading Bluetooth. A lab-only `noresume` guard prevents the old hibernation target from being used during this S3-driver boot validation; it is not part of the automatic installer. At this checkpoint, the machine was still on the test image and normal-boot validation was pending.

### Lab verification caused a pre-boot hash failure

The first ordinary boot attempt stopped at Limine with “URI wrong hash,” before Linux executed. The separate lab verifier used `objcopy --dump-section` on the live UKI without an output filename. Objcopy rewrote the PE image in place after the verifier's initial menu-hash check. This was a verification-tool defect, not evidence of a driver initialization failure. The automatic installer's `lsinitcpio` path supplies `/dev/null` as an explicit output and does not have this defect.

The lab verifier now inspects a private copy, supplies a separate output filename, and checks that both the live image and menu remain unchanged afterward. The faulty invocation was reproduced on a disposable copy. The normal UKI and menu were regenerated through `limine-mkinitcpio` using the already installed stock kernel and DKMS modules, without compiling a kernel or changing running drivers. Corrected verification checks the menu hash, stock kernel identity, module source versions, boot policy and preservation of all five test images. At this checkpoint, an ordinary hardware boot was still pending.

### Normal boot exposed missing Apple firmware

The next normal boot reached Linux but Wi-Fi failed during initramfs startup: `Direct firmware load for brcm/brcmfmac4377b3-pcie.bin failed with error -2`, followed by `Dongle setup failed`. Bluetooth's dependency gate then timed out with `Wi-Fi netdev not ready; Bluetooth left unloaded`. The driver modules loaded; their Apple board-specific firmware had been omitted from the normal image. The working test image explicitly included those files.

The initcpio hook now copies the installed `brcmfmac4377b3-*` firmware files into the image and aborts if the supported Formosa board's binary, either SPPR NVRAM variant, CLM blob or TxCap blob is missing or empty. These dynamically selected Apple filenames are not covered by the driver's static firmware metadata. Firmware remains sourced from the machine's existing Apple firmware installation; this patch does not redistribute it. The installer also rejects a generated image missing the five required files.

The corrected hook was deployed and the normal UKI regenerated without rebuilding the kernel or driver modules. Independent extraction verified all 15 installed Wi-Fi firmware files byte-for-byte, the stock kernel, replacement Wi-Fi modules, menu hash and preservation of the five test boot entries. Fourteen installer tests and five source tests passed, including missing-firmware rejection and an actual hook failure for each required file. The initial lab deployment encountered a nested verification-lock conflict and rolled back safely; the corrected deployment passed. At this checkpoint, a fresh normal boot with the firmware packaging change was still pending; the later checks below passed.

### Normal installed-driver boot passed

On September12, the user returned from the normal entry and confirmed Wi-Fi, Bluetooth and audio working. Boot `fb189f6a-986d-4816-8b86-bf775f4f9a4f` uses stock kernel `7.2.4-arch1-Watanare-T2-1-t2`, without lab command-line markers or a runtime Bluetooth load override. Loaded Wi-Fi source version `E8C051F8EBDA8DE23852575` and Bluetooth `4DF58889A43B9AC7E9E3E8C` match the tested drivers; module lookup selects both from `updates/dkms`. Wi-Fi recovery policy is enabled.

The journal confirms Wi-Fi firmware initialization, then a ready Wi-Fi interface, followed by the Bluetooth gate loading its driver and BlueZ starting successfully. An audio transport became ready and the user confirmed functionality. Existing P2P creation errors and transient BlueZ connection/cache warnings remain in the log; this pass records working normal-boot behavior, not an absence of warnings. This supersedes the pending normal-boot checkpoints above. A clean OS installation and suspend/resume on this normal image have not been validated by this boot; hibernation remains unresolved and the lab `noresume` guard remains installed.

### Normal installed-driver suspend/resume passed

The user subsequently performed a short suspend cycle on the same normal boot and confirmed Bluetooth and audio working afterward. The journal records deep suspend entry at 21:20:27, ACPI S3 entry and low-level resume at 21:20:32, then suspend exit at 21:20:33. This confirms actual S3 entry and return. T2BCE completed its stateful resume successfully. Bluetooth restored its vendor windows, encountered transient HCI command errors, then exercised the patched Bluetooth function reset and reached firmware/RTI readiness while rebuilding HCI. The user-confirmed working audio validates the resulting recovery; this is not a claim of an error-free log.

The Wi-Fi interface was operationally up after resume, though no separate network traffic probe was performed in this checkpoint. Normal boot and one short S3 cycle now pass with the installed drivers. This does not validate overnight battery drain, a clean OS installation, the Wi-Fi function-reset fallback, or hibernation. The earlier test-image validation and its limitations remain documented separately.
