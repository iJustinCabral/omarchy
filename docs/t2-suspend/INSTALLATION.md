# Automatic T2 suspend driver installation

Fresh hardware setup and the upgrade migration now install the driver set automatically on Apple MacBookAir9,1 with the validated BCM4377 Wi-Fi PCI identity and a detected T2 chip. The existing Bluetooth installer establishes boot ordering first. The shared suspend installer downloads hash-pinned driver source, reproduces the `wifi-reenable` source profile, registers it with DKMS, builds all five modules against installed `linux-t2` headers for qualified kernels, installs the complete set, verifies selection and ABI, and rebuilds the normal T2 boot image through `limine-mkinitcpio`. It does not unload modules, toggle radios, restart Bluetooth, suspend, or reboot. The next ordinary boot activates the installation.

## Entry points

- Fresh setup: `install/hardware/apple/fix-t2-suspend.sh`, immediately after the Bluetooth gate leaf in `install/hardware/all.sh`.
- Existing installations: migration `1789256882.sh` calls `omarchy-setup-t2-suspend` on supported hardware. Any setup error propagates and leaves the migration pending.
- Repair/inspection: `omarchy setup t2-suspend`, `omarchy setup t2-suspend --verify`, and `omarchy setup t2-suspend --rollback` use the same manager.

Setup installs DKMS, matching T2 headers, compiler, make and patch through Omarchy's package helper. The source fetcher needs only Python's HTTPS support; every file is checked against the committed SHA256 manifest. There is no unpinned kernel-tree checkout, external package publication dependency, downloaded binary driver, or full kernel build. Source is prepared before live configuration is changed.

## Installed files and policy

| Location | Purpose |
| --- | --- |
| `/usr/src/omarchy-t2-radio-1.1/` | Verified driver source, DKMS build description, and the qualification gate (`check-radio-qualification.sh`, `qualified-radio.conf`) |
| `/var/lib/dkms/omarchy-t2-radio/` | DKMS builds, installation records and archived original modules |
| `/usr/share/dkms/modules_to_force_install/omarchy-t2-radio` | Replace the complete radio set even when a vendor companion's source version equals stock |
| `/etc/modprobe.d/omarchy-t2-suspend.conf` | Enable the model-scoped Wi-Fi recovery option from the tested image |
| `/etc/bluetooth/main.conf` | Set `[Policy] ResumeDelay = 5`; preserve other content and refuse a conflicting explicit administrator value |
| `/etc/NetworkManager/conf.d/99-omarchy-t2-radio.conf` | Reproduce the tested interface-specific scan-MAC policy |
| `/usr/lib/initcpio/install/omarchy-t2-suspend` | Check replacement modules and include Wi-Fi modules plus required Apple firmware before boot-image publication |
| `/etc/mkinitcpio.conf.d/zz-omarchy-t2-suspend.conf` | Append that verification hook |
| `/var/lib/omarchy-t2-suspend/receipt.json` | Original/installed configuration, source identities and transaction state |
| `/var/lib/omarchy-t2-suspend/boot-*/boot/` | Boot backup made before initial installation |

The scan policy disables scan MAC randomization only on the tested interface. It is included to reproduce the latest tested configuration, not because it independently solved the firmware stall; connection-profile MAC policy is unchanged. The Bluetooth delay and Wi-Fi option take effect with the next boot, along with the modules. The driver patches themselves retain their documented hardware checks. The Wi-Fi FLR helper remains an experimental recovery path: the latest functional pass did not exercise it, and the earlier reboot remains unexplained.

The retired Wi-Fi-unload sleep service remains removed. The Bluetooth startup gate (a prerequisite branch) and the Wi-Fi recovery watcher (an independent sibling contribution, when installed) retain their separate ownership and rollback receipts. This installer checks the gate before proceeding; it refuses conflicting custom service overrides or lab arrangements instead of overwriting them. DKMS configurations that request immediate live module loading are refused.

## Kernel updates and failure behavior

Arch's DKMS hook runs before the normal mkinitcpio hook when kernel/header files change. DKMS rebuilds this source for installed kernels ending in `-t2`; matching headers are required. The scoped force-install record ensures the three vendor companion modules are not rejected merely because their source versions are unchanged. DKMS stores original modules for removal. See the [DKMS documentation](https://github.com/dkms-project/dkms/blob/main/dkms.8.in) for module lifecycle and [pacman hook semantics](https://man.archlinux.org/man/alpm-hooks.5) for transaction ordering.

The initcpio hook checks every selected module's source version against its DKMS build and verifies the target kernel ABI. Missing or mismatched replacements terminate mkinitcpio before image publication. Returning an ordinary hook error is insufficient: mkinitcpio can otherwise write an incomplete image and return failure afterward. Bluetooth is checked on the root filesystem but not explicitly added to the initramfs; it still loads through the existing readiness gate. Image inspection also rejects early Bluetooth inclusion and missing required Apple firmware. The hook copies installed `brcmfmac4377b3-*` files and requires the Formosa binary, both SPPR NVRAM variants, CLM and TxCap blobs before building. These board-specific filenames are requested dynamically and are absent from static driver firmware metadata.

During initial installation, all builds complete before any replacement is installed. A subsequent installation, selection, or boot-image failure removes the owned DKMS registration, restores configuration and original modules, and restores the boot snapshot. Edited administrator files or source are preserved and cause an explicit error. An interrupted transaction remains recorded for rollback. Repeated completed installation verifies state and does not rebuild unnecessarily.

The owned `/usr/src/omarchy-t2-radio-<version>` root is published as mode `0755` so unprivileged DKMS inspection can traverse the registered source link. Repeated setup repairs that directory mode before verification without rebuilding modules.

A later manual rollback rebuilds the boot image for the currently installed kernel rather than restoring an obsolete kernel image from the original installation. DKMS removal restores its archived original drivers. Backups and the receipt remain for audit. Other T2 support components remain installed.

Automatic rebuilding is not a guarantee of compatibility with arbitrary future kernel APIs. An incompatible update reports a build failure and the boot guard prevents silently publishing an image with the wrong radio modules. Maintainers must update and validate the source profile when the kernel changes incompatibly. Source/installer revisions must bump the DKMS version and update the hook's version reference; changing an installed version's source in place is not supported. The installer upgrades an older installed version by rolling back the version named in the receipt (removing its DKMS registration and source, restoring original configuration and publishing a stock-driver image) and then installing the new version transactionally; a failed upgrade leaves stock drivers and a rolled-back receipt. This runs when `omarchy setup t2-suspend` (the `install` action) is invoked. `--verify` on a receipt of another version reports the installed version and asks for that command instead of checking, and `--rollback` removes whichever version the receipt names. Migration `1789256882.sh` calls the same command but runs only once per machine, so a machine that already applied it (for example with 1.0) must run `omarchy setup t2-suspend` to upgrade unless a new migration is added. A full package transaction is not rolled back by a post-transaction hook.

## Qualification gate, BCE coherence and DKMS archive

The package is radio only (Wi-Fi and Bluetooth); it never replaces any `t2bce_*` module. Because `BUILD_EXCLUSIVE_KERNEL="-t2$"` would otherwise rebuild the pinned source for any future `linux-t2` kernel, three guards bound what it may do to a kernel update.

- Qualification gate: `installer/qualified-radio.conf` lists, per kernel release, the stock `srcversion` of all five radio modules for which the pinned series is known to be compatible. `check-radio-qualification.sh` is the DKMS `PRE_BUILD` step; a kernel whose stock modules do not match a complete row makes DKMS skip the package, so that kernel keeps its stock drivers (and the unpatched stock suspend behavior). Adding a row is a requalification decision, never a routine version bump. The file records the limits of the check: `srcversion` hashes only each module's own sources, not kernel headers or internal APIs, so a match means the stock radio source is unchanged, not that the pinned series will compile. A build failure on a matching kernel makes the boot-image hook refuse and keep the previous image. Install decides qualification before any mutation, records `qualified_kernels` in the receipt, builds and installs only those kernels, runs `depmod` for all, and refuses when no installed kernel qualifies. Verification asks the gate again.
- BCE coherence: the stock `t2bce_dma`, `t2bce_core`, `t2bce_vhci`, `t2bce_audio` (and optional `t2bce_ave`) are one kernel-built unit. The initcpio hook and `verify` refuse to proceed when any of them resolves outside `kernel/drivers/staging/t2bce/` (for example from `updates/` or `extra/`), or when a required one is missing. This package does not replace them; the guard protects against another package doing so, which on a kernel update can leave in-tree siblings mismatched and disable the internal keyboard.
- Hook radio policy per kernel: all five modules from the package build are accepted; all five stock with no package build on an unqualified kernel is accepted with a warning; all five stock on a qualified kernel is refused (the build failed or never ran); any mixture, or any module that is neither the package build nor stock, is refused.
- DKMS archive: `dkms install` moves each stock module it replaces into `/var/lib/dkms/omarchy-t2-radio/original_module/<release>/x86_64/` with a `.origin` note naming the original path. After installation the gate therefore reads the stock module from the kernel tree first and then from that archive, and only when the `.origin` note confirms it came from the stock directory. `updates/` and `extra/` are never read. Install passes its pre-build qualification decision to its post-install selection check, because the stock tree no longer shows the fingerprint after the move.

### 2026-09-29 note

On the owner's MacBookAir9,1, `linux-t2` `7.2.7-arch1-Watanare-T2-2-t2` has byte-identical stock radio `srcversion` values to `7.2.6-arch2-Watanare-T2-2-t2`, so both are recorded as qualified rows. A real ACPI S3 lid-close cycle passed on 7.2.7 with radio drivers built from this package's lineage successor, the working-branch 1.6 radio-only package, which additionally carries the hibernation-era Wi-Fi patch 0006. That S3 evidence therefore came from the working-branch package, not from this PR's 1.1 build; this PR's patch series is unchanged and has not itself been exercised on 7.2.7.

## Validation boundary

The exact HTTPS source-fetch path and DKMS build were exercised in temporary directories against the installed T2 headers. Real DKMS installation into a temporary module tree exercised original-module archival and replacement. Transaction fixtures cover idempotence, build/install/image failures, boot/configuration restoration, administrator conflicts, source drift, missing headers, early Bluetooth and exclusion of power/radio commands. Shell fixtures cover fresh setup, migration, CLI verification/rollback and error propagation. The corrected installer has also been deployed on the test machine: a normal boot and a short actual S3 cycle passed with the installed drivers. See the [validation record](VALIDATION.md) for the deployment defects, corrections and observed results. A clean OS installation remains untested.

The earlier hardware suspend results remain the evidence for the driver behavior. This integration makes automatic delivery concrete, but neither fixes the unresolved hibernation/S4 issue nor expands qualification to other Mac models.

```mermaid
flowchart TD
  A[Fresh setup or upgrade migration] --> B{Supported MacBookAir9,1 and BCM4377?}
  B -->|No| C[Skip]
  B -->|Yes| D[Install dependencies and verify Bluetooth gate]
  D --> E[Fetch hash-pinned source and apply verified patches]
  E --> G[Save configuration and boot backup]
  G --> F[DKMS build all modules]
  F --> H[Install complete module set and tested policy]
  H --> I[Verify module selection and build boot image]
  I --> J[Next ordinary boot uses new drivers]
  K[Kernel and header update] --> L[DKMS automatically rebuilds]
  L --> I
  I -->|Initial installation fails| R[Restore original modules, configuration and boot files]
```
