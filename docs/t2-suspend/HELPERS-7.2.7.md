# Kernel-bound hibernation helpers for linux-t2 7.2.7

Requalification of the MacBookAir9,1 hibernation pair for `7.2.7-arch1-Watanare-T2-2-t2` needs three external modules rebuilt against the 7.2.7 headers, next to the patched t2bce stack (`T2BCE-7.2.7-REBASE.md`). This records the inventory, the unprivileged build, the artifacts, the pins that changed and the values an operator must use. Nothing here was loaded, staged or booted, and nothing here qualifies hibernation.

## Inventory

Kernel-bound (external `.ko`, vermagic-locked):

| Helper | Source | Variant flag | Role |
| --- | --- | --- | --- |
| `mba_hibernate_cold_pci_guard` | `experiments/hibernate-cold-pci-guard/` | none | guard inside the restore UKI (`cold_pci_restore` profile, `guard.ko`) |
| `mba_hibernate_efi_restore_marker` v2 | `experiments/hibernate-efi-restore-marker/` | `KCFLAGS=-DMBA_RESTORE_MARKER_V2` | restore-side EFI stage marker, embedded in the restore UKI and loaded by the pair runner check |
| `mba_hibernate_efi_postwrite_marker` v3 | `experiments/hibernate-efi-postwrite-marker/` | `KCFLAGS=-DMBA_POSTWRITE_SOURCE_MARKER_V3` | external source marker loaded by the S4 runner and the product backend (`config.json` `marker_file`/`marker_pin`) |

Not kernel-bound: `read-swap-header` (`experiments/hibernate-cold-pre-cpu/read-swap-header.c`, sha256 `2d7ee416...`) is a statically linked userspace ELF (sha256 `04dc3a5e80e1bf7306b77bf148b329a55a4028c9f561928b1b23f0647ebd763e`, no kernel headers, only libc and `linux/fs.h` ioctls). It is unchanged and stays valid for 7.2.7. Pass the same binary as `--cold-pci-restore-header-helper` with `--expected-cold-pci-restore-header-helper-sha256 04dc3a5e...`.

Other `.ko` sources under `experiments/` (RTC, ftrace-efi, stage marker, cold-pre-cpu/syscore/arch, cold-pci-pre-arch, kretprobes) belong to superseded profiles. The v16 pair used only the three above, and the current source and restore builders do not need any other module. They were not rebuilt.

## Compatibility with 7.2.7

All three sources compile unchanged and warning-free (`W=1`) against the 7.2.7 headers. The only message is the existing pahole 132/131 mismatch. Each srcversion is identical to the 7.2.6 build, which is expected because srcversion hashes the module sources, so the source is byte-identical to what was qualified on 7.2.6. Compilation is the compatibility evidence for the symbols they use; it says nothing about runtime behaviour on 7.2.7.

## Build (unprivileged)

```bash
K=/usr/lib/modules/7.2.7-arch1-Watanare-T2-2-t2/build
D=<private helper build directory>/build/<name>   # copy only <module>.c and Kbuild here
make -C "$K" M="$D" modules W=1                                         # guard
make -C "$K" M="$D" modules W=1 KCFLAGS=-DMBA_RESTORE_MARKER_V2         # restore marker v2
make -C "$K" M="$D" modules W=1 KCFLAGS=-DMBA_POSTWRITE_SOURCE_MARKER_V3  # postwrite marker v3
```

Toolchain: GCC 16.2.1 20260810, GNU ld 2.47.

## Artifacts

Directory: `<private helper build directory>/artifacts/<name>/`, each with the `.ko` and a `provenance.json`; `helpers-7.2.7/provenance.json` aggregates source sha256 per file, flags, kernel release and toolchain. Vermagic is `7.2.7-arch1-Watanare-T2-2-t2 SMP preempt mod_unload` for all three (modinfo prints a trailing space; the pins hold the stripped string).

| Artifact | sha256 | srcversion |
| --- | --- | --- |
| `guard/mba_hibernate_cold_pci_guard.ko` | `a2cb23c2fd2abb3e57156961ceee61d9884aaafcf6c034bd61f1d8678f393643` | `9D7B498FA4B5693DA3769B7` |
| `restore-marker-v2/mba_hibernate_efi_restore_marker.ko` | `b65f4d49e18c7bca3d1e7da1bce6afe1fd75a31bb6f6d5610ebae845d6c02255` | `0412DBD0B906890DE7EAF44` |
| `postwrite-v3/mba_hibernate_efi_postwrite_marker.ko` | `aeac152708982fa0de528a05e7f6bd91d917af478dc625db26e517018a30af4d` | `1A72ABF3A3BFC778FC5A9C6` |

Module `mba_restore_variable` is `v2` and `mba_postwrite_variable` is `v3`. Source sha256: guard `.c` `728a76d0...`, restore marker `.c` `a517ae29...`, postwrite marker `.c` `3a14bee8...` (full values and Kbuild hashes in the provenance files).

The module sha256 is not reproducible: rebuilding the guard from identical sources in another directory gave `0452e448...` instead of `a2cb23c2...` because the build path is embedded. So the sha256 pins name these specific files. Do not rebuild and expect the same hash. Keep the artifacts directory; copy the exact files. The srcversion is stable across rebuilds and across 7.2.6/7.2.7, so it carries no kernel binding on its own. The kernel binding is the vermagic release, which every consumer checks against the running or target release.

## Pin sites

Changed:

- `experiments/cold-pci-restore-protocol.py` `GUARD_SHA256` replaced with the 7.2.7 guard hash (was `f04c0d36...`, the retired 7.2.6 build). `GUARD_SRCVERSION` is unchanged. This is the only hard-coded helper hash the builders check; the release binding is dynamic through the image provenance `kernel_release`. The 7.2.6 hash was not kept: it verified only the retired v16 pair, whose evidence is handled by the `cleanup-*` scripts with their own pins.
- `experiments/audit-cold-pre-cpu-return.py` `SOURCE_MODULE_SHA256` replaced with the 7.2.7 postwrite marker hash (`SOURCE_MODULE_SRCVERSION` unchanged). The return audit compares the recorded postwrite identity of an attempt against this pin. Because consumed 7.2.6 attempt directories still exist and must remain auditable, `LEGACY_SOURCE_MODULES` keeps the single retired 7.2.6 pair (`4cbe981d...` with `1A72ABF3...`); a legacy hash is accepted only with its exact srcversion, and any other value is refused. New attempts use the current pin.
- Tests: `tests/test-cold-pci-restore-tooling.py` and `tests/test-cold-pre-cpu-return.py` assert the new pins, that the retired guard hash is not accepted, and that the legacy postwrite pair is accepted only exactly. No assertion was weakened.

Deliberately unchanged (evidence or fixtures):

- `cleanup-successful-v16-slots.py` (`KERNEL = "7.2.6-..."`, image and receipt pins) and `cleanup-terminal-restore-witness.py` (7.2.6 osrelease check, per-vector pins) verify consumed 7.2.6 evidence; they must keep 7.2.6 values.
- `audit-hibernation-swap-header.py` mentions the 7.2.6 `swsusp_header` layout in a docstring; the layout is unchanged in 7.2.7 for this use.
- `tests/test-hibernate-product-*.py` use `4cbe981d...` and 7.2.6 vermagic strings as synthetic fixtures for `hibernate/*.py`; they do not depend on the real artifact.

Pins outside my ownership (`hibernate/*.py`): none hard-code a helper hash, srcversion or 7.2.6 string. `hibernate/artifacts.py` imports `AUDIT.RESTORE.GUARD_SHA256` symbolically and picks up the new value. The marker pin arrives only through `config.json`.

## Operator values

Product `config.json` (schema `omarchy-t2-qualified-product-config-v2`), replacing the 7.2.6 `marker_pin`:

```json
"marker_file": "/var/lib/omarchy-t2-postwrite-marker/v3/mba_hibernate_efi_postwrite_marker.ko",
"marker_pin": {
  "sha256": "aeac152708982fa0de528a05e7f6bd91d917af478dc625db26e517018a30af4d",
  "srcversion": "1A72ABF3A3BFC778FC5A9C6",
  "vermagic": "7.2.7-arch1-Watanare-T2-2-t2 SMP preempt mod_unload",
  "variable_version": "v3"
}
```

The other keys (`source_directory`, `restore_directory`, `production_uki`, `source_tree`, `manifest`, `audited_details_sha256`, `staged_receipt_sha256`, `power_policy`) come from the new 7.2.7 pair and are not helper pins.

Install of the marker, as root: copy the exact artifact to the `marker_file` path (a fresh `v3` path is required only if it would overwrite consumed evidence; the existing convention is `/var/lib/omarchy-t2-postwrite-marker/v3/`). Requirements enforced by the code:

- Absolute path, a regular file, not a symlink, no symlinked parent (`artifacts._regular_path`).
- Live use (root `/`) requires owner uid 0 and mode exactly `0600` (`host_backend._marker_identity`); the S4 runner adapter applies the same to the restore module.
- Bytes must hash to `marker_pin.sha256`, `modinfo -F srcversion`, `-F vermagic` and `-F mba_postwrite_variable` must equal the pin (compared stripped), and the vermagic release must equal `/proc` kernel release and the audited `kernel_release`.
- `product.validate` re-checks the pinned bytes when the config is loaded; the state directory itself must be root `0700`.

Nothing in `hibernate/*.py` checks the marker's parent directory ownership or mode; use root-owned `0700` directories anyway.

UKI builder (`build-hibernation-candidate-uki.py`) for the restore image:

```
--kernel-release 7.2.7-arch1-Watanare-T2-2-t2
--restore-marker-module <artifacts>/restore-marker-v2/mba_hibernate_efi_restore_marker.ko
--restore-marker-version v2
--expected-restore-marker-sha256 b65f4d49e18c7bca3d1e7da1bce6afe1fd75a31bb6f6d5610ebae845d6c02255
--expected-restore-marker-srcversion 0412DBD0B906890DE7EAF44
--cold-pci-restore-guard-module <artifacts>/guard/mba_hibernate_cold_pci_guard.ko
--expected-cold-pci-restore-guard-sha256 a2cb23c2fd2abb3e57156961ceee61d9884aaafcf6c034bd61f1d8678f393643
--expected-cold-pci-restore-guard-srcversion 9D7B498FA4B5693DA3769B7
--cold-pci-restore-header-helper <read-swap-header binary>
--expected-cold-pci-restore-header-helper-sha256 04dc3a5e80e1bf7306b77bf148b329a55a4028c9f561928b1b23f0647ebd763e
```

The source UKI builder (`build-hibernation-source-uki.py`) takes no helper modules. The pair verifier and test-resume runner (`audit-hibernation-uki-pair.py`, `run-hibernation-uki-pair-test-resume.py`) take no helper flags; they read identities from image provenance.

S4 runner (`run-hibernation-uki-pair-s4.py`), postwrite-efi backend:

```
--marker-backend postwrite-efi --postwrite-source-marker-version v3
--postwrite-efi-marker-module /var/lib/omarchy-t2-postwrite-marker/v3/mba_hibernate_efi_postwrite_marker.ko
--expected-postwrite-efi-marker-sha256 aeac152708982fa0de528a05e7f6bd91d917af478dc625db26e517018a30af4d
--expected-postwrite-efi-marker-srcversion 1A72ABF3A3BFC778FC5A9C6
--restore-efi-marker-version v2
--restore-efi-marker-module /var/lib/omarchy-t2-restore-marker/v2/mba_hibernate_efi_restore_marker.ko
--expected-restore-efi-marker-sha256 b65f4d49e18c7bca3d1e7da1bce6afe1fd75a31bb6f6d5610ebae845d6c02255
--expected-restore-efi-marker-srcversion 0412DBD0B906890DE7EAF44
```

Both installed module copies must be root-owned `0600`. The runner requires the restore UKI provenance `restore_marker` to record the same sha256, srcversion, `v2` version and variable as these flags, so the builder and runner flags must name the same artifact.

## Limits

- The three modules have never been loaded on 7.2.7. Loading, arming and any S4 vector remain serialized hardware steps under the orchestrator.
- A rebuilt module changes its sha256 and invalidates every pin and image built from the old bytes; rebuild only by decision, then update this table and the image.
