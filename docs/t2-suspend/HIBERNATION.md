# T2 hibernation (S4) for MacBookAir9,1

Opt-in hibernation for the MacBookAir9,1 (T2, BCM4377 radios) on `linux-t2`. It is not enabled by default, by install or by any migration: nothing here changes what `systemctl hibernate` does until an operator deliberately deploys and opts in. This page is the overview; [DEPLOYMENT.md](DEPLOYMENT.md) and [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md) are the operator procedures and [EVIDENCE.md](EVIDENCE.md) says what was actually demonstrated.

## What it is

S3 suspend keeps RAM powered and is covered by the radio driver package (see [INSTALLATION.md](INSTALLATION.md)). S4 writes a memory image to swap, powers off, and later cold-boots a second kernel that reads the image and hands execution back to the saved session. On this Mac the second kernel cannot simply be the stock boot: the T2 BCE family, the Wi-Fi and Bluetooth functions and shared PCI power management need hibernation-aware drivers and a fixed restore ordering, and a stock image gives no way to load them before the image is read.

## Why a private image pair

Two private unified kernel images (UKIs) are built and staged next to the production entry:

- **Source image** boots the session that will be saved. It carries the candidate module stack (patched T2 BCE, `brcmfmac`, `hci_bcm4377`) and the marker and guard modules that record and gate the S4 sequence.
- **Restore image** is booted cold by the one-shot loader entry, reads the image and hands back to the source session. Its early initramfs holds the cold-restore guards.

The stock `Omarchy linux-t2` entry and its production UKI stay untouched as the fallback. The pair is built and audited offline by `packages/t2-suspend/experiments/` (`build-hibernation-candidate-uki.py`, `build-hibernation-source-uki.py`, `audit-hibernation-uki-pair.py`, `stage-hibernation-uki-pair.py`); the kernel changes it depends on are the `experiments/00*.patch` series plus `patches/bce/` and `patches/wifi/0006`, applied by the `hibernation` source profile of `prepare-source.py`. The candidate stack now targets `linux-t2` 7.2.7: t2bce is pinned to `6780d522` in `packages/t2-suspend/t2bce-source.json` and the patch series includes 0016 and 0017 (see [T2BCE-7.2.7-REBASE.md](T2BCE-7.2.7-REBASE.md)). Hardware S4 evidence exists only for the 7.2.6 generation.

The `experiments/` directory name and paths are kept on purpose: the deployed runtime snapshot and its inventory pin those paths, and the code shipped here is the code that ran on hardware. Only the parts the runtime and the pair build actually reach are included; lab probes and one-shot cleanup tools stay on the working branch.

## The byte-for-byte rule

Every private UKI must reuse the production `.linux` and `.cmdline` sections byte for byte. Replacement kernels repeatedly failed to mount the physical encrypted root even after offline and VM checks, so a private image may differ from production only in its initramfs and module payload. `stage-hibernation-uki-pair.py` and the pair audit enforce this and refuse anything else; do not work around them, and never reboot into an image that failed the audit or an earlier restore. A successful ordinary boot of the source or restore image does not show that S4 is safe.

## Qualification

Qualification is per exact artifact set, not per model. The audited pair, its module identities, the resume tuple and the kernel are bound into a manifest; each hardware cycle then goes through a ledger with one-use, consumed guards (`transaction.py`, `trial.py`) so a failed or consumed vector is never repeated. A cycle is complete only when the original session returns on the same boot, the evidence is archived and the stage slots are retired (`evidence_archive.py`, `slot_retirement.py`, `workflow.py`). Changing any qualified item invalidates qualification: it must be redone, never edited.

## Using it

Opt-in is a root-owned empty marker, `/etc/omarchy/t2-hibernate-product.enabled`, provisioned only after the root-owned runtime (`/var/lib/omarchy/t2-hibernate-product/`), the sleep drop-in and the reviewed unit are installed. Without the marker `omarchy system hibernate` is exactly `systemctl hibernate`. With it the command refuses off MacBookAir9,1, locks the session, and asks logind for `HibernateWithFlags` with inhibitors enforced, never falling back to stock hibernation. The unit `omarchy-t2-hibernate-product.service` and the `systemd-hibernate.service` drop-in run the fixed root-owned runtime; nothing is auto-started. `omarchy system hibernate` needs `omarchy-hw-t2` from the T2 hardware-detection PR.

A hidden wrapper drives the boot-policy actions of that runtime and never builds, stages or powers anything:

```bash
omarchy setup t2-hibernate status        # read-only summary, no privilege
omarchy setup t2-hibernate assess        # classify the current generation against the qualified baseline
omarchy setup t2-hibernate maintenance   # hold hibernation off before an update
omarchy setup t2-hibernate reactivate    # re-apply the source default when assess says "unchanged"
omarchy setup t2-hibernate activation    # reviewed source-default activation
omarchy setup t2-hibernate deactivation  # restore the exact stock boot policy
```

## Surviving updates

The prototype guard blocks every package transaction while hibernation is active, because an update can change the kernel, modules, firmware or boot entries under a private image that still points at the old ones. The maintenance lifecycle removes that block without weakening the veto:

1. **Maintenance.** With no saved image and the stock fallback verified, `maintenance` deactivates the source default, restores the retained stock boot configuration, archives a generation baseline (kernel, UKIs, module stack, driver and firmware inventory, control files, bootloaders) and durably writes `package-maintenance.pending`. The marker vetoes both sleep routes and reactivation.
2. **Guard.** The ALPM hook (`00-omarchy-t2-hibernate-guard.hook`, `update_guard.py`) admits ordinary transactions only while that inactive evidence validates, and keeps working after kernel and boot-image updates.
3. **Assess.** `assess` recomputes the baseline items read-only and reports `unchanged`, `requalification-required` or `unknown`. Snapshot churn in `limine.conf` does not count as a change.
4. **Reactivate or requalify.** If nothing the qualification depends on changed, `reactivate` re-applies the retained source default without requalification. Otherwise hibernation stays off until the pair is rebuilt and requalified. Interrupted transitions recover by re-running the same action; the [runbook](MAINTENANCE-RUNBOOK.md) covers the stuck states.

A `linux-t2` kernel update therefore correctly ends in `requalification-required`, which is what happened to the reference machine on 7.2.6 to 7.2.7. After a production kernel change the stale staged pair can be removed with the reviewed `stage-hibernation-uki-pair.py retire-after-production-change` mode ([runbook section 9](MAINTENANCE-RUNBOOK.md)). A generation-rebind path (maintenance to a new qualified generation) is in development on the working branch and will be added to this pull request after its audit.

## Limits

- Qualified only on one MacBookAir9,1 with kernel 7.2.6; the rebased 7.2.7 candidate is offline-verified only and its requalification is pending an attended test. Other models and kernels need their own qualification.
- Not automatic: no migration, installer or default enables it, and there is no unattended rollout.
- The 30 percent reserve check is a provisional engineering guard, not a measured battery or endurance policy.
- A marker rebind after requalification is not implemented.
- Distribution of the private UKI build (who builds, signs and stages it on a user machine) is an open question; today it is an operator procedure.
- The runtime carries some reference-machine constants that were part of the tested bytes (for example a fixed repair unit name in `trial.py`); they are deliberately left as tested.

## Tests

```bash
./test/shell                                    # includes system-hibernate-test.sh and setup-t2-hibernate-test.sh
cd packages/t2-suspend/tests && python3 -B test-hibernate-product-transaction.py   # one suite; each test-hibernat*.py is standalone
python3 -B packages/t2-suspend/experiments/verify-hibernation-candidate.py --input <fetched-input>   # offline patch series and kernel-source harnesses
```

Several harnesses take a kernel or patched source tree argument (they are exercised by `verify-hibernation-candidate.py`). The virtual-machine logind harness with real pacman transactions is not part of this branch; it lives on `fix-t2-vintage-mac-support`.

## Full history

The complete investigation log, the working notes and the raw evidence are on branch `fix-t2-vintage-mac-support`: `docs/t2-suspend/HIBERNATION.md` (journal), `RESUME.md` (current state) and `docs/t2-suspend/evidence/`.
