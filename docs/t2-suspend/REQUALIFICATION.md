# Requalifying T2 hibernation after a kernel update

This is the tested operator procedure for bringing hibernation back after a production kernel update changed the qualified generation. It is distilled from the two attended runs that requalified linux-t2 7.2.7 on the MacBookAir9,1 (2026-09-29 and 2026-09-30, scripts and logs under `~/.local/state/codex-mba-autonomous/gen-7.2.7/`, `h6e/` and `h6f/`) and generalises the gate list in [DEPLOYMENT.md](DEPLOYMENT.md) (gate H6). The concrete 7.2.7 record is [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md); the design rationale is [REBIND-DESIGN.md](REBIND-DESIGN.md); stuck states are in [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md) sections 9 and 10. The map of the documents is [README.md](README.md).

It is a hardware campaign. Every step marked attended needs the owner at the laptop and their explicit go at that moment. Read the hardware safety rules in [`AGENTS.md`](../../AGENTS.md) first: never restage a replacement `.linux`, every private UKI keeps the production `.linux` and `.cmdline` byte-for-byte, never reuse a consumed guard, never repeat a failed vector, and serialise every boot, EFI, module-load and power step. Updates stay allowed for the whole procedure because the machine is in inactive package maintenance; hibernation stays off until H6h.

## When to use it

After `omarchy update` (or `omarchy-update-t2-hibernation post`) reports that the kernel or drivers changed, or whenever read-only `assess` prints `requalification-required`. Do not start while `assess` says `unknown` or `unchanged`; `unchanged` means run `reactivate` instead, and `unknown` needs the runbook first. Precondition: the machine is in inactive maintenance on the stock boot entry, the update guard exits 0, the stock kernel is healthy (keyboard, trackpad, Wi-Fi, Bluetooth, audio, a real S3 cycle on the stock entry), and AC power is connected for the trial.

Running `assess`, read-only:

```bash
S=/var/lib/omarchy/t2-hibernate-product
NATIVE=$S/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
sudo /usr/bin/python3 -I -B "$NATIVE" assess | jq '{class, changed_items, unknown_items}'
```

Expected after a kernel update: `requalification-required`, with `kernel`, `production_uki` and `control_inventory` changed and possibly `driver_modules` and `firmware` unknown. `rebind` accepts that class and refuses `unknown` and `unchanged`.

## Variables used below

```bash
S=/var/lib/omarchy/t2-hibernate-product
NATIVE=$S/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
EXP=$S/runtime/packages/t2-suspend/experiments   # root-owned, review-pinned copy; never run privileged Python from the workspace
T=$S/runtime/packages/t2-suspend/hibernate/trial.py
REL=<new kernel release, from uname -r>
CAND=<reviewed t2bce candidate build for this kernel>
WORK=~/.local/state/codex-mba-autonomous/gen-<kernel>   # private operator tree, outside the ESP
```

## Pitfalls we hit, read these first

- **Maintenance barrier self-veto (fixed in `77b293c6`).** The first runtime upgrade under maintenance (approval `c6051717`) failed safely because the adapter's own guard refused the barrier the adapter had just written. The fix admits the upgrade's own barrier and rebound marker and adds the `leftover` field to adopt an unconsumed earlier barrier. The failed approval is never re-run; a new approval with `leftover` adopts the barrier. See MAINTENANCE-RUNBOOK section 10.
- **Retire judge and the kernel-version comment (`ecb35dac`).** The retire dry-run refused on the `comment: Kernel version:` line that limine-entry-tool writes after the production entry. The fix reached the installed runtime only through another runtime upgrade under maintenance. Expect the stager to need a runtime upgrade whenever its retire judge is wrong for the new kernel.
- **Limine advertises entries only as of the boot.** After staging, `LoaderEntries` lists the old pair until one reboot on the stock entry, and `arm-source` refuses with "Limine has not advertised both pair entries". The same stock refresh reboot is needed after every reset that restages.
- **The receipt changes on arm, disarm and reset.** The staged receipt's digest is baked into the trial config, the product config and the boot policy review. Regenerate all inputs after the last arm or reset, and do not arm, disarm or reset after the boot policy review is generated.
- **Typed-phrase scripts need a real terminal.** The operator scripts read the confirmation phrase from `/dev/tty`. Run them in the owner's terminal, not through an agent tool or the `!` prompt, which has no tty. Read-only checks can run anywhere.
- **Helper modules are kernel-bound.** The cold PCI guard, restore marker and postwrite marker must be rebuilt for each kernel, re-pinned with their `srcversion` and `vermagic`, and independently reviewed before any image is built. A module built for the previous kernel has the wrong vermagic and hash. See [HELPERS-7.2.7.md](HELPERS-7.2.7.md). The t2bce module file hashes are not reproducible, so identify a rebuild by `srcversion`.
- **The trial needs a source-selected boot.** Trial readiness requires `LoaderEntrySelected` to be the source entry, a plain reboot with the one-shot consumed, AC online, no EFI stage slots and no marker module loaded.
- **Routine S4 needs a source-default boot.** A first routine cycle under a new manifest is refused on the restore-selected session that the trial leaves you in. After `rebind`, reboot once normally so the source default boots, then run the routine cycle.
- **Root-only state directories.** `$S` and the trial tree are root-only, so globs, `cd` and `readlink` fail as your user. Use `sudo sh -c '...'` or `sudo readlink`.
- **The marker goes to a fresh path per kernel**, `/var/lib/omarchy-t2-postwrite-marker/v3-<kernel>/`, because the installed config still pins the old module in `v3/`.
- **`source_tree` is built before the trial**, extracted the same way the audit extracts embedded modules (`lsinitcpio --early` plus `--cpio`); nothing else builds it.
- **Tools print trace lines on stdout.** Builders and the audit print `+ command` trace lines on stdout ahead of their JSON. Parse the last JSON line only.
- **Runners expect a source directory, not a proof file.** `--test-resume-proof-source` takes the source directory; the S4 runner also needs `--post-resume-input-evidence` and `--pre-s4-input-evidence`, and the marker modules must be absolute, root-owned, mode 0600 files. The runbook text in DEPLOYMENT H6e predates these corrections; prefer the corrected flow below.
- **A stale recovery acceptance may sit at the fixed path.** The acceptance file from an earlier vector would be refused; the operator script replaces it after the typed phrase.
- **Successful S4 leaves EFI stage slots that block updates.** The update guard refuses pacman until they are retired (H6e-clean). Never delete the EFI variables by hand.
- **Transient units.** The 7.2.7 trial ran as a transient unit `omarchy-t2-generation-trial-<manifest12>` without `--collect`, so a failed unit is kept as evidence. A foreground `sudo python3 -I -B "$T" --generation <manifest12> execute` is equivalent but dies with the terminal. The journal may show workflow state `archived` first; only `reconciled` in the ledger file is success.

## The sequence

| Step | Purpose | Attended | One-use or consumes |
| --- | --- | --- | --- |
| H6a | Upgrade the runtime under maintenance | root staging | approval is single-use |
| H6b | Retire the old pair | root | no |
| H6c | Rebuild helper modules and the new pair, then audit twice | no power action | no |
| H6d | Stage the new pair | root | no |
| Stock refresh | Reboot once so Limine advertises the new entries | reboot | no |
| H6e | Ordinary source boot, `test_resume`, restore boot, real S4 vector | yes | test_resume guard, S4 pair guard, stage slots |
| H6e-clean | Retire the two stage slots of the successful vector | root | no |
| Reset and arm | Stock reboot, restage the same images, arm the source one-shot | reboot | receipt changes |
| H6f | Generation trial, one real S4 | yes | trial guard for this generation |
| H6g | Issue qualification, config and boot policy review | root | no |
| H6h | `rebind` | root, no reboot | no |
| H6i | One routine S4 | yes | first cycle under the new manifest |

Evidence for each step lands in the operator tree (`$WORK/h6e/logs`, `$WORK/h6f/logs` by convention) and in the root-owned stores listed per step.

### H6a: runtime upgrade under maintenance

Purpose: install a runtime that knows how to retire the old pair and rebind, and whose guard resolves the maintenance chain from the retire step's custody files. It must come before H6b because retiring removes the receipt the old guard reads.

Stage and run exactly as the H1 and H2 gates in DEPLOYMENT.md describe, with protocol `omarchy-t2-runtime-upgrade-maintenance-approval-v1`. The approval pins the current boot id, so regenerate it after any reboot. The adapter:

```bash
sudo -n /usr/bin/python3 -I -B "$S/runtime-upgrade-native.py"
```

Expected: the adapter prints success; `runtime-upgrade-completed-<new12>.json`, retained old-runtime files, a consumed approval record and `runtime-rebind-<new12>.json` exist; the marker's `runtime_review_sha256` equals the new review; the guard exits 0; `assess` is still `requalification-required`. Abort: any refusal (writes nothing, diagnose read-only), or a retained `source-default-activation.pending` barrier, which vetoes updates and needs the new-approval `leftover` adoption described above. Consumes the approval. Evidence: `$S/runtime-upgrade-*`, `$S/boot-policy-transitions/<maintenance id>/`.

### H6b: retire the old pair

```bash
P=$EXP/stage-hibernation-uki-pair.py
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change --dry-run
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change
```

Expected: the dry run prints the plan and no error; afterwards `pair-retirement.json` and `pair-retired-receipt.json` exist, the guard exits 0 and `assess` is unchanged in class. Abort: any refusal (see the retire judge pitfall); an interrupted run is re-run or undone with `retire-rollback`. Old test vectors under `/var/lib/omarchy-t2-hibernation-pair` are kept and never reused.

### H6c: build and audit the new pair (no power actions)

1. Rebuild the three kernel-bound helper modules for `$REL` from `$EXP` and record `sha256sum`, `modinfo -F srcversion` and `modinfo -F vermagic`; review the pins; update `GUARD_SHA256` and `GUARD_SRCVERSION` in `cold-pci-restore-protocol.py` in a reviewed commit before building.
2. Build the source and restore images into new private directories as root (the builders need root to embed the unlock key):

```bash
sudo /usr/bin/python3 -I -B "$EXP/build-hibernation-source-uki.py" --candidate-source "$CAND" \
  --production-uki /boot/EFI/Linux/omarchy_linux-t2.efi --kernel-release "$REL" --output "$WORK/pair-source" --experiment-id <id>
sudo /usr/bin/python3 -I -B "$EXP/build-hibernation-candidate-uki.py" --candidate-source "$CAND" \
  --production-uki /boot/EFI/Linux/omarchy_linux-t2.efi --kernel-release "$REL" --output "$WORK/pair-restore" \
  --experiment-id cold-pci-guard-fullrestore-v1 --minimal-restore-devices <marker and guard pin flags from the previous pair's provenance.json>
sudo /usr/bin/python3 -I -B "$EXP/audit-hibernation-uki-pair.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore"
```

Expected: the audit classification is `structurally-matched-private-pair-not-boot-qualified` and prints the manifest digest (`manifest12` is its first 12 hex). The production `.linux` and `.cmdline` sections must equal the production image's byte-for-byte (the 7.2.7 run recorded this in `audit-sections.log`). Get a second, independent audit before H6d; the first is structural and is not proof that the pair boots. Abort: any pin mismatch or section difference. Nothing is consumed.

### H6d: stage

```bash
sudo /usr/bin/python3 -I -B "$P" stage --source "$WORK/pair-source" --restore "$WORK/pair-restore"
sudo /usr/bin/python3 -I -B "$P" verify
```

Expected: receipt `staged`, limine block written, verify passes, guard exits 0. `stage` refuses while an old receipt or image remains. Then reboot once on the stock entry with nothing armed and confirm the new entry ids appear in `LoaderEntries`.

### H6e: attended boots and the S4 vector

One step at a time, owner attended, the stock entry stays the default. The 7.2.7 scripts (`h6e/00` to `h6e/07`) wrapped these commands with state checks; the flow they enforce, which differs from the original DEPLOYMENT text, is:

1. Stock check, then arm the source one-shot (`arm-source`) and reboot. The one-shot boots the source entry once. On failure to reach a working desktop: hold power, boot, pick `Omarchy.linux-t2`, stop and ask. Do not re-arm blindly.
2. On the source boot: run `verify-hibernation-uki-pair-source.py --role source` (expect `pair-source-ordinary-boot-preflight-passed`, `hibernate_attempted: false`), check keyboard, trackpad, Wi-Fi, Bluetooth, audio by hand, and capture physical-input evidence (root-owned 0600 JSON with `boot_id`, `entry_id`, `keyboard_seen`, `trackpad_seen`) before and after.
3. `test_resume` (one-use, phrase `EXECUTE-TESTRESUME-<source16>`): in-place, no power-off, expect `state: returned-and-cleaned`. Any other state is terminal for this source vector. Vector files: `/var/lib/omarchy-t2-hibernation-pair/test-resume-vectors/<source sha256>/`.
4. Arm the restore one-shot and reboot into the restore image, verify with `--role restore`, hand-check, then reboot to stock. This proves an ordinary boot only; no image is restored. Then reset the pair (`rollback`, `clear`, `stage` of the same images, `verify`) and arm the source again, because the receipt is otherwise in `restore-arming`.
5. On a fresh source boot: capture pre-S4 input evidence, install the root-owned marker modules, validate the S4 runner (it prints the transition vector, `sha256(source:restore:runtime)`), write the recovery acceptance after the phrase `I AM AT THE MACBOOK AND CAN RECOVER TO STOCK`, then execute with phrase `EXECUTE-S4-<vector16>`. The screen goes dark and the machine powers off; wait about 30 seconds after all lights and fans stop, then press power once. Limine boots the restore entry and the original session returns.

Expected success: `attempt.json` with `state: returned-and-cleaned`, `real_s4_attempted: true`, `recovery_method: operator-attended-cold-power`, postwrite stage at least 3 (4 observed), restore stage 7, restore hook stage 2, and the cold-PCI restored-source witness beside it. Abort: no usable session within about 5 minutes (hold power 10 seconds, choose `Omarchy.linux-t2`). A failed or ambiguous S4 vector is terminal: preserve everything, never retry, never delete EFI variables. Consumes: the S4 pair guard, attempt directory, V3 source and V2 restore stage slots, hook witnesses and the recovery acceptance.

### H6e-clean: retire the stage slots

```bash
V=<pair vector printed by the S4 runner>
sudo /usr/bin/python3 -I -B "$EXP/cleanup-successful-pair-slots.py" --vector "$V"            # validate, read-only
sudo /usr/bin/python3 -I -B "$EXP/cleanup-successful-pair-slots.py" --vector "$V" --execute  # typed phrase CLEAN-SLOTS-<vector16>
```

The tool (`6d569778`, `4c5842ba`) derives everything from the vector's durable evidence and refuses failed, ambiguous or unreconciled vectors. It is not in the installed runtime that preceded the 7.2.7 upgrade, so the operator ran it from a root-owned export of the reviewed commit; a future runtime ships it. Expected: `slots_cleared: true`, the update guard exits 0, `assess` stays `requalification-required`. Idempotent: re-run if interrupted.

### Reset, arm, source boot

Reboot on stock, run the pair reset (`rollback`, `clear`, `stage`, `verify`), arm the source, reboot and verify the source boot with `trial.verify_readiness` preconditions: source entry selected, one-shot consumed, AC online, no stage slots, marker module not loaded, root on `/dev/mapper/root`. Build the trial `source_tree` (embedded modules extracted the way the audit does) before the trial; a wrong tree would burn the one-use trial after its guard is consumed. Install the postwrite marker at a fresh root-owned 0600 path for this kernel.

### H6f: generation trial (one real S4)

Generate `config.json` (`omarchy-t2-explicit-trial-config-v1`, with `retire_slots: true`) and `authorization.json` (`omarchy-t2-product-one-use-trial-v1`, `qualified: false`, `original_boot_id` equal to the current boot). Install them root-owned 0600 under a fresh `0700` tree `/var/lib/omarchy/t2-hibernate-trial/generations/<manifest12>/{guards,ledger,archives}`, then:

```bash
sudo /usr/bin/python3 -I -B "$T" --generation <manifest12> inspect     # full admission, consumes nothing
sudo /usr/bin/python3 -I -B "$T" --generation <manifest12> execute     # one use; phrase EXECUTE-TRIAL-<manifest12>
```

Expected: a real S4 as in H6e; the session returns and within about a minute `ledger/cycle-<cycle id>.json` reaches `state: reconciled`, with `guards/trial-consumed.json` naming it. Any other state is terminal for this generation. A reboot invalidates the authorization, and any receipt change invalidates the config: regenerate.

### H6g: issue the qualification

After independent review of the trial record, write the qualification (`omarchy-t2-product-cycle-v1`, `evidence_sha256` equal to the SHA-256 of the exact bytes of the reconciled cycle file), the product config (schema v2, battery `power_policy`) and the boot policy review (`approved: true`). Install them root-owned 0600 as `$S/rebind-*.json` (phrase `ISSUE-QUALIFICATION-<manifest12>`). The trial uses the legacy AC-only policy, so keep the charger connected.

### H6h: rebind

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" rebind     # phrase REBIND-<manifest12>; no reboot or power action while it runs
```

Expected JSON: `"rebound": true`, `"requalification_required": false`, `"live_execution": true`, `"power_operation": false`. Afterwards the new `config.json`, `qualification.json` and `boot-policy.json` exist, the opt-in file exists, the marker and pending are gone, `default_entry` names the source entry, and the guard refuses package transactions again until the next `maintenance`. If interrupted, re-run; do not reboot. See MAINTENANCE-RUNBOOK section 10 for refusals.

### H6i: one routine S4

Reboot once normally so the source default boots, then `omarchy system hibernate` (phrase `ROUTINE-S4-<manifest12>` in the operator script). Expected: the newest ledger cycle under `$S/ledger` is `reconciled` with ledger state `reconciled` (`qualified-product-cycle-reconciled` is the classification `product.py` prints, not a ledger state), chained to the previous terminal cycle. Until it passes, the generation is bound but unproven.

## Recommended future work

Turn the gen-7.2.7 operator scripts into in-repo tooling (a parameterised `omarchy` debug or maintenance command plus tests) so that the next kernel update does not depend on hand-adapted scripts and a person who remembers the pitfalls. The scripts already encode most of the corrections in this document (stock refresh, reset after restore boot, slot cleanup export, source tree, regenerated inputs, typed phrases). Not done in this pass.
