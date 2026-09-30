# New-generation rebind: design rationale

Status when written: source and synthetic tests only. The rebind has since run on the reference MacBookAir9,1 (see [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md), gate H6h); this document is design, not hardware evidence, qualification or permission to hibernate. Operator procedure: [MAINTENANCE-RUNBOOK.md, "Requalify and rebind a new generation"](MAINTENANCE-RUNBOOK.md) and [DEPLOYMENT.md gate H6](DEPLOYMENT.md). Companion evidence: RESUME.md (on branch `fix-t2-vintage-mac-support`).

## The gap

After `linux-t2` 7.2.6 to 7.2.7 the machine sits in inactive package maintenance (`package-maintenance.pending`). `boot_policy_native.py assess` reports `requalification-required` (kernel, production UKI, control inventory changed). The only exit was `reactivate`, which handles class (a) `unchanged` only and is bound to the old policy, receipt, config manifest and baseline. Three more things blocked the path: the runtime upgrade refuses while the marker exists (the marker pins the runtime review), `trial.py` hard-codes one one-use state root whose consumed guard can never be reset, and it was unproven that the product ledger accepts a first cycle under a new manifest. This change adds the missing new-generation path without weakening any of those guards.

## Constraints that shaped the design

- Every step must be recoverable by re-running the same fixed command, with sleep and updates vetoed the whole time, exactly like `reactivate`.
- Nothing may self-issue authority. The qualification, the product config and the boot policy review are externally issued files; the engine only checks their bindings and installs them.
- No consumed guard, ledger record or archive is ever reset, moved or rewritten. New state lives beside the old.
- The installed guard validates the maintenance chain on every package transaction. It must keep admitting updates during the whole requalification window, and it must keep refusing anything forged.

## Finding: the old receipt needs custody

The maintenance chain (`update_guard._maintenance`, `assess`, `_verify_existing_maintenance`, the reactivation and the rollback paths) reads the staged pair receipt at the fixed path `/var/lib/omarchy-t2-hibernation-pair/receipt.json` and requires its SHA-256 to equal the marker's `staged_receipt_sha256`. Retiring the old pair (the stager `retire` mode) deletes that receipt, and staging the new pair writes a different receipt at the same path. Without a fix, the chain breaks in the middle of the requalification window: the guard would refuse every update, and `assess` would report `unknown` instead of `requalification-required`.

The fix is a custody record. The stager's retirement leaves two root-private files in the product state directory:

- `pair-retired-receipt.json`, the exact bytes of the retired receipt.
- `pair-retirement.json`, `{"protocol": "omarchy-t2-pair-retirement-v1", "retired_receipt_sha256", "source_sha256", "restore_sha256"}` with exactly those keys.

`boot_policy_transition.marker_receipt(root, intent)` returns the live receipt while its digest is the marker's, and otherwise the retained copy, provided the record chains to the marker's digest and the retained bytes hash to it. A new receipt at the fixed path never satisfies the old marker on its own. `update_guard._maintenance` and the fixture coordinator use it, so the guard, `assess` and every recovery keep validating across retirement. The rebind and the guard are the only consumers; the stager only produces the two files.

Consequence for ordering: the runtime that contains this resolver must be deployed before the old pair is retired, because the installed (older) guard reads the fixed receipt path. That is why the operator sequence starts with the runtime upgrade under maintenance.

## `rebind`

`boot_policy_native.py rebind` (fixed action, no arguments, same real logind block inhibitor, `db.lck` and physical lock as the other actions) calls `boot_policy_transition._rebind`. Preconditions, all checked before any write, all refusing with zero writes:

1. The maintenance marker exists, validated by the update guard's exact validator, and the reviewed runtime equals the marker's runtime binding.
2. No policy, opt-in, deactivation pending, runtime pending or foreign activation pending exists. A pending under the shared filename with another protocol is never adopted.
3. The read-only assessment core reports `requalification-required`. `unchanged` refuses and points at `reactivate`. `unknown` refuses; there is deliberately no override, because an unknown item is exactly the ambiguity the requalification exists to remove. (The task allowed an explicitly reviewed override; none was built. See open questions.)
4. The old pair is retired: the live receipt digest differs from the marker's, the retirement record chains to the marker digest, its image identities equal the baseline manifest's, and the new receipt's images differ from the retired ones.
5. The staged authority exists under distinct names and binds the new pair: `rebind-config.json` (its `staged_receipt_sha256` equals the live new receipt, its manifest differs from the retired generation's and pins the staged images), `rebind-qualification.json` (protocol `omarchy-t2-product-cycle-v1`, `qualified: true`, `manifest_sha256` equal to the digest of the staged manifest, checked by `transaction.receipt_value`), and `rebind-boot-policy-review.json` (the externally approved source-default policy for the new receipt).
6. Product-level validation by the native adapter's `_rebind_inspect`: the audit derived from the staged config reproduces the archived resume target, `product.validate` accepts the staged config and qualification for the derived manifest, the new pair verifies as staged stock (`trial._verify_deployment(source_default=False)`), no saved image is at the resume page, and a fresh generation baseline is captured from the staged names (`generation_items(config_name=..., qualification_name=...)`). A missing critical item fails; tolerated items may be unreadable.
7. Limine: the pair backup (`limine.conf.before`) must hash to the receipt's `original_limine_sha256`; the current bytes with the recorded snapshot region spliced in must hash to the receipt's `staged_limine_sha256` (so the only tolerated drift is snapper churn); the reviewed policy must be exactly the approved proposal for those bytes.

New backup bytes are the reconstructed staged bytes, not the current bytes, because `boot_policy.prepare` binds the receipt's staged hash to exact bytes including the snapshot region.

The fresh generation capture is checked to have read exactly the staged config and qualification bytes this run will install (their SHA-256 in the capture must equal the bytes read earlier), so a swap between capture and install is refused before any write instead of only at W7.

Torn writes: the pending (W1) and `boot-policy.json` (W4) are published by writing a complete temporary and renaming it, so those names never hold partial bytes. A stray temporary holds no authority; rollback removes its own, and a forward run clears an earlier run's torn pending temporary without adopting it. The runtime marker rewrite retains its old copies the same way.

### Write order

Each write is preceded by `guard()`. The pending uses the activation-pending filename with protocol `omarchy-t2-package-rebind-intent-v1`. It chains the old marker digest, the old baseline digest, the retirement record digest, the old receipt digest, the new receipt digest, the fresh baseline digest and the old and new SHA-256 of the four authority files (config, qualification, boot-policy review, Limine backup) plus the Limine change.

| Step | Write |
| --- | --- |
| W1 | rebind pending (sleep and updates vetoed from here) |
| W2 | archive directory `boot-policy-transitions/<id>`: intent, comparison (with the assessment), fresh baseline, retirement record, retained receipt, new receipt, opt-in evidence, and copies of every old and new authority file |
| W3 | atomically install config, qualification, review and backup (temp file plus `os.replace`, each verified against the recorded digest) |
| W4 | `boot-policy.json` |
| W5 | one `default_entry` line of the current Limine bytes (point of no return; snapshot region untouched) |
| W6 | routine opt-in |
| W7 | ACTIVE postchecks against the fresh baseline (below) |
| W8 | `completion.json` |
| W9 | unlink the marker |
| W10 | unlink the pending, release the package lock |

W2 archives also let recovery authenticate the retirement record and the retained receipt (their digests are in the pending), not only the new receipt. W7 verifies `boot_policy.verify` for the new receipt, the opt-in, an idle ledger, the unchanged reviewed runtime and the native postchecks: deployment as source default, `product.validate` on the installed authority, no saved image, and every critical generation item equal to the fresh baseline (tolerated items unreadable on either side are skipped).

### Recovery and rollback exactness

Recovery is a re-run. It authenticates the pending (canonical, exact key set, bound to the marker and baseline digests), classifies each of the four authority files as exactly the old or exactly the new bytes (anything else is foreign and preserved), and requires the archive to be complete and byte-exact once any state changed. Then:

- No valid completion: roll back. Reverse the boot line on the current bytes, remove the opt-in and policy, restore each authority file from the archived old copy, re-validate inactive maintenance with the pending ignored, re-run the retained gate, write `rollback.json`, retire the pending. The result equals the prior maintenance state byte for byte and mode for mode; only a torn rebind archive directory may remain as noise (a test asserts the exact tree).
- A valid completion with the marker present: re-check ACTIVE; if it holds, finish W9 and W10, otherwise roll back. Never proceed forward past W5 on any other evidence.
- Marker gone, completion valid: finish W10.

A failure releasing the package lock reinstates the pending. A torn completion is never trusted forward. The tests inject a crash before every write, repeated crashes during recovery, and foreign bytes in each authority file, the archive, the policy and the Limine bytes.

## Runtime upgrade under maintenance

The ordinary path still refuses when the marker exists; `runtime_deployment._upgrade_snapshot` treats the marker as a blocker unless called with `maintenance=True`. The maintenance path additionally requires the runtime-only v2 pins (exact config bytes preserved, a fresh UUID4 approval id, the six core pins plus the adapter's seventh pin `new_image_state`) and rewrites the marker's runtime binding under the same barrier:

- The marker's only runtime-dependent field is `runtime_review_sha256`. The archived baseline binds the marker's digest, and the guard requires marker == archived `maintenance-intent.json`. So the three files move together.
- Before any replacement, the old marker, the old baseline and a rebind record are written exclusively into the archive (`*.before-runtime-<new12>.json`, `runtime-rebind-<new12>.json`). The three replacements are then atomic renames, executed only after every file is proven to be exactly the old or the new form.
- `settle_maintenance_binding` is the idempotent recovery: given the intent and the installed review digest, it converges all three to the new form when the new runtime is installed and to the exact old bytes when the old one is. It creates any missing retained copy first and refuses foreign bytes without writing.

The installed adapter selects the mode from its approval protocol (`omarchy-t2-runtime-upgrade-maintenance-approval-v1`). Its host pins are the qualification, the hook and the exact marker bytes; boot policy and opt-in must be absent (Limine legitimately churns and is validated by the chain instead). The before-barrier check is the old reviewed guard's validator plus the pinned resume page check; the postcheck loads the new reviewed guard from the verified tree and runs its validator with only this upgrade's two veto files ignored; and it repeats once with the barrier retired. The recovery restores the durable veto first, then settles the marker binding.

## Per-generation trial state

`trial.py` gains `--generation MANIFEST12`. Its state root becomes `/var/lib/omarchy/t2-hibernate-trial/generations/<first 12 hex of the manifest digest>/` (config, authorization, `guards/`, `ledger/`, `archives/`, all root-private 0700 real directories provisioned by the operator). The derived manifest digest must match the directory name. The physical-cycle lock stays the single global lock. Without the flag, behaviour is unchanged, including the permanent consumed-guard refusal; `repair-constructor` is bound to the original root and refuses with `--generation`. Nothing reads, moves or resets the original guard.

An alias of the original trial is refused: with `--generation`, the audited manifest must not equal the manifest named by the original root's consumed guard record or its config (both read fail-closed), so provisioning `generations/<original manifest12>/` cannot mint a second one-use trial of the manifest whose guard was consumed.

## Qualification evidence

`evidence_sha256` must equal the SHA-256 of the exact bytes of `/var/lib/omarchy/t2-hibernate-trial/generations/<manifest12>/ledger/cycle-<id>.json`, the record `trial.execute` leaves in its terminal state. It is the most authoritative of the durable artifacts: it is the ledger's own cycle file, whose evidence digests chain prepared, returned, archive, release and reconcile, and it exists only in state `reconciled` after slot retirement succeeded (the trial config must set `retire_slots: true`). `trial_evidence()` reads and validates it before any write, refusing unless: every directory is a real 0700 owner directory (no symlinks) and every file private, single-link and regular; the manifest12 named by the directory is the digest of the staged config's manifest; the ledger holds exactly one cycle, valid under `transaction.cycle_value`, for that manifest, in state `reconciled`; `ledger/state.json` is unblocked for the manifest; and `guards/trial-consumed.json` (protocol `omarchy-t2-product-one-use-trial-v1`) names the same cycle id, vector and manifest. A record from the original trial root is never consulted (only `generations/` is read), so it cannot satisfy this. The cycle and guard bytes are archived in the rebind archive and the cycle digest is in the pending. What this does not prove: it binds the qualification to a real successful attended trial of this exact manifest, not that the trial's hardware outcome was good beyond what the ledger records; the operator's review of that outcome remains the qualification decision.

## Signals

`rebind` and `reactivate` (and the other live actions of the native adapter) and the runtime-upgrade adapter install handlers that turn SIGHUP, SIGTERM and SIGINT into `SystemExit`, so the existing `finally` clauses release `db.lck` and the pending veto stays for a re-run to recover. SIGKILL and power loss cannot be handled and can leak the lock; the runbook (section 4 procedure) covers it.

## Guard confirmation of retirement

When the guard uses the retained receipt, it also requires that no ESP image at the stager's fixed image paths still hashes to a retired image (absent, or different bytes of the new pair, are accepted). The cost is hashing the two staged images per guard run, only while custody is in use. The shared `pair_custody.IMAGE_PATHS` equals the stager's table (tested).

## Assessment precondition against the live 7.2.7 report

The live report (`class: requalification-required`, changed `control_inventory`, `kernel`, `production_uki`, unknown `driver_modules` and `firmware`, baseline valid, stock Limine projection equal) is accepted. `_assess_core` gives changed items precedence, and `rebind` refuses only the classes `unchanged` and `unknown`. An unknown item next to a changed one is safe because the old generation's items are used only to classify that the old qualification no longer applies; they never authorize anything. The new generation is judged from scratch by the fresh capture (critical items must be readable and are compared again after install) plus product validation, the staged-pair verification and the saved-image check. After the runtime upgrade under maintenance the report is expected to keep that class: kernel and production UKI still differ, `control_inventory` loses the per-boot `/run` entries (only genuine control-file changes remain), and `driver_modules`/`firmware` stay unknown, because the still-installed config names the 7.2.6 provenance release whose module directory no longer exists. They become readable in the fresh capture, which uses the new config's release (the radio-only inventory, and tolerated items may in any case be unreadable). This is derived from the code and the report, not from a live run after the upgrade.

## Ledger continuity

The product ledger needed no change. `Ledger.configure(new manifest)` drops the qualification but keeps every cycle and allocation link; `begin` requires all previous cycles reconciled and links the new allocation to the exact old head, and `_allocation_head` never compares manifests between links. Synthetic tests cover the first and later cycles under the new manifest, immutability of old records, refusal after an unreconciled or failed old cycle (a failure block persists across `configure` and needs external reconciliation, which is intended), a foreign qualification, and a tampered predecessor. The routine dispatcher's `_admission_state` only requires immediate same-session predecessor evidence when the restore entry is selected, which is never the case for a first cycle after a rebind.

## What this does not do

It issues no qualification, config or policy review. It does not restage or reboot anything, touch EFI, modules or power, or reset any guard. It does not build or stage the new pair (that is the stager and the attended hardware campaign). It does not authorize S4: the first routine S4 after a rebind is a separate attended action.

## Open questions

- The stager's `retire` mode must write `pair-retirement.json` and `pair-retired-receipt.json` exactly as above (or the constants in `boot_policy_transition.py` must change). The engine's record parser is strict. The stager's `retire-after-production-change` now writes them (before the live receipt is removed, journaled, rolled back by `retire-rollback`) through the shared `hibernate/pair_custody.py`, which the guard and rebind also use to validate them, including that the record's images equal the retained receipt's. Nothing enforces that they exist before the old receipt is deleted: if the stager deletes the receipt without them, the guard refuses updates and `assess` reports `unknown` until they exist. The stager must also atomically replace an existing record whose `retired_receipt_sha256` is not the receipt being retired, because a successful rebind leaves the previous generation's two files in place (they are archived in the rebind archive and never consumed).
- The qualification is still authored by the operator or orchestrator, but it is no longer free-standing: see "Qualification evidence". A trial whose slots were not retired never reaches `reconciled` and cannot qualify.
- No override for `unknown` assessments exists. If a reviewed override is wanted, it should be a further staged, externally issued evidence file bound to the marker digest, not a flag.
- `post_return_reconcile.py` needs no generation-aware variant: it is a one-off recovery pinned to the single failed cycle `d8923d12-...` (hard-coded cycle, boot, vector and byte pins, no CLI, no caller in the repository or any documented operator sequence). A generation trial archives and reconciles inside `trial.execute` through `WORKFLOW.run`, exactly like the original.
- Rebind installs a boot policy review that an external reviewer must author (`prepare` output with `approved: true`); the existing activation has the same manual step.
