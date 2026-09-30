# Runtime deployment procedure: e489bab7 to cf907542

Operator procedure for deploying the audited update-survival source (branch `fix-t2-vintage-mac-support`, reviewed commit `cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc`) to the live MacBookAir9,1, whose installed hibernation runtime is generation `e489bab70e13bfcbbfacc8811a6f6093e7973dd0`. Companion documents: [RESUME.md](RESUME.md) (state and task list), [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md) (fail-closed stuck states after gate H3), [HIBERNATION.md](HIBERNATION.md) (evidence), [AGENTS.md](../../AGENTS.md) (hardware safety rules).

Status: **draft procedure, not approved for execution.** Nothing here has been run against the live machine. Every gate below (H0 to H4) needs its own explicit operator approval at the moment it is reached; a prior approval, an automatic goal continuation or a green fixture test is not approval. Facts that could not be confirmed from the repository or from user-readable files are marked **unverified**.

## Scope and non-goals

This procedure replaces the root-private runtime snapshot at `/var/lib/omarchy/t2-hibernate-product/runtime` (plus its review and bootstrap authority) with the reviewed source, then moves the machine into inactive package maintenance so that ordinary `pacman`/`omarchy update` transactions can run. It deploys runtime code only.

It does NOT: build, stage, install or boot any UKI, `.linux`, `.cmdline`, EFI variable, kernel or module; change `qualification.json`, `config.json` or the source and restore images; run any S3, S4 or other power transition; reactivate hibernation (gate H5 is a separate, later, optional approval and needs a runtime generation that contains `reactivate`); or deploy the S3 fix (RESUME.md task 6). Gate H3 does rewrite `/boot/limine.conf` back to the retained stock configuration and removes the routine opt-in and active policy; that is a boot-configuration change (not a boot-image change) and is called out at that gate. Hibernation stays OFF after H3 by design. That is the intended fail-safe.

The adapter changes runtime authority under a fixed protocol: source `runtime_upgrade_native.py` (adapter), `runtime_deployment.py` (core, `_upgrade_snapshot` at line 295) and `image_state.py`. Facts cited below use `file:line` at the reviewed commit.

## Why the design has a staged image-state helper

The installed generation `e489bab7` lacks `image_state.py` (RESUME.md, "Additional upgrade audit"; source-history inspection, unverified on the host). The adapter's pre-barrier precheck therefore never loads it from the installed runtime. It reads the root-staged, doubly pinned helper `STATE/runtime-upgrade-image-state.py` (`runtime_upgrade_native.py:29`, `:172-191`). The helper's sha256 must equal both approval `expected.new_image_state` (`:182`) and the new review's `image_state.py` entry (`:184`), and the helper is executed from the already verified bytes, never re-read (`:164-169`). Its swap-header parser is pinned to the old review's digest (`:186-190`). After the barrier the checks load the newly installed runtime tree instead (`:266-267`, `:282`).

The adapter owns `db.lck` and the physical-cycle flock itself (`:426-540`) because the installed `_locks` lacks `check_physical`. The seven approval pins are validated by the adapter (`HASHES`, `:42`, checked `:93-95`); the core receives only the six `CORE_HASHES` (`:41`, passed `:583`).

## Reference constants

| Item | Value | Source |
| --- | --- | --- |
| `STATE` | `/var/lib/omarchy/t2-hibernate-product` (root 0700) | `runtime_upgrade_native.py:25` |
| Approval protocol | `omarchy-t2-runtime-upgrade-approval-v2` | `:88` (field set `:86-87`) |
| Approval fields (exact set) | `protocol approved current_boot_id source_directory reviewed_commit adapter_sha256 expected unchanged approval_id` | `:86-87` |
| `expected` (exact set of 7) | `old_review old_bootstrap old_config new_review new_bootstrap new_config new_image_state` | `:41-42`, `:93` |
| `unchanged` (exact set of 5) | `qualification boot_policy limine opt_in hook` | `:45-51`, `:98` |
| Fixed staged names in `STATE` | `runtime-upgrade-native.py`, `runtime-upgrade-approval.json`, `runtime-upgrade-review.json`, `runtime-upgrade-config.json`, `runtime-upgrade-bootstrap.py`, `runtime-upgrade-image-state.py` | `:26-29`, `runtime_deployment.py:36-38` |
| Adapter file modes | root:root, 0600, single link, no group/other write | `:65-75`, `:117-124` |
| Consumed record | `runtime-upgrade-approval-consumed-<approval_id>.json`, created with `O_EXCL` | `runtime_deployment.py:364,394-396`, `_new_private:261` |
| Completion record | `runtime-upgrade-completed-<first 12 hex of new commit>.json` = `runtime-upgrade-completed-cf9075424e20.json` | `runtime_deployment.py:377`, `:421` |
| Retained names | `runtime-retained-e489bab70e13-before-cf9075424e20`, `runtime-review-retained-e489bab70e13-before-cf9075424e20.json`, `runtime-bootstrap-retained-e489bab70e13-before-cf9075424e20.py`, `config-retained-e489bab70e13-before-cf9075424e20.json` | `runtime_deployment.py:372-376` |

Pins expected from the prior deployment of `e489bab7` (mirrored from the user-readable copy `~/.local/state/codex-mba-autonomous/runtime-upgrade-review.zGJnAZ/`, whose sha256 I recomputed): the installed generation is `old_review 947f0ce95c9eb73da0f2316f0795d5c16c8b41dacffa7a3870db771602c2ee0d`, `old_bootstrap 85b33df9dead8a1621008074ab40bef3cffc9981529d4f1aa2d57381c8723248` (equals sha256 of `runtime_deployment.py` at `e489bab7`, verified with `git show`) and `old_config = new_config 2f66daf877d84a12c7fcb5df8de40a5722898f37be39a563c1609fbe16aa4f23` (equals the config file in that directory, verified). That the live `STATE` files still have exactly these bytes is **unverified** (root-only) and is re-checked at H0.

Pin values are not listed here on purpose: they depend on the exact reviewed commit and must be recomputed independently at approval time and never copied from a document.

## Gate map and stop rules

| Gate | Effect on machine | Privilege | Approval |
| --- | --- | --- | --- |
| Prerequisites, build, pins, approval file, review | none (repo and user files only) | none | not a hardware gate |
| H0 | read-only root inspection of `STATE`, `/boot/limine.conf`, locks | sudo, read-only | operator |
| H1 | writes six staged files into `STATE` (retains prior staged files first) | sudo | operator |
| H2 | runs the adapter: replaces runtime, review, bootstrap; consumes approval | sudo, real inhibitor | operator |
| H3 | maintenance publisher: deactivates hibernation, restores stock `limine.conf`, writes marker | sudo, real inhibitor | operator |
| H4 | first package update through the native guard, then `omarchy update` | sudo / update flow | operator |
| H5 (optional, later) | `reactivate`: re-applies the retained source default without requalification, only when `assess` reports `unchanged` | sudo, real inhibitor | operator |
| H6a to H6i (after a kernel update, hardware campaign) | requalify and `rebind` a new generation: runtime upgrade under maintenance, retire, build, stage, attended vectors, issue authority, generation trial, `rebind`, one routine S4 | sudo, real inhibitor, attended hardware | operator, per sub-gate |

Stop and ask for review if any check differs from its expected output. Unknown means stop. Never retry a failed gate by repeating it: recovery for H2 and H3 is read-only diagnosis first (see the failure section). Never reboot, power-cycle, suspend or hibernate the machine at any point of gates H0 to H5. Gate H6 is different: its attended hardware steps (H6e to H6g and H6i) reboot into the staged entries as described there, one at a time; every other H6 step (H6a, H6b, H6d, H6h) must not be interrupted by a reboot or power action.

### Do not create snapshots before H3

This applies to the installed runtime (`e489bab7`) and to any deployed generation that predates the snapshot-blind Limine comparison; the reviewed source ignores the snapshot region while hibernation is active, but it is not installed until H2.

Until H3 has completed, do not run `omarchy update`, `omarchy-snapshot` or `snapper create`, and do not delete snapshots. `omarchy update` creates a Snapper snapshot before pacman runs (and before the hibernation guard refuses the transaction), and the enabled `limine-snapper-sync` watcher then rewrites the snapshot region of `/boot/limine.conf`. While hibernation is active, the product and the H3 deactivation require `/boot/limine.conf` to equal the staged pair bytes exactly (`stage-hibernation-uki-pair.py` `verify_staged`, only `default_entry` may differ), so any such rewrite makes H3 refuse (fail closed, hibernation unavailable) until reviewed. After H3, snapshot churn is expected and admitted: the maintenance checks only read `default_entry` and the stock `//linux-t2` entry binding, never the snapshot region (verified with fixture and VM tests, `b2dbf51f`).

## Prerequisites (read-only, unprivileged)

Run from the repository. Every command is read-only. Reconcile before proceeding, as AGENTS.md "T2 Hibernation Hardware Safety" requires.

```bash
cd /home/jjc/Projects/MBA_9_1
git rev-parse HEAD                      # expect cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc, or a descendant if only docs changed
git merge-base --is-ancestor cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc HEAD && echo "reviewed commit is in history"
git status --short                      # informational; the export below does not use the working tree
cat /proc/sys/kernel/random/boot_id     # record it; it goes into the approval. Last recorded in RESUME.md: a45522fe-3787-4d06-a53e-2e6b896ea210
jq -r '.runtime_upgrade_execution' ~/.local/state/codex-mba-autonomous/handoff.json   # expect the e489bab7 record; do not dump the rest of the file
pgrep -ax pacman || echo "no pacman process"
ls /var/lib/pacman/db.lck 2>&1          # expect: No such file or directory
systemd-inhibit --list --no-pager       # expect only delay inhibitors (NetworkManager, UPower, lock screen); no block inhibitors
cat /etc/omarchy/t2-hibernate-product.enabled | wc -c   # expect 0 (empty opt-in file, source-default mode)
sha256sum /etc/omarchy/t2-hibernate-product.enabled /etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook
# expect e3b0c442...b855 (empty) and 0491dcf7...9fac (both observed unprivileged and matching the prior approval when this was written)
findmnt -n -o SOURCE,FSTYPE --target /swap/swapfile     # expect /dev/mapper/root[...] btrfs
cat /sys/power/resume /sys/power/resume_offset          # informational; the adapter compares them with the audited tuple
cat /sys/class/power_supply/*/online /sys/class/power_supply/BAT*/capacity 2>/dev/null   # AC online, or capacity >= 30
```

The power policy is enforced by product code (`power_policy.observe`, `product.check`; `min_charge_percent` 30 in the config). Plug in AC for the whole procedure. Also confirm out of band that the machine is booted on the ordinary source-default entry it was last verified on, that no hibernation or restore is in flight, and that you are not relying on suspend during the procedure.

Root-only preconditions, checked at H0 and re-checked by the adapter itself: hibernation is active in source-default mode; `qualification.json`, `boot-policy.json` and `/boot/limine.conf` are the pinned bytes; no `runtime-upgrade.pending`, `source-default-activation.pending`, `source-default-deactivation.pending`, `package-maintenance.pending` or `.runtime-pending` (`runtime_deployment.py:325`, `:378`); no saved image at the resume page; no EFI overrides; ledger reconciled; `physical-cycle.lock` exists (`runtime_upgrade_native.py:44`, `:511-514`). All **unverified** until H0.

## Build the source directory

Never point the adapter at the development tree. The adapter reads the source as root, so it must be an immutable exact export owned by the operator, at a canonical path with no symlink components (`runtime_upgrade_native.py:104-106`).

```bash
C=cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc
D=/home/jjc/.local/state/codex-mba-autonomous/runtime-upgrade-${C:0:8}
[[ ! -e $D ]] || echo "REFUSING: $D exists; stop here and do not run the next lines"
install -d -m 0700 "$D" "$D/source"
git -C /home/jjc/Projects/MBA_9_1 cat-file -e "$C^{commit}"
git -C /home/jjc/Projects/MBA_9_1 archive --format=tar "$C" packages/t2-suspend/hibernate packages/t2-suspend/experiments | tar -x -C "$D/source"
[[ "$(readlink -f "$D/source")" == "$D/source" ]] && echo "source path is canonical"
```

Only the two runtime trees are exported because `inventory()` reads only those (`runtime_deployment.py:27`, `:112-134`). `git archive` uses the commit's tree, so the working tree, untracked files and `__pycache__` never enter it. Keep `$D/source` unmodified until H2 has finished; the adapter compares its inventory to the approved review at H2 (`runtime_upgrade_native.py:220`, `runtime_deployment.py:352`). After the export, make it read-only for the owner if desired (`chmod -R a-w "$D/source"`); modes do not enter the inventory, only bytes and sizes.

## Compute the review, the inventory and every pin

Unprivileged and read-only. This imports `runtime_deployment` from the EXPORT (never the dev tree) and calls `inventory()` exactly as the adapter does. `python3 -I` avoids the user site and the current directory; the interpreter writes no bytecode.

```bash
cd "$D"
python3 -I -B - "$D" "$C" <<'PY'
import hashlib, importlib.util, json, sys
from pathlib import Path
d, commit = Path(sys.argv[1]), sys.argv[2]
src = d / "source"
hib = src / "packages/t2-suspend/hibernate"
spec = importlib.util.spec_from_file_location("rd", hib / "runtime_deployment.py")
rd = importlib.util.module_from_spec(spec); spec.loader.exec_module(rd)
files = rd.inventory(src)                       # runtime_deployment.py:112, read-only
review = {"protocol": rd.SCHEMA, "approved": True, "reviewed_commit": commit, "files": files}
raw = json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n"
(d / "runtime-upgrade-review.json").write_bytes(raw)
h = lambda b: hashlib.sha256(b).hexdigest()
for name, member in (("runtime-upgrade-native.py", "runtime_upgrade_native.py"), ("runtime-upgrade-bootstrap.py", "runtime_deployment.py"),
                     ("runtime-upgrade-image-state.py", "image_state.py")):
  (d / name).write_bytes((hib / member).read_bytes())
print("files", len(files), "bytes", sum(v["size"] for v in files.values()))
print("new_review", h(raw))
print("new_bootstrap", h((hib / "runtime_deployment.py").read_bytes()), "== inventory", files["packages/t2-suspend/hibernate/runtime_deployment.py"]["sha256"])
print("new_image_state", h((hib / "image_state.py").read_bytes()), "== inventory", files["packages/t2-suspend/hibernate/image_state.py"]["sha256"])
print("adapter_sha256", h((hib / "runtime_upgrade_native.py").read_bytes()), "== inventory", files["packages/t2-suspend/hibernate/runtime_upgrade_native.py"]["sha256"])
print("hook", files["packages/t2-suspend/hibernate/00-omarchy-t2-hibernate-guard.hook"]["sha256"])
PY
cp -- ~/.local/state/codex-mba-autonomous/runtime-upgrade-review.zGJnAZ/runtime-upgrade-config.json "$D/runtime-upgrade-config.json"
sha256sum "$D"/runtime-upgrade-*
```

Rules that the pins must satisfy (the adapter and core refuse otherwise):

- `new_bootstrap` equals the review's `runtime_deployment.py` entry, and `adapter_sha256` equals the review's `runtime_upgrade_native.py` entry (`runtime_upgrade_native.py:200`, `:206`; `runtime_deployment.py:337-338`).
- `new_image_state` equals the review's `image_state.py` entry (`runtime_upgrade_native.py:184`).
- `old_config == new_config` and the config file is the exact bytes already installed as `config.json` (`runtime_upgrade_native.py:96`, `runtime_deployment.py:362`). Reusing the prior staged config file is correct only because its digest equals the installed config's; that equality is verified at H0.
- The installed hook bytes must appear in both the old and new reviews under the hook entry (`runtime_deployment.py:339-341`). The dry run shows the new review's hook entry equals `0491dcf7...`; the old review's entry is checked at H0.
- The new commit must differ from the old (`runtime_deployment.py:342`).
- The `unchanged` pins (below) come from root-only files, so they are collected at H0. The three old-generation pins (`old_review`, `old_bootstrap`, `old_config`) are read from root-owned live files at H0, not taken from memory or from this document.

## Gate H0: root read-only inspection

Operator approval required. Read-only under `sudo`; it changes nothing. Run in the owner's own terminal (`sudo` with a password); an assistant may only be handed the printed output.

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo ls -la --time-style=full-iso "$S"
sudo sha256sum "$S/runtime-deployment-review.json" "$S/runtime-deployment-bootstrap.py" "$S/config.json" \
  "$S/qualification.json" "$S/boot-policy.json" /boot/limine.conf /etc/omarchy/t2-hibernate-product.enabled \
  /etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook
sudo jq -r '.reviewed_commit' "$S/runtime-deployment-review.json"        # expect e489bab70e13bfcbbfacc8811a6f6093e7973dd0
sudo jq -r '.files["packages/t2-suspend/hibernate/00-omarchy-t2-hibernate-guard.hook"].sha256' "$S/runtime-deployment-review.json"   # expect 0491dcf7...
# STATE is root-only (0700): globs must expand inside the root shell, not in yours.
sudo bash -c 'cd /var/lib/omarchy/t2-hibernate-product && shopt -s nullglob && ls -la runtime-upgrade* source-default-*.pending package-maintenance.pending .runtime-pending *retained*cf907542* runtime-upgrade-completed-cf9075424e20.json 2>&1'
# expect: only the previous upgrade's retained/staged names described in H1 (if any); NO *.pending, NO .runtime-pending, NO *cf907542* names
sudo flock -n /var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock true && echo "physical lock free"
sudo test -f /var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock && echo "lock file exists"
```

Expected (all **unverified** until run):

- `runtime-deployment-review.json` = `947f0ce9...2ee0d`, `runtime-deployment-bootstrap.py` = `85b33df9...23248`, `config.json` = `2f66daf8...16aa4f23`.
- Present in `STATE`: the previous upgrade's fixed-name files (`runtime-upgrade-native.py` = adapter `460ac3da...482e`, `runtime-upgrade-approval.json`, `runtime-upgrade-review.json`, `runtime-upgrade-config.json`, `runtime-upgrade-bootstrap.py`), plus `runtime-upgrade-completed-e489bab70e13.json`. There is no `runtime-upgrade-approval-consumed-*` file for that upgrade: the installed `e489bab7` core predates consumed-approval markers (its approval is protocol v1); replay of it is prevented by the completion record and the review mismatch. Observed at H0 on 2026-09-29. Whether the previous staged files were kept, and under what names, is **unverified**; the handoff says they were staged and the adapter run, not that they were retained.
- Absent: `runtime-upgrade.pending`, `source-default-activation.pending`, `source-default-deactivation.pending`, `package-maintenance.pending`, `.runtime-pending`, and `/var/lib/pacman/db.lck`.
- `qualification.json`, `boot-policy.json` and `/boot/limine.conf` hashes; record them. The prior approval pinned `ffa9bc82...fe64`, `a6e406ec...2177` and `aba687f2...65b7` for these; they may legitimately differ now if boot policy or `limine.conf` changed since. Whatever H0 prints becomes the approval's `unchanged` values; a difference from the prior values must be explained before proceeding.

Stop if any pending marker exists, if `old_*` hashes differ from the pins above, or if `git` shows the consumed deployment `4125726a-4847-4802-a821-953e6abe995a` is not the last upgrade recorded in the handoff.

Also confirm the boot configuration is still exactly the approved source-default bytes. While hibernation is active, `/boot/limine.conf` must equal the boot policy's recorded `after_limine_sha256`:

```bash
S=/var/lib/omarchy/t2-hibernate-product
[[ $(sudo sha256sum /boot/limine.conf | cut -c1-64) == $(sudo jq -r .after_limine_sha256 "$S/boot-policy.json") ]] && echo "limine.conf is the approved source-default bytes"
```

If it differs, stop: `limine-snapper-sync` or something else rewrote it while hibernation was active, and H3 would refuse. Do not edit the file by hand; this needs review. (Do not use the installed stager's `verify` action for this check: at `e489bab7` it verifies the stock layout with `default_entry: 2` and always refuses in source-default mode. Observed 2026-09-29: it printed "Staged pair Limine configuration changed" while the hash above matched exactly.)

## Create the approval JSON

Unprivileged, in `$D`. The `approval_id` must be a fresh random UUID4 that has never been used; never reuse `4125726a-4847-4802-a821-953e6abe995a` or any id already present as an `approval-consumed` file (`runtime_upgrade_native.py:90-92`, `runtime_deployment.py:289-292`). All hashes are 64 lowercase hex characters (`:78-81`). Replace each placeholder with the value printed by the compute step or H0 and copy no value from this document.

```bash
cd "$D"
python3 -I -B - <<'PY'
import json, uuid
approval = {
  "protocol": "omarchy-t2-runtime-upgrade-approval-v2",
  "approved": True,
  "approval_id": str(uuid.uuid4()),
  "current_boot_id": "<contents of /proc/sys/kernel/random/boot_id, from the same boot as H2>",
  "source_directory": "/home/jjc/.local/state/codex-mba-autonomous/runtime-upgrade-cf907542/source",
  "reviewed_commit": "cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc",
  "adapter_sha256": "<sha256 of runtime-upgrade-native.py>",
  "expected": {
    "old_review": "<H0: sha256 of installed runtime-deployment-review.json>",
    "new_review": "<compute step: sha256 of runtime-upgrade-review.json>",
    "old_bootstrap": "<H0: sha256 of installed runtime-deployment-bootstrap.py>",
    "new_bootstrap": "<sha256 of runtime-upgrade-bootstrap.py>",
    "old_config": "<H0: sha256 of installed config.json>",
    "new_config": "<same value as old_config>",
    "new_image_state": "<sha256 of runtime-upgrade-image-state.py>"
  },
  "unchanged": {
    "qualification": "<H0>", "boot_policy": "<H0>", "limine": "<H0>",
    "opt_in": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "hook": "<H0: installed hook sha256>"
  }
}
open("runtime-upgrade-approval.json", "w").write(json.dumps(approval, separators=(",", ":")) + "\n")
PY
jq . runtime-upgrade-approval.json
```

The boot id in the approval must equal the boot id at H2; the adapter re-checks it at every guard call (`runtime_upgrade_native.py:129-130`). If the machine reboots between approval creation and H2, the approval is void: regenerate the file with a NEW `approval_id`. The source directory, the field set and every pin are validated by `_parse_approval` (`:84-111`); the `opt_in` pin must be the empty-file digest because the adapter also demands the opt-in be empty (`:137`).

## Independent review gate

An auditor other than the author (a separate Sol high agent or the owner) repeats the following from scratch and reports a match line by line. Only then may H1 begin. The auditor should work from a fresh export in a different directory, not from `$D`.

1. Re-export `git archive cf907542...` independently and compare it with `$D/source` (`diff -r`, expecting no difference apart from bytes not included in the export).
2. Recompute `inventory()` from the auditor's export and require `sha256` of the review file to match, byte for byte (`cmp`).
3. Recompute `adapter_sha256`, `new_bootstrap`, `new_image_state` from `git show cf907542:<path> | sha256sum` and require them to equal both the approval and the review's file entries.
4. Confirm `old_config == new_config` and `new_config` equals the digest of the staged `runtime-upgrade-config.json`.
5. Confirm the `unchanged` values against H0 output produced by the operator (not by the author).
6. Confirm `approval_id` is a fresh UUID4, distinct from `4125726a-4847-4802-a821-953e6abe995a` and from any consumed id printed at H0, and that `current_boot_id` equals the live boot id.
7. Read the diff `e489bab7..cf907542` for `packages/t2-suspend/hibernate` and `experiments` and confirm it matches the audited checkpoint in RESUME.md (this needs the auditor to re-run `git diff --stat`, not trust this document).
8. Confirm the six files in `$D` are exactly the six that H1 will install and that no extra byte has been added (the staged file set is exactly the six names in the reference table).

Record the auditor's result next to the approval. A mismatch anywhere blocks H1; regenerate everything rather than editing a file in place.

## Gate H1: root staging with readback

Operator approval required. Writes only to `STATE`; the runtime is untouched and the machine keeps the installed blanket guard hook. Nothing here executes staged code.

First retain the previous upgrade's fixed-name files (only those that exist; the check at H0 tells which). The retained names must not begin with `runtime-retained-`, `runtime-review-retained-`, `runtime-bootstrap-retained-` or `config-retained-`, because the adapter's recovery scans for those prefixes (`runtime_upgrade_native.py:358`), and must not be `runtime-upgrade.pending` or `runtime-upgrade-approval-consumed-*`/`runtime-upgrade-completed-*`. Use a distinct prefix:

```bash
S=/var/lib/omarchy/t2-hibernate-product
for name in runtime-upgrade-native.py runtime-upgrade-approval.json runtime-upgrade-review.json runtime-upgrade-config.json runtime-upgrade-bootstrap.py runtime-upgrade-image-state.py; do
  if sudo test -e "$S/$name"; then
    sudo test ! -e "$S/prior-e489bab7.$name" || { echo "retained name exists: $name"; false; }
    sudo cp -p -- "$S/$name" "$S/prior-e489bab7.$name"
    sudo cmp -- "$S/$name" "$S/prior-e489bab7.$name" && echo "retained $name"
  fi
done
sudo sync
```

Then install the six new files. Approval last, adapter before approval, so a half-staged state can never run:

```bash
D=/home/jjc/.local/state/codex-mba-autonomous/runtime-upgrade-cf907542
for name in runtime-upgrade-review.json runtime-upgrade-config.json runtime-upgrade-bootstrap.py runtime-upgrade-image-state.py runtime-upgrade-native.py runtime-upgrade-approval.json; do
  sudo install -m 0600 -o root -g root -T -- "$D/$name" "$S/$name"
done
sudo sync
for name in runtime-upgrade-review.json runtime-upgrade-config.json runtime-upgrade-bootstrap.py runtime-upgrade-image-state.py runtime-upgrade-native.py runtime-upgrade-approval.json; do
  sudo cmp -- "$D/$name" "$S/$name" && sudo stat -c '%n %U:%G %a links=%h size=%s' "$S/$name"
done
sudo sha256sum "$S"/runtime-upgrade-{review.json,config.json,bootstrap.py,image-state.py,native.py,approval.json}
```

Expected: six `cmp` successes, each file `root:root 600 links=1`, and hashes equal to the approval's pins (`new_review`, `new_config`, `new_bootstrap`, `new_image_state`, `adapter_sha256`) and to the auditor's list. Any mismatch: stop and leave the staged files in place; they are inert until H2. Restaging over them happens only after reviewer sign-off, with `install -T`.

## Gate H2: run the adapter

Operator approval required, with the machine on AC, idle, unchanged boot, and no pacman activity. This is the only step that replaces runtime authority.

```bash
sudo -n /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime-upgrade-native.py
```

Invocation facts: the adapter takes no arguments and refuses any (`runtime_upgrade_native.py:612-613`); it requires root, isolated Python and that `__file__` is exactly `STATE/runtime-upgrade-native.py` with private root-owned ancestry (`:114-125`). It re-executes itself under `/usr/bin/systemd-inhibit --what=sleep:shutdown --mode=block` (`:225-227`, `:565-568`) and verifies that inhibitor parent throughout (`:230-255`). The handoff records the previous run used the same form, `sudo -n python3 -I -B` (**unverified** exact text; the handoff summary does not include the full command line). `sudo -n` only works if `sudo` credentials are cached or passwordless; if not, prime the cache first with `sudo -v` in the same terminal rather than dropping `-n` in a script.

What it does, in order: parses the approval and rechecks the unchanged pins and boot id (`:563-564`); verifies old and new reviews, bootstrap bytes and the old runtime tree (`:194-222`); acquires the DB lock and physical-cycle flock (`:572-573`); runs the fixed pre-barrier product check with the staged image-state helper (`:577-580`); then the core `_upgrade_snapshot` (`runtime_deployment.py:295-434`) writes the compatible admission barrier and `runtime-upgrade.pending`, writes the consumed record, renames the old runtime, review, bootstrap and config to their `*-retained-e489bab70e13-before-cf9075424e20*` names, publishes the new review and bootstrap, deploys the new runtime, writes the config, runs the barrier-aware postcheck, writes the completion record, and retires `runtime-upgrade.pending` and then the barrier. The adapter then verifies the tree again, runs an ordinary product admission check with the new runtime, and releases `db.lck` (`:585-594`).

Success: exit status 0 and exactly one line of JSON on stdout (`:609`, `:614`):

```json
{"live_execution": true, "power_operation": false, "review_sha256": "<new_review pin>"}
```

Failure: a Python traceback ending in a `ValueError` or `OSError`, exit status non-zero, possibly with a `lock cleanup failed for /var/lib/pacman/db.lck ...` note (`:539`). A failure before the barrier (approval, pin, precheck, lock) leaves the installed generation untouched; a failure after the barrier retains the veto and evidence and enters bounded recovery (`_restore_veto` `:324-361`, `_retain_recovery` `:371-399`, bound `RECOVERY_BOUND` = 300 s at `:368`). In either case the process exits and the operator stops: **do not run the adapter again**. Go to the failure section.

Preconditions the adapter enforces itself (so a red run tells you which one failed, not that the design is wrong): boot id equals the approval's; opt-in file exists, is empty and mode 0644; hook, qualification, boot policy and `limine.conf` match the `unchanged` pins; no `UPGRADE_PENDING`, barrier, deactivation, maintenance or runtime pending (`runtime_deployment.py:325`, `:378`); `db.lck` absent (created with `O_EXCL`, `:450`); physical lock file present and not held (`:511-514`); no queued power jobs or logind preparation (`boot_policy_native._power_state`, `:202-239`); old `product.check` passes including the power policy; no saved image at the resume page (helper); the old runtime tree still equals the old review. Whether the live host satisfies each of these today is **unverified**.

## Post-upgrade verification (read-only)

Operator approval required (`sudo` read-only). None of these changes state.

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo sha256sum "$S/runtime-deployment-review.json" "$S/runtime-deployment-bootstrap.py" "$S/config.json"
# expect: new_review, new_bootstrap, and 2f66daf8...16aa4f23 (config unchanged)
sudo ls "$S" | grep -E 'retained|completed|consumed|pending'
# expect present: runtime-retained-e489bab70e13-before-cf9075424e20, runtime-review-retained-...json, runtime-bootstrap-retained-...py, config-retained-...json,
#   runtime-upgrade-completed-cf9075424e20.json, runtime-upgrade-approval-consumed-<this approval_id>.json (there is no consumed file for the earlier e489bab7 upgrade; see H0)
# expect ABSENT: runtime-upgrade.pending, source-default-activation.pending, package-maintenance.pending, .runtime-pending
sudo jq -r '.reviewed_commit' "$S/runtime-deployment-review.json"       # cf9075424e2069ff1cf6513e6eb6f3e5ee4a9cdc
sudo jq -r '.reviewed_commit' "$S/runtime/snapshot.json"                # same
sudo /usr/bin/python3 -I -B - <<'PY'
import importlib.util, json
S = "/var/lib/omarchy/t2-hibernate-product"
spec = importlib.util.spec_from_file_location("rd", S + "/runtime/packages/t2-suspend/hibernate/runtime_deployment.py")
rd = importlib.util.module_from_spec(spec); spec.loader.exec_module(rd)
review = json.load(open(S + "/runtime-deployment-review.json"))
rd._verify_tree(rd.Path(S) / "runtime", review["files"]); print("installed tree matches the approved review")
PY
ls /var/lib/pacman/db.lck 2>&1                                       # expect: No such file (the adapter released it)
sudo /usr/bin/python3 -I -B "$S/runtime/packages/t2-suspend/hibernate/update_guard.py"; echo "exit=$?"
# expect exit=1: no maintenance marker yet, so the blanket guard refuses while boot-policy.json exists
#   ("T2 source policy or routine hibernation remains active/incomplete: var/lib/omarchy/t2-hibernate-product/boot-policy.json", update_guard.py:117-146)
sudo test -e "$S/boot-policy.json" && echo "source-default policy still active"
```

Hibernation stays active and the hook still blocks every package transaction at this point. That is expected: the upgrade published runtime code only. `omarchy update` is still blocked. Do not proceed if the verification shows a mixed state (some retained files present, no completion, or a pending file); use the failure section.

## Gate H3: maintenance publisher

Operator approval required. Precondition: post-upgrade verification passed. This is where hibernation is turned off: `boot_policy_native.py maintenance` deactivates the source default (removes `boot-policy.json` and the routine opt-in, restores the retained stock `limine.conf` with `default_entry: 2`), archives the audited resume tuple, and durably writes `package-maintenance.pending` binding the new runtime review (`boot_policy_native.py:445-468`, `boot_policy_transition.py:444-462`). It changes `/boot/limine.conf` but no UKI, EFI variable, kernel or power state. It fails if anything runs on the power side (`_power_state`, `:202`), if `db.lck` exists, or if the runtime-upgrade pending files exist (`boot_policy_transition._runtime_pending:299-306`). It takes no arguments beyond the action name and re-executes itself under a real block inhibitor (`:59-61`, `:449-453`).

```bash
NATIVE=/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
sudo /usr/bin/python3 -I -B "$NATIVE" maintenance
```

Success: exit 0 and one JSON object that includes `"live_execution": true`, `"power_operation": false`, `"qualification_issued": false` and the transition's fields (`boot_policy_native.py:468`, `boot_policy_transition.py:482`); exact remaining field names beyond these were not confirmed here and are **unverified**. Re-entry when the marker already exists returns `"already_inactive": true` (`boot_policy_transition.py:538`). Then verify with the read-only checks of [MAINTENANCE-RUNBOOK.md section 5](MAINTENANCE-RUNBOOK.md): marker present; `boot-policy.json`, `source-default-*.pending` and `/etc/omarchy/t2-hibernate-product.enabled` absent; `default_entry: 2`; guard run exits 0 and silent.

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo ls "$S/package-maintenance.pending" && sudo jq -r '.runtime_review_sha256' "$S/package-maintenance.pending"   # equals new_review
sudo /usr/bin/python3 -I -B "$S/runtime/packages/t2-suspend/hibernate/update_guard.py"; echo "exit=$?"   # expect 0
```

Failure: the publisher leaves the machine either unchanged or in the interrupted state that [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md) section 1 describes (marker plus stale deactivation pending). Re-running the same maintenance command completes that state safely (`completed_interrupted_maintenance: true`); if it refuses, stop for review. Never remove files by hand.

Hibernation remains OFF after H3. The only sanctioned way back is the optional, separately approved gate H5 below, and only from a runtime generation that contains `reactivate`; do not try to re-enable it by hand (do not recreate the opt-in file, do not re-run `activation`).

### After H3: record and check the generation baseline

H3 also archives `generation-baseline.json` next to the maintenance intent (written before the intent and the marker, so a marker never exists without it). It records the qualified generation that was active when maintenance began: running kernel, production/source/restore UKI hashes, module stack, manifest, `config.json` and `qualification.json` digests, driver modules, firmware (hardlinked Apple firmware is accepted and its link count recorded), root control files (out-of-scope symlinks such as the limine enroll hooks recorded as link text only) and the ESP bootloaders `EFI/BOOT/BOOTX64.EFI` and `EFI/limine/limine_x64.efi`. The baseline cannot be amended later; only a new maintenance publication would replace it.

Immediately after H3, run the read-only assessment and keep its output:

```bash
sudo -n /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py assess | tee ~/t2-assess-after-h3.json | jq '{class, busy}'
```

Expected: `class: "unchanged"`. It writes nothing and holds no lock while hashing. If any item reports `unknown` here (for example a root-only control path that still could not be read), record it: that item will stay `unknown` in later assessments, which only keeps reactivation conservative.

## Reboot into the stock entry and verify (between H3 and H4)

H3 makes the stock `Omarchy linux-t2` entry the default again but does not change the running system. Before any package update, the owner reboots once so updates run on the standard boot image with the installed DKMS drivers, not under the hibernation source image's private experimental drivers. An assistant never initiates this reboot.

After the reboot, read-only:

```bash
f=$(ls /sys/firmware/efi/efivars/LoaderImageIdentifier-*); tail -c +5 "$f" | tr -d '\0'; echo   # expect EFI\Linux\omarchy_linux-t2.efi, not mba_t2_hibernation_source.efi
for m in hci_bcm4377 brcmfmac t2bce_core t2bce_vhci t2bce_audio; do echo "$m $(cat /sys/module/$m/srcversion) $(modinfo -F srcversion $m)"; done   # each pair must match (disk drivers loaded)
journalctl -b -u bluetooth-after-wifi --no-pager | grep bt-order   # the stock gate, not the hibernation candidate loader
sudo /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py; echo "exit=$?"   # expect 0
sudo /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py assess | jq '{class, busy}'   # expect unchanged
```

Then test ordinary sleep once on the stock entry (lid close, wait a minute, open). The earlier S3 freezes were specific to the hibernation source image's private drivers; on stock, sleep should resume with keyboard, trackpad, audio, Wi-Fi and Bluetooth working. If it does not, stop and report before updating.

## Gate H4: first package update, then `omarchy update`

Operator approval required for each update. The installed hook now runs the new native guard because the marker exists (`update_guard.main:434-440`, marker branch `:438`); with a valid marker it admits ordinary transactions under the physical lock after the exact inactive validator and a saved-image check.

1. Preconditions: `sudo /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py` exits 0; no `db.lck`; AC power.
2. First update a small, low-risk package that does not touch the kernel, initramfs, modules or bootloader, for example a user-space tool the owner chooses (`sudo pacman -S <small package>`; the exact package is the owner's choice and **not verified** here). Expect the hook line `Checking inactive T2 source boot policy before package changes...` and a normal transaction. Afterwards re-run the guard and require exit 0.
3. Only then run `omarchy update`. If it includes a kernel or `limine` package, the guard's fallback check requires the retained stock config to keep binding the production UKI; see MAINTENANCE-RUNBOOK.md section 3 for an incoherent kernel transaction. Hibernation stays vetoed throughout by the marker.
4. After each transaction re-run the guard (`exit=0`) and the runbook section 5 indicators.

Do not change the boot image or run `limine-mkinitcpio` unless the runbook section 3 gate is followed; kernel updates under maintenance are the case the design tests, and a kernel transaction on this machine ordinarily rewrites boot artifacts, so the owner decides when to include one.

After the first updates, `assess` should report `unchanged` for userspace-only updates, or `requalification-required` once the kernel, modules, firmware, UKIs or bootloader changed. Snapshot entries added to `/boot/limine.conf` by `limine-snapper-sync` do not count as a change. Reactivating hibernation is not part of this procedure (see [RESUME.md](RESUME.md)).

## Gate H5 (optional, later): reactivation

Operator approval required, separately from H0 to H4. Precondition: a runtime generation that contains `reactivate` is installed (the `cf907542` generation this procedure deploys predates it; a later reviewed runtime upgrade is needed first), the maintenance marker exists, and the read-only assessment reports `class: "unchanged"`:

```bash
NATIVE=/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
sudo -n /usr/bin/python3 -I -B "$NATIVE" assess | tee ~/t2-assess-before-h5.json | jq '{class, changed_items, unknown_items, limine}'
```

`reactivate` is not hibernation permission and not requalification. It only re-applies the source default that the H3 deactivation removed, when nothing that the qualification depends on has changed. It re-evaluates the same assessment itself under its own locks, so the output above is a preview, not an authorization.

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" reactivate
```

Do NOT reboot, power-cycle, suspend or hibernate while it runs, and do not interrupt it. Sleep and package updates are vetoed for the whole run (the activation pending, and the maintenance marker until it is retired), but a reboot is not vetoed once the boot configuration line is written.

What it does, in order (every write is preceded by the real logind exclusion check): it refuses unless the preconditions hold; writes `source-default-activation.pending` (protocol `omarchy-t2-package-reactivation-intent-v1`, the runtime upgrade's barrier filename with a different protocol), an archive directory `boot-policy-transitions/<new id>` (intent, policy, comparison, opt-in evidence), `boot-policy.json`; then changes exactly ONE line of `/boot/limine.conf`, `default_entry: 2` to the source entry, on the current bytes (the snapshot region is never rewritten or dropped); creates the routine opt-in; re-verifies the active state; writes `completion.json`; removes the maintenance marker and finally the pending. Success prints canonical JSON with `"reactivated": true`, `"requalification_required": false`, `"live_execution": true`, `"power_operation": false`. Afterwards updates are refused by the blanket guard again (`boot-policy.json` and the opt-in exist), exactly as before H3; deactivate again with `maintenance` before any update.

Refusals (all with zero writes; the marker stays and updates stay allowed):

| Message | Meaning |
| --- | --- |
| `requalification required: <items>` | Something the qualification depends on changed (kernel, UKIs, module stack, manifest, config, qualification, driver modules, firmware, control files, bootloader, or the stock Limine projection). Reactivation is not possible; the generation must be requalified. |
| `compatibility unknown: <reason>` | The baseline is missing, invalid or an item could not be read. Nothing is assumed; reactivation is refused. |
| `Unrelated Limine drift` | `/boot/limine.conf` differs from the retained backup by more than the snapshot region. |
| `Interrupted deactivation/maintenance publication preserved` | A deactivation pending exists: finish the interrupted maintenance publication first. |
| `Runtime deployment/upgrade pending` | A runtime upgrade is pending or interrupted; it and reactivation exclude each other. |
| `Existing source-default policy, opt-in or pending` | Source-default state already exists (or the shared pending name holds something that is not a reactivation intent, which is never adopted). |
| a busy lock, EFI override, saved hibernation image or reviewed-runtime mismatch | The same fail-closed checks as maintenance; nothing is written. |

Interrupted or failed run: re-run `reactivate`. It authenticates its own pending and then rolls the boot configuration line, the opt-in and the policy back (never forward past the boot-config write) and re-verifies the inactive maintenance state; if the completion was already written it re-checks and only finishes retiring the marker and pending. See [MAINTENANCE-RUNBOOK.md section 6](MAINTENANCE-RUNBOOK.md). After a rollback a fresh attempt is allowed. Never delete the pending or any archive file by hand.

Residual gap: userspace packages outside the UKI (systemd, logind and others) are not assessed items. Only the effective `systemd-hibernate.service` route is checked, so an update to them that the assessment does not see is not covered by `unchanged`.

## Gate H6: requalify and rebind a new generation

Operator approval required, separately for each sub-gate; a prior approval, a green fixture test or an automatic goal continuation is not approval. Precondition: the machine is in inactive package maintenance and `assess` reports `requalification-required` after a kernel update (RESUME.md, 7.2.7 incident). Rationale and state machine: [REBIND-DESIGN.md](REBIND-DESIGN.md); stuck states: [MAINTENANCE-RUNBOOK.md section 9](MAINTENANCE-RUNBOOK.md) (retire) and [section 10](MAINTENANCE-RUNBOOK.md) (rebind). Nothing here is hardware evidence. H6d to H6f and H6h to H6i are attended hardware actions; follow AGENTS.md hardware safety: never restage a replacement `.linux`, never reuse a consumed guard, never repeat a failed vector, keep production `.linux` and `.cmdline` byte-for-byte in every private UKI, and serialise every boot, EFI, module-load and power step. Updates stay allowed for the whole sequence.

The order matters. The runtime upgrade comes FIRST because the installed runtime's guard validates the maintenance chain from the receipt file at its fixed path, and retiring the old pair removes that file; the runtime deployed at H6a resolves it from the custody files the retire step leaves (`pair-retired-receipt.json` plus `pair-retirement.json`, shared contract `hibernate/pair_custody.py`). Live-state note: the machine's current assessment (`recovery-7.2.7-*/assess-7.2.7.json`) is `requalification-required` with `kernel`, `production_uki` and `control_inventory` changed and `driver_modules`/`firmware` unknown; `rebind` accepts that overall class (changed items take precedence over unknown ones) and only refuses a class of `unknown` or `unchanged`.

Common variables used below:

```bash
S=/var/lib/omarchy/t2-hibernate-product
NATIVE=$S/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
EXP=$S/runtime/packages/t2-suspend/experiments        # root-owned, review-pinned copy installed by H6a; never run privileged Python from the workspace
REL=7.2.7-arch1-Watanare-T2-2-t2
CAND=/home/jjc/.local/state/codex-mba-autonomous/t2bce-7.2.7-hardening/candidate-7.2.7-h1
WORK=/home/jjc/.local/state/codex-mba-autonomous/gen-7.2.7                # new private build tree, outside the ESP
```

| Step | Action |
| --- | --- |
| H6a | Maintenance runtime upgrade |
| H6b | Retire the old pair |
| H6c | Build the new pair (sudo builders) and audit it |
| H6d | Stage it |
| H6e | Attended ordinary boots, `test_resume`, S4 vector |
| H6f | Boot the new source entry; generation trial (`trial.py --generation`) |
| H6g | Issue the qualification (bound to the trial's record), config and boot policy review |
| H6h | `rebind` |
| H6i | One routine S4 |

### H6a: maintenance runtime upgrade

Stage and run exactly as H1 and H2 do, with these differences. The approval protocol is `omarchy-t2-runtime-upgrade-maintenance-approval-v1`. The seven `expected` pins and a fresh UUID4 `approval_id` are as for v2 (`old_config` equals `new_config`, because the configuration is untouched). `unchanged` is exactly `{qualification, hook, marker}`: the SHA-256 of `qualification.json`, of the installed pacman hook and of the exact `package-maintenance.pending` bytes. Limine, boot policy and opt-in are not pinned (boot policy and opt-in must be absent). The new runtime must contain commit `1d1528fb` (volatile state out of the baseline), the rebind engine, `pair_custody.py` and the custody-aware guard. Adapter command (no arguments):

```bash
sudo -n /usr/bin/python3 -I -B "$S/runtime-upgrade-native.py"
```

Verify: `runtime-rebind-<new12>.json` and the two `*.before-runtime-<new12>.json` copies exist in `$S/boot-policy-transitions/<maintenance id>/`, `jq -r .runtime_review_sha256 "$S/package-maintenance.pending"` equals the new review digest, the guard exits 0 (`sudo /usr/bin/python3 -I -B $S/runtime/packages/t2-suspend/hibernate/update_guard.py`) and `sudo /usr/bin/python3 -I -B "$NATIVE" assess | jq '{class, changed_items, unknown_items}'` still reports `requalification-required`. After the volatile-state fix `control_inventory` differs only by real control files; `driver_modules` and `firmware` stay `unknown` until rebind (the qualified 7.2.6 module directory is gone). Failures: MAINTENANCE-RUNBOOK.md section 10, "After a runtime upgrade under maintenance that failed". A failure leaves the barrier `source-default-activation.pending` (plus `runtime-upgrade.pending` only if it stopped after the barrier's first guard) and vetoes updates; the failed approval is never re-run. The first live attempt (approval `c6051717`, commit `0807b7d7`) stopped at its first guard because the adapter's guard refused the core's own barrier; a new approval with the `leftover` field adopts that unconsumed barrier under strict no-movement proof (same section, "Adopting the barrier of an earlier, unconsumed approval"). Optional approval field for that case only: `"leftover": {"approval_id": <earlier UUID4>, "intent_sha256": <SHA-256 of the exact barrier bytes>}`.

### H6b: retire the old pair

```bash
P=$EXP/stage-hibernation-uki-pair.py
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change --dry-run     # read-only plan
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change               # attended; re-run if interrupted
```

Preconditions and recovery: MAINTENANCE-RUNBOOK.md section 9. Journal order: archive, journal, custody, Limine, images, backup, receipt, record. The custody files are written before the live receipt is removed, so the guard keeps validating at every instant. Verify: `sudo jq . $S/pair-retirement.json` (exactly `protocol`, `retired_receipt_sha256`, `source_sha256`, `restore_sha256`), `sudo sha256sum $S/pair-retired-receipt.json` equals both `retired_receipt_sha256` and `jq -r .staged_receipt_sha256 $S/package-maintenance.pending`, the guard exits 0, `assess` still `requalification-required`. Undo only an interrupted retirement with `retire-rollback` (it removes the custody it wrote after restoring the receipt).

### H6c: build the new pair and audit it

Kernel-bound helper modules must be rebuilt for `$REL` and re-pinned before any image is built; a module built for 7.2.6 has the wrong vermagic and the wrong hash. Build each out of tree against `/usr/lib/modules/$REL/build` from its directory under `$EXP` (each has a `Kbuild` and README), record `sha256sum` and `modinfo -F srcversion` and `modinfo -F vermagic`, and have the pins independently reviewed:

| Helper (source directory under `$EXP`) | Where its pin lives |
| --- | --- |
| Cold PCI guard, `hibernate-cold-pci-guard` (`mba_hibernate_cold_pci_guard`) | In the tree: `GUARD_SHA256` and `GUARD_SRCVERSION` in `cold-pci-restore-protocol.py` (lines 13 and 14), enforced by `build-hibernation-candidate-uki.py` and the pair audit. srcversion normally does not change without a source change; the sha256 does with the kernel. Update both in a reviewed commit BEFORE building; also the pre-arch guard flags below |
| Restore marker v2, `hibernate-efi-restore-marker` (`mba_hibernate_efi_restore_marker`) | Not in the tree: passed as `--expected-restore-marker-sha256` and `--expected-restore-marker-srcversion` to the candidate builder (with `--restore-marker-version v2`) and as `--expected-restore-efi-marker-sha256`, `--expected-restore-efi-marker-srcversion`, `--restore-efi-marker-version v2` to the S4 runner; recorded in the built images' `provenance.json` |
| Postwrite marker v3, `hibernate-efi-postwrite-marker` (`mba_hibernate_efi_postwrite_marker`) | The product config's `marker_pin` `{sha256, srcversion, vermagic, variable_version: "v3"}` (vermagic's first token must be `$REL`, checked by `host_backend.validate_static_inputs`), the trial authorization's `marker_pin`, and `--postwrite-efi-marker-module`, `--postwrite-source-marker-version v3`, `--expected-postwrite-efi-marker-sha256/-srcversion` on the S4 runner |
| Cold pre-cpu, pre-syscore, pre-arch and pci-pre-arch modules and their header helpers | Only if the pair profile uses them: their `--expected-cold-*` flags (builder `--help` lists all); hard-coded historical pins such as `SOURCE_MODULE_SHA256` in `audit-cold-pre-cpu-return.py` are for the specific old binaries and are not valid for 7.2.7 |

The candidate `$CAND` (patches 0005 to 0017, `candidate-7.2.7-h1`, `provenance.json` records `hardware_qualified: false`) supplies the t2bce modules. Its module file hashes are not reproducible; identify a rebuild by srcversion (core `E6502516231074FB1ADB781`, dma `D8292CC3FFC947C39023071`, vhci `D6A4F0C4742C9FD289568DF`, audio `5D7F99F76022CA6E84DFB8C`, ave `3B8513911A86C7A1E4FEE5A`). The builders run as root so mkinitcpio can embed the unlock key. Build source and restore images into a NEW private directory each, outside the ESP; the production `.linux` and `.cmdline` are read from the current production UKI and preserved byte-for-byte:

```bash
sudo /usr/bin/python3 -I -B "$EXP/build-hibernation-source-uki.py" --candidate-source "$CAND" \
  --production-uki /boot/EFI/Linux/omarchy_linux-t2.efi --kernel-release "$REL" --output "$WORK/pair-source" --experiment-id gen-7.2.7-source
sudo /usr/bin/python3 -I -B "$EXP/build-hibernation-candidate-uki.py" --candidate-source "$CAND" \
  --production-uki /boot/EFI/Linux/omarchy_linux-t2.efi --kernel-release "$REL" --output "$WORK/pair-restore" --experiment-id cold-pci-guard-fullrestore-v1 --minimal-restore-devices \
  --restore-marker-module "$WORK/mba_hibernate_efi_restore_marker.ko" --restore-marker-version v2 \
  --expected-restore-marker-sha256 <sha256> --expected-restore-marker-srcversion <srcversion> \
  --cold-pci-restore-guard-module "$WORK/mba_hibernate_cold_pci_guard.ko" \
  --expected-cold-pci-restore-guard-sha256 <GUARD_SHA256> --expected-cold-pci-restore-guard-srcversion <GUARD_SRCVERSION> \
  <the remaining pair-profile --cold-pci-* flags from the previous generation's provenance.json>
sudo /usr/bin/python3 -I -B "$EXP/audit-hibernation-uki-pair.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore"
```

The restore builder enforces `--experiment-id cold-pci-guard-fullrestore-v1` and requires `--minimal-restore-devices` with the cold-PCI flags. Pair outputs go to `$WORK/pair-source` and `$WORK/pair-restore` because `$WORK/source` holds the H6a runtime export. Take the exact restore-side flag set from the qualified 7.2.6 pair's `provenance.json` (unchanged flags stay unchanged; only kernel-bound module paths and pins change). Independent audit of the pair before staging. This is a structural audit, not proof that the pair boots.

### H6d: stage the new pair

```bash
sudo /usr/bin/python3 -I -B "$P" stage --source "$WORK/pair-source" --restore "$WORK/pair-restore"
sudo /usr/bin/python3 -I -B "$P" verify
```

`stage` refuses while an old receipt or image exists (H6b removed them) and writes the new receipt, backup and Limine block.

### H6e: attended ordinary boots, `test_resume` and S4 vector

Owner attended, serialised, one at a time. The stock `Omarchy.linux-t2` entry stays the default; the staged one-shots are armed and consumed by the runners.

```bash
sudo /usr/bin/python3 -I -B "$P" arm-source                                    # then reboot into the source entry (attended)
sudo /usr/bin/python3 -I -B "$EXP/verify-hibernation-uki-pair-source.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore" --role source
sudo /usr/bin/python3 -I -B "$EXP/run-hibernation-uki-pair-test-resume.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore" \
  --physical-input-evidence <evidence> --validate-only --operator-attended
sudo /usr/bin/python3 -I -B "$EXP/run-hibernation-uki-pair-test-resume.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore" \
  --physical-input-evidence <evidence> --execute --operator-attended --expected-source-sha256 <source sha256>
sudo /usr/bin/python3 -I -B "$EXP/run-hibernation-uki-pair-s4.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore" \
  --test-resume-proof-source <proof> --disk-mode platform --marker-backend postwrite-efi --operator-attended --validate-only \
  --postwrite-efi-marker-module "$WORK/mba_hibernate_efi_postwrite_marker.ko" --postwrite-source-marker-version v3 \
  --expected-postwrite-efi-marker-sha256 <sha256> --expected-postwrite-efi-marker-srcversion <srcversion> \
  --restore-efi-marker-module "$WORK/mba_hibernate_efi_restore_marker.ko" --restore-efi-marker-version v2 \
  --expected-restore-efi-marker-sha256 <sha256> --expected-restore-efi-marker-srcversion <srcversion>
# the same command with --execute --expected-pair-vector <vector> consumes the durable pair guard: run only with separate explicit approval
sudo /usr/bin/python3 -I -B "$P" disarm-restore                                # only when the runner says an owned restore one-shot remains
```

Each `--execute` is a one-time hardware vector: a failed or ambiguous attempt is terminal, is preserved as evidence and is never repeated. Ordinary boot success does not establish S4 safety. Use the runners' own `--help` for the exact evidence arguments.

### H6f: boot the new source entry, then the generation trial

The generation trial is a one-use, unqualified hardware run whose durable terminal record is what the qualification must later point at. Its readiness check requires the current boot to be the staged source entry: `LoaderEntrySelected` must be `MBA-T2-hibernation-source-<first 16 hex of the source sha256>` (`trial.verify_readiness`), AC power online, the source marker module not loaded and no EFI stage or override variables. So first, attended, boot into the source entry (the one-shot armed by `arm-source` in H6e is consumed by that boot; re-arm it if this is a later session) and confirm:

```bash
sudo /usr/bin/python3 -I -B "$P" arm-source && systemctl reboot    # attended; select nothing manually: the one-shot picks the source entry
sudo /usr/bin/python3 -I -B "$EXP/verify-hibernation-uki-pair-source.py" --source "$WORK/pair-source" --restore "$WORK/pair-restore" --role source
```

The trial's two inputs are written by the operator or orchestrator as root, never by this code, from audited evidence, root-owned 0600:

- `config.json` (schema `omarchy-t2-explicit-trial-config-v1`, exact keys `source_directory restore_directory production_uki source_tree marker_file marker_pin manifest audited_details_sha256 staged_receipt_sha256 retire_slots`). Provenance: the artifact paths are the private build outputs of H6c; `manifest` and `audited_details_sha256` are what the audit derives (`trial.py inspect` prints `manifest_sha256`; a mismatch refuses); `staged_receipt_sha256` is the live NEW receipt's hash; `marker_file`/`marker_pin` are the postwrite marker v3 built and pinned for this kernel in H6c. `retire_slots` MUST be `true`: only a retiring trial reaches the terminal `reconciled` cycle that H6g and `rebind` require.
- `authorization.json` (protocol `omarchy-t2-product-one-use-trial-v1`, `qualified: false`). Provenance: written by the operator after reviewing the audit, with `manifest_sha256` and `audited_details_sha256` of this pair, `original_boot_id` equal to the CURRENT boot id (`/proc/sys/kernel/random/boot_id`), a fresh `authorization_id`, the same `marker_pin`, and `physical_acceptance` `{boot_id, authorization_id, accepted: true, method: "operator-attended-cold-power"}` recording the operator's explicit attended acceptance. It is permission for one run, not qualification.

Provision the fresh root named by the first 12 hex digits of the manifest digest (`TX.digest(manifest)`) with real `0700` directories; the original trial root and its consumed guard are never reused:

```bash
G=/var/lib/omarchy/t2-hibernate-trial/generations/<manifest12>
sudo install -d -m 0700 -o root -g root "$G" "$G/guards" "$G/ledger" "$G/archives"
sudo install -m 0600 -o root -g root -T -- <reviewed>/trial-config.json "$G/config.json"
sudo install -m 0600 -o root -g root -T -- <reviewed>/trial-authorization.json "$G/authorization.json"
T=$S/runtime/packages/t2-suspend/hibernate/trial.py
sudo /usr/bin/python3 -I -B "$T" --generation <manifest12> inspect
sudo /usr/bin/python3 -I -B "$T" --generation <manifest12> execute            # one use; separate explicit approval
```

It refuses if the audited manifest is not the directory's, if the manifest is the original trial's, or if this generation's guard is already consumed. `repair-constructor` never applies to a generation. After a successful run the durable terminal record is `$G/ledger/cycle-<cycle id>.json` in state `reconciled` (plus the consumed `$G/guards/trial-consumed.json` naming the same cycle and an unblocked `$G/ledger/state.json`). A failed or ambiguous trial is terminal for that generation: never repeat its vector.

### H6g: issue the qualification, config and boot policy review

Externally, after independent review of the trial record. The qualification is still written by the operator or orchestrator, but it can only point at a real successful trial: `rebind` requires `evidence_sha256` to equal the SHA-256 of the exact bytes of `$G/ledger/cycle-<cycle id>.json`:

```bash
sudo sha256sum "$G"/ledger/cycle-*.json          # the value for evidence_sha256
```

Qualification: `{"protocol": "omarchy-t2-product-cycle-v1", "manifest_sha256": <digest of the new manifest>, "evidence_sha256": <that sha256>, "qualified": true}`. Product config: schema v2 for the new pair (`staged_receipt_sha256` is the live NEW receipt's hash, the v3 `marker_pin`, `power_policy` present). Boot policy review: `boot_policy.prepare` output for the new receipt with `approved: true`. Stage all three root-owned 0600, under distinct names:

```bash
for f in rebind-config.json rebind-qualification.json rebind-boot-policy-review.json; do
  sudo install -m 0600 -o root -g root -T -- "<reviewed dir>/$f" "$S/$f"
done
sudo sync
```

### H6h: `rebind`

Read-only checks first (MAINTENANCE-RUNBOOK.md section 10), then:

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" rebind
```

Do not reboot, power-cycle, suspend or hibernate while it runs. `rebind` reads and validates the generation trial record (private real directories, no symlinks, reconciled cycle for this manifest, consumed guard naming it, evidence digest) before any write. SIGHUP, SIGTERM and SIGINT (a dropped ssh session, Ctrl-C) are converted to an exit that releases `db.lck`; the pending veto stays and re-running recovers. SIGKILL or power loss can leak `db.lck`: confirm with `pgrep -ax pacman` that no pacman runs, then follow MAINTENANCE-RUNBOOK.md section 4 and re-run `rebind`. Success prints canonical JSON with `"rebound": true`, `"requalification_required": false`, `"live_execution": true`, `"power_operation": false`. Afterwards `config.json`, `qualification.json`, `boot-policy-review.json`, `limine.conf.before-source-default` and `boot-policy.json` are the new generation's, the opt-in exists, the marker and pending are gone and the old set is archived under `boot-policy-transitions/<id>`. Interrupted: re-run it. While the machine is ACTIVE after `rebind`, pacman is blocked by the guard (`boot-policy.json` and the opt-in exist) until the next `maintenance` publish, exactly as before H3; run `maintenance` before any package update.

### H6i: one routine S4

Attended, separately approved: the first `product.py hibernate` cycle under the new manifest (via `omarchy-t2-hibernate-product.service` or `sudo /usr/bin/python3 -B $S/runtime/packages/t2-suspend/hibernate/product.py check` first, then `hibernate`). The product ledger chains it to the previous terminal cycle. Until it passes, treat the generation as bound but unproven.

## Failure and rollback handling

General rules: fail closed. There is no automatic retry, no replay and no rollback command. The retained `*-retained-e489bab70e13-before-cf9075424e20*` files preserve the old runtime, review, bootstrap and config as evidence, but restoring them is a separately reviewed operation, not part of this procedure. Do not run the adapter or publisher a second time to "finish" a run. Never replay consumed deployment `4125726a-4847-4802-a821-953e6abe995a` or any approval whose consumed file exists: a replay is refused before any lock because the installed review no longer matches `old_review` (`runtime_upgrade_native.py:198`, in `_verified_engines` before `_locks`; the consumed-approval file is checked again at `runtime_deployment.py:378-380`), and even if it were not, replaying is forbidden.

| Where it failed | State | Action |
| --- | --- | --- |
| Prerequisites, build, compute, approval, review | Host untouched | Fix and regenerate; a changed approval needs a new UUID4 and a new review pass |
| H0 | Host untouched | Stop; any mismatch of installed pins or a pending marker is a stop, not something to work around |
| H1 | Staged files only, inert | Leave them; diagnose; restage only after the reviewer signs off. Retained copies (`prior-e489bab7.*`) must not be deleted |
| H2, before barrier (`pin`, `unchanged`, `guard`, lock, precheck error) | Installed generation untouched, `db.lck` released | Read the traceback; the approval is not consumed until the barrier exists. Fix the cause, and if the approval file changed, get a new UUID4 and a re-review |
| H2, after the barrier | Barrier `source-default-activation.pending` and `runtime-upgrade.pending` retained; consumed and possibly completion files written | Keep everything. Reconcile read-only: list `STATE`, compare to the verification section. The adapter's recovery retains the veto durably (`runtime_upgrade_native.py:324-361`); never delete either pending file. Hibernation stays vetoed. Escalate for review. |
| H2, `db.lck` left over | Our lock may remain | MAINTENANCE-RUNBOOK.md section 4: remove only after the listed checks pass |
| H3 | Marker written or not | MAINTENANCE-RUNBOOK.md sections 1 to 3 and 5 |
| H4 | Update aborted by the guard before mutation | Read the guard message; runbook sections 2 and 3; never bypass the hook |
| H5 | Refused with zero writes, or interrupted with an activation pending | Refusal: read the message above, nothing changed. Interrupted: do not reboot; re-run `reactivate` (MAINTENANCE-RUNBOOK.md section 6) |
| H6a | Refused before the barrier, or barrier retained | As H2; the maintenance recovery also settles the marker binding and always retains old-form copies beside it; a barrier left by an earlier unconsumed approval is adopted only by a new approval that pins it (`leftover`), never removed by hand (MAINTENANCE-RUNBOOK.md section 10) |
| H6b | Refused, or interrupted retirement | MAINTENANCE-RUNBOOK.md section 9: re-run, or `retire-rollback` |
| H6h | Refused with zero writes, or interrupted with a rebind pending | Refusal: read the message. Interrupted: do not reboot; re-run `rebind` (MAINTENANCE-RUNBOOK.md section 10) |

If the machine loses power, hangs or reboots at any gate, do not assume state: on the next boot, reconcile with the handoff, `git`, and the read-only inventory in the runbook before any further action, and do not try to complete the gate.

## What NOT to do

From AGENTS.md "T2 Hibernation Hardware Safety", RESUME.md and the runbook:

- No reboot, restage or booting of any replacement-kernel image; never touch the failed marker-source UKI SHA-256 `974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd`, the rejected v1/v2 images or another replacement-kernel image. Any private UKI must preserve production `.linux` and `.cmdline` byte-for-byte via the pair stager. This procedure never stages one.
- No S3, S4, hibernate, suspend, poweroff or reboot as a test of this procedure. A successful ordinary boot does not show that S4 or cold restoration is safe; nothing here establishes that.
- Preserve consumed PM guards and consumed approvals; do not repeat a failed hardware vector or replay a consumed deployment.
- Do not run privileged Python from the writable workspace or from `$D`. Only the root-private staged files under `STATE` run as root; `$D/source` is read as inventory and copy input only.
- Do not delete, edit, "tidy" or hand-create anything under `STATE`, and do not edit `maintenance-resume.json`, the marker or any archive file.
- Do not disable, remove or bypass the pacman guard hook, or use `--noscriptlet` or `--hookdir` tricks.
- Do not reactivate hibernation by hand after H3; the only sanctioned path is gate H5 (`reactivate`), and never reboot while it runs.
- Do not copy embedded unlock assets into GitHub, logs or test guests.
- Do not deploy a dev-tree copy, an untracked file, or a commit other than the one the review was computed from. If `HEAD` moves, the approval is for the old commit, not the new one.
- Do not treat a passing fixture, VM or audit as permission to run a gate. The operator's explicit approval at each gate is the only permission.

## Unverified facts (checklist for the operator and reviewers)

1. That live `STATE` still holds exactly `947f0ce9...`/`85b33df9...`/`2f66daf8...` as installed review, bootstrap and config (root-only).
2. Whether the previous upgrade's fixed-name staged files, completion and consumed records still exist and under what names.
3. Current `qualification.json`, `boot-policy.json` and `/boot/limine.conf` hashes and whether they equal the prior approval's pins.
4. That the old review's hook entry equals the installed hook (the installed hook itself matches `0491dcf7...`).
5. Live power state: AC online or at least 30 percent, ledger reconciled, no EFI overrides, no saved image.
6. That the physical-cycle lock file exists and is free.
7. That the installed `systemd-hibernate` drop-in and effective `ExecStart` satisfy the maintenance route check.
8. The full JSON output shape of H3 beyond the fields cited, and the exact text of the previous adapter invocation.
9. The `omarchy update` package set for H4 and whether it includes kernel packages.
