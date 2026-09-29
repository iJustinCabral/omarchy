# Runtime deployment procedure: e489bab7 to 28774823

Operator procedure for deploying the audited update-survival source (branch `fix-t2-vintage-mac-support`, reviewed commit `28774823666bd39a3bc5714e02f1cd07045becd5`) to the live MacBookAir9,1, whose installed hibernation runtime is generation `e489bab70e13bfcbbfacc8811a6f6093e7973dd0`. Companion documents: [RESUME.md](RESUME.md) (state and task list), [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md) (fail-closed stuck states after gate H3), [HIBERNATION.md](HIBERNATION.md) (evidence), [AGENTS.md](../../AGENTS.md) (hardware safety rules).

Status: **draft procedure, not approved for execution.** Nothing here has been run against the live machine. Every gate below (H0 to H4) needs its own explicit operator approval at the moment it is reached; a prior approval, an automatic goal continuation or a green fixture test is not approval. Facts that could not be confirmed from the repository or from user-readable files are marked **unverified**.

## Scope and non-goals

This procedure replaces the root-private runtime snapshot at `/var/lib/omarchy/t2-hibernate-product/runtime` (plus its review and bootstrap authority) with the reviewed source, then moves the machine into inactive package maintenance so that ordinary `pacman`/`omarchy update` transactions can run. It deploys runtime code only.

It does NOT: build, stage, install or boot any UKI, `.linux`, `.cmdline`, EFI variable, kernel or module; change `qualification.json`, `config.json` or the source and restore images; run any S3, S4 or other power transition; reactivate hibernation (RESUME.md task 4 is not implemented); or deploy the S3 fix (RESUME.md task 6). Gate H3 does rewrite `/boot/limine.conf` back to the retained stock configuration and removes the routine opt-in and active policy; that is a boot-configuration change (not a boot-image change) and is called out at that gate. Hibernation stays OFF after H3 by design. That is the intended fail-safe.

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
| Completion record | `runtime-upgrade-completed-<first 12 hex of new commit>.json` = `runtime-upgrade-completed-28774823666b.json` | `runtime_deployment.py:377`, `:421` |
| Retained names | `runtime-retained-e489bab70e13-before-28774823666b`, `runtime-review-retained-e489bab70e13-before-28774823666b.json`, `runtime-bootstrap-retained-e489bab70e13-before-28774823666b.py`, `config-retained-e489bab70e13-before-28774823666b.json` | `runtime_deployment.py:372-376` |

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

Stop and ask for review if any check differs from its expected output. Unknown means stop. Never retry a failed gate by repeating it: recovery for H2 and H3 is read-only diagnosis first (see the failure section). Never reboot, power-cycle, suspend or hibernate the machine at any point of this procedure.

### Do not create snapshots before H3

This applies to the installed runtime (`e489bab7`) and to any deployed generation that predates the snapshot-blind Limine comparison; the reviewed source ignores the snapshot region while hibernation is active, but it is not installed until H2.

Until H3 has completed, do not run `omarchy update`, `omarchy-snapshot` or `snapper create`, and do not delete snapshots. `omarchy update` creates a Snapper snapshot before pacman runs (and before the hibernation guard refuses the transaction), and the enabled `limine-snapper-sync` watcher then rewrites the snapshot region of `/boot/limine.conf`. While hibernation is active, the product and the H3 deactivation require `/boot/limine.conf` to equal the staged pair bytes exactly (`stage-hibernation-uki-pair.py` `verify_staged`, only `default_entry` may differ), so any such rewrite makes H3 refuse (fail closed, hibernation unavailable) until reviewed. After H3, snapshot churn is expected and admitted: the maintenance checks only read `default_entry` and the stock `//linux-t2` entry binding, never the snapshot region (verified with fixture and VM tests, `b2dbf51f`).

## Prerequisites (read-only, unprivileged)

Run from the repository. Every command is read-only. Reconcile before proceeding, as AGENTS.md "T2 Hibernation Hardware Safety" requires.

```bash
cd /home/jjc/Projects/MBA_9_1
git rev-parse HEAD                      # expect 28774823666bd39a3bc5714e02f1cd07045becd5, or a descendant if only docs changed
git merge-base --is-ancestor 28774823666bd39a3bc5714e02f1cd07045becd5 HEAD && echo "reviewed commit is in history"
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
C=28774823666bd39a3bc5714e02f1cd07045becd5
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
sudo bash -c 'cd /var/lib/omarchy/t2-hibernate-product && shopt -s nullglob && ls -la runtime-upgrade* source-default-*.pending package-maintenance.pending .runtime-pending *retained*28774823* runtime-upgrade-completed-28774823666b.json 2>&1'
# expect: only the previous upgrade's retained/staged names described in H1 (if any); NO *.pending, NO .runtime-pending, NO *28774823* names
sudo flock -n /var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock true && echo "physical lock free"
sudo test -f /var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock && echo "lock file exists"
```

Expected (all **unverified** until run):

- `runtime-deployment-review.json` = `947f0ce9...2ee0d`, `runtime-deployment-bootstrap.py` = `85b33df9...23248`, `config.json` = `2f66daf8...16aa4f23`.
- Present in `STATE`: the previous upgrade's fixed-name files (`runtime-upgrade-native.py` = adapter `460ac3da...482e`, `runtime-upgrade-approval.json`, `runtime-upgrade-review.json`, `runtime-upgrade-config.json`, `runtime-upgrade-bootstrap.py`), plus `runtime-upgrade-completed-e489bab70e13.json` and `runtime-upgrade-approval-consumed-4125726a-4847-4802-a821-953e6abe995a.json` (the consumed deployment). Whether the previous staged files were kept, and under what names, is **unverified**; the handoff says they were staged and the adapter run, not that they were retained.
- Absent: `runtime-upgrade.pending`, `source-default-activation.pending`, `source-default-deactivation.pending`, `package-maintenance.pending`, `.runtime-pending`, and `/var/lib/pacman/db.lck`.
- `qualification.json`, `boot-policy.json` and `/boot/limine.conf` hashes; record them. The prior approval pinned `ffa9bc82...fe64`, `a6e406ec...2177` and `aba687f2...65b7` for these; they may legitimately differ now if boot policy or `limine.conf` changed since. Whatever H0 prints becomes the approval's `unchanged` values; a difference from the prior values must be explained before proceeding.

Stop if any pending marker exists, if `old_*` hashes differ from the pins above, or if `git` shows the consumed deployment `4125726a-4847-4802-a821-953e6abe995a` is not the last upgrade recorded in the handoff.

Also confirm the boot configuration still matches the staged pair exactly, using the installed runtime's read-only stager verify (it loads the receipt and runs `verify_staged`; it writes nothing):

```bash
sudo -n /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/experiments/stage-hibernation-uki-pair.py verify >/dev/null && echo "staged limine.conf verified"
```

If it fails, stop: the snapshot region or another part of `/boot/limine.conf` changed while hibernation was active, and H3 would refuse. Do not edit the file by hand; this needs review. The stager is part of the installed runtime tree (`runtime_deployment.TREES` at `e489bab7` includes `packages/t2-suspend/experiments`).

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
  "source_directory": "/home/jjc/.local/state/codex-mba-autonomous/runtime-upgrade-28774823/source",
  "reviewed_commit": "28774823666bd39a3bc5714e02f1cd07045becd5",
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

1. Re-export `git archive 28774823...` independently and compare it with `$D/source` (`diff -r`, expecting no difference apart from bytes not included in the export).
2. Recompute `inventory()` from the auditor's export and require `sha256` of the review file to match, byte for byte (`cmp`).
3. Recompute `adapter_sha256`, `new_bootstrap`, `new_image_state` from `git show 28774823:<path> | sha256sum` and require them to equal both the approval and the review's file entries.
4. Confirm `old_config == new_config` and `new_config` equals the digest of the staged `runtime-upgrade-config.json`.
5. Confirm the `unchanged` values against H0 output produced by the operator (not by the author).
6. Confirm `approval_id` is a fresh UUID4, distinct from `4125726a-4847-4802-a821-953e6abe995a` and from any consumed id printed at H0, and that `current_boot_id` equals the live boot id.
7. Read the diff `e489bab7..28774823` for `packages/t2-suspend/hibernate` and `experiments` and confirm it matches the audited checkpoint in RESUME.md (this needs the auditor to re-run `git diff --stat`, not trust this document).
8. Confirm the six files in `$D` are exactly the six that H1 will install and that no extra byte has been added (the staged file set is exactly the six names in the reference table).

Record the auditor's result next to the approval. A mismatch anywhere blocks H1; regenerate everything rather than editing a file in place.

## Gate H1: root staging with readback

Operator approval required. Writes only to `STATE`; the runtime is untouched and the machine keeps the installed blanket guard hook. Nothing here executes staged code.

First retain the previous upgrade's fixed-name files (only those that exist; the check at H0 tells which). The retained names must not begin with `runtime-retained-`, `runtime-review-retained-`, `runtime-bootstrap-retained-` or `config-retained-`, because the adapter's recovery scans for those prefixes (`runtime_upgrade_native.py:358`), and must not be `runtime-upgrade.pending` or `runtime-upgrade-approval-consumed-*`/`runtime-upgrade-completed-*`. Use a distinct prefix:

```bash
S=/var/lib/omarchy/t2-hibernate-product
for name in runtime-upgrade-native.py runtime-upgrade-approval.json runtime-upgrade-review.json runtime-upgrade-config.json runtime-upgrade-bootstrap.py; do
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
D=/home/jjc/.local/state/codex-mba-autonomous/runtime-upgrade-28774823
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

What it does, in order: parses the approval and rechecks the unchanged pins and boot id (`:563-564`); verifies old and new reviews, bootstrap bytes and the old runtime tree (`:194-222`); acquires the DB lock and physical-cycle flock (`:572-573`); runs the fixed pre-barrier product check with the staged image-state helper (`:577-580`); then the core `_upgrade_snapshot` (`runtime_deployment.py:295-434`) writes the compatible admission barrier and `runtime-upgrade.pending`, writes the consumed record, renames the old runtime, review, bootstrap and config to their `*-retained-e489bab70e13-before-28774823666b*` names, publishes the new review and bootstrap, deploys the new runtime, writes the config, runs the barrier-aware postcheck, writes the completion record, and retires `runtime-upgrade.pending` and then the barrier. The adapter then verifies the tree again, runs an ordinary product admission check with the new runtime, and releases `db.lck` (`:585-594`).

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
# expect present: runtime-retained-e489bab70e13-before-28774823666b, runtime-review-retained-...json, runtime-bootstrap-retained-...py, config-retained-...json,
#   runtime-upgrade-completed-28774823666b.json, runtime-upgrade-approval-consumed-<this approval_id>.json, and the earlier 4125726a consumed file
# expect ABSENT: runtime-upgrade.pending, source-default-activation.pending, package-maintenance.pending, .runtime-pending
sudo jq -r '.reviewed_commit' "$S/runtime-deployment-review.json"       # 28774823666bd39a3bc5714e02f1cd07045becd5
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

Hibernation remains OFF after H3. Reactivation is not implemented (RESUME.md task 4); do not try to re-enable it by hand (do not recreate the opt-in file, do not re-run `activation`).

### After H3: record and check the generation baseline

H3 also archives `generation-baseline.json` next to the maintenance intent (written before the intent and the marker, so a marker never exists without it). It records the qualified generation that was active when maintenance began: running kernel, production/source/restore UKI hashes, module stack, manifest, `config.json` and `qualification.json` digests, driver modules, firmware (hardlinked Apple firmware is accepted and its link count recorded), root control files (out-of-scope symlinks such as the limine enroll hooks recorded as link text only) and the ESP bootloaders `EFI/BOOT/BOOTX64.EFI` and `EFI/limine/limine_x64.efi`. The baseline cannot be amended later; only a new maintenance publication would replace it.

Immediately after H3, run the read-only assessment and keep its output:

```bash
sudo -n /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py assess | tee ~/t2-assess-after-h3.json | jq '{class, busy}'
```

Expected: `class: "unchanged"`. It writes nothing and holds no lock while hashing. If any item reports `unknown` here (for example a root-only control path that still could not be read), record it: that item will stay `unknown` in later assessments, which only keeps reactivation conservative.

## Gate H4: first package update, then `omarchy update`

Operator approval required for each update. The installed hook now runs the new native guard because the marker exists (`update_guard.main:434-440`, marker branch `:438`); with a valid marker it admits ordinary transactions under the physical lock after the exact inactive validator and a saved-image check.

1. Preconditions: `sudo /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py` exits 0; no `db.lck`; AC power.
2. First update a small, low-risk package that does not touch the kernel, initramfs, modules or bootloader, for example a user-space tool the owner chooses (`sudo pacman -S <small package>`; the exact package is the owner's choice and **not verified** here). Expect the hook line `Checking inactive T2 source boot policy before package changes...` and a normal transaction. Afterwards re-run the guard and require exit 0.
3. Only then run `omarchy update`. If it includes a kernel or `limine` package, the guard's fallback check requires the retained stock config to keep binding the production UKI; see MAINTENANCE-RUNBOOK.md section 3 for an incoherent kernel transaction. Hibernation stays vetoed throughout by the marker.
4. After each transaction re-run the guard (`exit=0`) and the runbook section 5 indicators.

Do not change the boot image or run `limine-mkinitcpio` unless the runbook section 3 gate is followed; kernel updates under maintenance are the case the design tests, and a kernel transaction on this machine ordinarily rewrites boot artifacts, so the owner decides when to include one.

After the first updates, `assess` should report `unchanged` for userspace-only updates, or `requalification-required` once the kernel, modules, firmware, UKIs or bootloader changed. Snapshot entries added to `/boot/limine.conf` by `limine-snapper-sync` do not count as a change. Reactivating hibernation is not part of this procedure (see [RESUME.md](RESUME.md)).

## Failure and rollback handling

General rules: fail closed. There is no automatic retry, no replay and no rollback command. The retained `*-retained-e489bab70e13-before-28774823666b*` files preserve the old runtime, review, bootstrap and config as evidence, but restoring them is a separately reviewed operation, not part of this procedure. Do not run the adapter or publisher a second time to "finish" a run. Never replay consumed deployment `4125726a-4847-4802-a821-953e6abe995a` or any approval whose consumed file exists: a replay is refused before any lock because the installed review no longer matches `old_review` (`runtime_upgrade_native.py:198`, in `_verified_engines` before `_locks`; the consumed-approval file is checked again at `runtime_deployment.py:378-380`), and even if it were not, replaying is forbidden.

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

If the machine loses power, hangs or reboots at any gate, do not assume state: on the next boot, reconcile with the handoff, `git`, and the read-only inventory in the runbook before any further action, and do not try to complete the gate.

## What NOT to do

From AGENTS.md "T2 Hibernation Hardware Safety", RESUME.md and the runbook:

- No reboot, restage or booting of any replacement-kernel image; never touch the failed marker-source UKI SHA-256 `974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd`, the rejected v1/v2 images or another replacement-kernel image. Any private UKI must preserve production `.linux` and `.cmdline` byte-for-byte via the pair stager. This procedure never stages one.
- No S3, S4, hibernate, suspend, poweroff or reboot as a test of this procedure. A successful ordinary boot does not show that S4 or cold restoration is safe; nothing here establishes that.
- Preserve consumed PM guards and consumed approvals; do not repeat a failed hardware vector or replay a consumed deployment.
- Do not run privileged Python from the writable workspace or from `$D`. Only the root-private staged files under `STATE` run as root; `$D/source` is read as inventory and copy input only.
- Do not delete, edit, "tidy" or hand-create anything under `STATE`, and do not edit `maintenance-resume.json`, the marker or any archive file.
- Do not disable, remove or bypass the pacman guard hook, or use `--noscriptlet` or `--hookdir` tricks.
- Do not reactivate hibernation by hand after H3.
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
