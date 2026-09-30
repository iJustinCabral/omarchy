# Inactive-Maintenance Stuck-State Runbook

Operator procedure for the fail-closed states the whole-path integration audit found in the inactive package-maintenance design (see [RESUME.md](RESUME.md), "Exact next implementation tasks" item 3). In every state below hibernation stays safely vetoed and OS updates are blocked until manual action. The goal is diagnosis, then the narrowest safe repair, then verification. Every claim is cited from source at `packages/t2-suspend/hibernate/`; anything not confirmed from code is marked **unverified**.

Source-only status: at the time of writing the maintenance publisher, marker-aware guard and this procedure exist in source only. The installed runtime `e489bab7` does not recognize any of it and deployment is not approved. This runbook applies only after a reviewed runtime containing `boot_policy_native.py maintenance` and the native guard has been deployed. On any other system, none of these states can arise.

## Ground rules

- Never delete, edit or "tidy" anything under `/var/lib/omarchy/t2-hibernate-product/` other than the single item a section below explicitly allows after its checks. The archive is the evidence the guard validates against; deleting it turns a recoverable state into a permanent one (a marker lacking archive documents is simply refused, there is no migration: `update_guard._resume_document` docstring).
- Never replay a consumed action, never re-run `activation`/`deactivation`, never create the marker by hand, never edit `maintenance-resume.json`, and never bypass or disable the pacman hook (`--overwrite`-style tricks, `--noscriptlet`, removing the hook file, `pacman -U` with `--hookdir` games). The guard takes no arguments or environment override by design (`update_guard.main`: "No update-guard arguments or bypasses permitted").
- Before touching the MacBookAir9,1 boot image (section 3), reconcile the current boot with `/home/jjc/.local/state/codex-mba-autonomous/handoff.json` and [HIBERNATION.md](HIBERNATION.md), as AGENTS.md requires. Never reboot into or restage the failed UKI hashes listed there.
- Stop and ask for review when a check below fails in a way the section does not describe. Unknown means stop.
- Commands here are read-only unless labelled REPAIR. Read-only does not mean unprivileged: the state directory is root-private (0700).

## Reference: paths and messages

All under `/` on the live system (sources use root-relative forms).

| Item | Path |
| --- | --- |
| State directory (0700, root) | `/var/lib/omarchy/t2-hibernate-product` (`boot_policy.STATE`) |
| Maintenance marker | `/var/lib/omarchy/t2-hibernate-product/package-maintenance.pending` |
| Deactivation pending | `/var/lib/omarchy/t2-hibernate-product/source-default-deactivation.pending` |
| Activation pending | `/var/lib/omarchy/t2-hibernate-product/source-default-activation.pending` |
| Runtime pendings | `/var/lib/omarchy/t2-hibernate-product/runtime-upgrade.pending`, `.runtime-pending` |
| Active policy (must be absent) | `/var/lib/omarchy/t2-hibernate-product/boot-policy.json` |
| Retained stock config backup | `/var/lib/omarchy/t2-hibernate-product/limine.conf.before-source-default` (`boot_policy.BACKUP`) |
| Staged receipt | `/var/lib/omarchy-t2-hibernation-pair/receipt.json` (`boot_policy.RECEIPT`) |
| Archive directory | `/var/lib/omarchy/t2-hibernate-product/boot-policy-transitions/<transition_id>/` (`boot_policy_transition.HISTORY`) |
| Archive contents | `maintenance-intent.json`, `policy.json`, `intent.json`, `completion.json`, `opt-in` (0644, empty), `maintenance-resume.json` |
| Ledger | `/var/lib/omarchy/t2-hibernate-product/ledger/` |
| Reviewed runtime | `/var/lib/omarchy/t2-hibernate-product/runtime/` and `runtime-deployment-review.json` |
| Physical-cycle lock (0600, flock) | `/var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock` |
| Pacman DB lock | `/var/lib/pacman/db.lck` |
| Production UKI | `/boot/EFI/Linux/omarchy_linux-t2.efi` |
| Limine config | `/boot/limine.conf` |
| Guard hook | `/etc/pacman.d/hooks/00-omarchy-t2-hibernate-guard.hook` (PreTransaction, `AbortOnFail`, Install/Upgrade/Remove of `*`) |

The archive directory name is the `transition_id` inside the marker. Every guard failure is printed by the hook as `T2 hibernation update guard: <message>` on stderr and exits 1, which aborts the pacman transaction before any change.

Fixed commands (root; the runtime path is the installed, reviewed, byte-pinned copy, never the workspace):

```bash
GUARD=/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/update_guard.py
NATIVE=/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
# Read-only: exactly what the pacman hook runs. Exit 0 admits, exit 1 prints the refusal.
sudo /usr/bin/python3 -I -B "$GUARD"; echo "exit=$?"
# Idempotent re-entry of the publisher (never writes when the marker exists; needs no pacman running).
sudo /usr/bin/python3 -I -B "$NATIVE" maintenance
```

The publisher re-execs itself under `systemd-inhibit --what=sleep:shutdown --mode=block` (`boot_policy_native._inhibit_command`). Running the guard by hand while another pacman transaction runs is harmless; running the publisher while pacman runs fails on the exclusive create of `db.lck`.

## State inventory (read-only, do this first)

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo ls -la --time-style=full-iso "$S" "$S/boot-policy-transitions" /var/lib/omarchy/t2-hibernate-trial
sudo ls -la --time-style=full-iso /var/lib/pacman/db.lck 2>&1
pgrep -ax pacman || echo "no pacman process"
sudo cat "$S/package-maintenance.pending"; echo
mapfile -t ID < <(sudo jq -r .transition_id "$S/package-maintenance.pending")
sudo ls -la --time-style=full-iso "$S/boot-policy-transitions/${ID[0]}"
```

Interpret with the section that matches. Healthy inactive maintenance has the marker, no other file from the "must be absent" set (below), a complete archive, an empty `pacman` lock slot when idle, and a guard run that exits 0 (see section 5).

## 1. Marker and deactivation pending both present

### Recognize

The publisher writes the marker before retiring the deactivation pending (`boot_policy_transition._transition`: marker written and read back, then "the compatible deactivation pending is retired only after these final prerequisites hold again", then `pending.unlink()`). A crash or kill in that window, or a failure of `maintenance_gate(root, "final")`, leaves both. Both files present:

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo ls -la "$S/package-maintenance.pending" "$S/source-default-deactivation.pending"
```

Refusals (identical text on both paths, because re-entry reuses the guard validator):

- Pacman hook and direct guard run: `T2 hibernation update guard: Active or incomplete source state prevents maintenance evidence` (`update_guard._maintenance`, loop over `ACTIVE` skipping only the marker).
- Publisher re-entry (`boot_policy_native.py maintenance`): traceback ending in the same `ValueError` from `_verify_existing_maintenance` -> `G._maintenance`. The marker and pending are untouched.
- A new publisher run cannot take the fresh path either: `Existing package maintenance intent refuses new transition`.
- Sleep is vetoed by both files: `Incomplete source-default transition or package maintenance blocks hibernation` (`sleep_entry.reject_pending`).

A crash usually also leaves `/var/lib/pacman/db.lck` (the publisher creates it with `O_EXCL` and unlinks it only on orderly exit); handle it with section 4. If it is present, the publisher's re-entry also fails at the lock with `FileExistsError`.

### Verify the evidence is complete and consistent (read-only)

Write order in the code is: pending, archive dir, `policy.json`, `opt-in`, `intent.json`, (stock `limine.conf` restored, `boot-policy.json` and opt-in removed), `completion.json`, `maintenance-resume.json`, `maintenance-intent.json`, marker, then pending retirement. A marker therefore implies all archive files were durably written. Confirm:

```bash
S=/var/lib/omarchy/t2-hibernate-product; A="$S/boot-policy-transitions/${ID[0]}"
# All eight evidence files exist and are single-link regular files.
sudo stat -c '%n %U %a %h %s' "$S/package-maintenance.pending" "$A"/{maintenance-intent.json,policy.json,intent.json,completion.json,maintenance-resume.json,opt-in} "$S/limine.conf.before-source-default" /var/lib/omarchy-t2-hibernation-pair/receipt.json
# Marker equals archived intent byte-for-byte.
sudo cmp "$S/package-maintenance.pending" "$A/maintenance-intent.json" && echo marker==archive
# The stale pending is exactly the archived deactivation intent (it is written from the same bytes).
sudo cmp "$S/source-default-deactivation.pending" "$A/intent.json" && echo pending==intent.json
# Marker pins match the retained files (compare the printed hashes to the marker fields).
sudo jq . "$S/package-maintenance.pending"
sudo sha256sum "$A/policy.json" "$A/completion.json" /var/lib/omarchy-t2-hibernation-pair/receipt.json
# Active policy and routine opt-in must be gone; the stock config must be the stock default 2.
sudo ls "$S/boot-policy.json" /etc/omarchy/t2-hibernate-product.enabled 2>&1
sudo grep -n '^ *default_entry\|remember_last_entry' /boot/limine.conf
sudo sha256sum /boot/limine.conf   # equals marker fallback_limine_sha256 unless a coherent kernel update ran since
```

Expected: marker fields `old_policy_sha256`, `staged_receipt_sha256`, `deactivation_completion_sha256` equal the three `sha256sum` outputs; `maintenance-resume.json` is the canonical schema `omarchy-t2-package-maintenance-resume-v1` with the same `transition_id` and a `resume` of `device=/dev/mapper/root`, `devnum`, `offset`; the `boot-policy.json` and opt-in files are absent; `default_entry: 2` is the only `default_entry` line and there is no `remember_last_entry`. Also confirm no other pending exists (`activation`, `runtime-upgrade.pending`, `.runtime-pending`) and that the resume page holds no image (section 2, "no saved image" check).

If any comparison fails, stop: this is not the crash window, and the archive needs review.

### Resolution

Re-run the maintenance action from the installed runtime. When it finds the marker and the deactivation pending together, it completes the interrupted publication instead of refusing (`boot_policy_native.native("maintenance")` routes to `boot_policy_transition._complete_interrupted_maintenance`):

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" maintenance | jq .    # expect completed_interrupted_maintenance: true
```

Under the same DB lock, physical lock and inhibitor as the publisher, it proves the pending is byte-identical to the archived deactivation intent that the marker chains to (same transition id, policy hash and completion hash), runs the update guard's exact validator with only that one pending ignored, runs the native final gate (hibernate route, marker vetoes, stock fallback and production UKI BLAKE2b, archived resume tuple against a fresh audit, no saved image), then retires the pending exactly as the interrupted run would have, re-validates without any ignore, and runs the retained gate. The marker is never touched. Any mismatch refuses with nothing changed, and any failure after the pending is removed reinstates identical bytes. A second run returns `already_inactive`.

Do not remove the pending by hand. If the completion refuses, stop: the evidence does not match the crash window and needs review.

The completion uses the strict final gate, which re-audits the qualified artifacts. That is safe here because no kernel update can land in this state: while the deactivation pending exists, the update guard refuses every pacman transaction, so the artifacts cannot have changed since the crash.

### Verify afterwards

```bash
sudo /usr/bin/python3 -I -B "$GUARD"; echo "exit=$?"          # expect exit=0, no output
sudo /usr/bin/python3 -I -B "$NATIVE" maintenance | jq .      # expect already_inactive true, needs db.lck absent and pacman idle
```

The guard exit 0 admits ordinary transactions; it never lifts the sleep veto.

## 2. Swapfile relocated or resume command line lost after maintenance began

### Recognize

The guard runs `image_state.require_no_image` on every transaction against the tuple archived at publish time. `maintenance-resume.json` binds exactly `{device: "/dev/mapper/root", devnum: "<major:minor>", offset: <int>}` plus `transition_id` and the three intent pins; nothing else (`update_guard._resume_document`, `_resume_target`). The check fails with one of these `T2 hibernation update guard: ...` messages (`image_state.require_no_image` `topology()`):

- `Active kernel resume target differs`: `/sys/power/resume` or `/sys/power/resume_offset` no longer equal the archived devnum/offset (for example the `resume=`/`resume_offset=` cmdline was lost, or the mapper's minor changed).
- `Actual Btrfs swapfile mapping differs`: `btrfs inspect-internal map-swapfile -r /swap/swapfile` no longer prints the archived offset (swapfile recreated or moved).
- `Swapfile is not on the qualified encrypted Btrfs root`: `findmnt --target /swap/swapfile` is not `/dev/mapper/root[...] btrfs`.
- Also possible: `Exact root-mapper block alias required`, `Opened resume block identity differs`, `Pending or unknown hibernation image header` (the last means a swap header that is not a clean version-1 `SWAPSPACE2` page: **treat as a possible saved image, section stop rule below**).

Compare live values with the archive:

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo jq .resume "$S/boot-policy-transitions/${ID[0]}/maintenance-resume.json"
cat /sys/power/resume /sys/power/resume_offset
sudo btrfs inspect-internal map-swapfile -r /swap/swapfile
findmnt -n -o SOURCE,FSTYPE --target /swap/swapfile
ls -l /dev/mapper/root; cat /proc/cmdline | tr ' ' '\n' | grep -E '^(resume|resume_offset)='
```

### Verify there is no saved image by other means (read-only)

Do not trust a single signal. Read the swap header page at the archived offset if the archived location still exists, and check that no restore stage exists:

```bash
# Only when the archived offset is still the swapfile's real offset. Expect the swap signature, no "S1SUSPEND"/"S2SUSPEND".
sudo dd if=/dev/mapper/root bs=4096 skip=<archived offset> count=1 status=none | tail -c 10 | cat -v
sudo dd if=/dev/mapper/root bs=4096 skip=<archived offset> count=1 status=none | head -c 1032 | tail -c 4 | xxd
ls /sys/firmware/efi/efivars | grep -i 'LoaderEntry\(OneShot\|Default\)'   # expect nothing
journalctl -b -1 -u systemd-hibernate.service --no-pager | tail -50
```

`SWAPSPACE2` in the last ten bytes and version `01000000` at offset 1024 is what the guard itself requires (`image_state`: `page[-10:] == b"SWAPSPACE2"`, `page[1024:1028] == b"\x01\0\0\0"`). If the swapfile actually moved, the header at the old offset proves nothing about the new location; also read the header at the new offset (`btrfs inspect-internal map-swapfile -r`). If either page is not clean, or you cannot tell, or the previous boot ended in a hibernation attempt: **stop and ask for review**. Do not boot, resume or run the stock swap-in path to "see".

### Safe way forward

1. Preferred: restore the original topology so the archived tuple is true again. Recreate the swapfile at the original offset only if it is byte-identical in placement, or restore the original `resume=`/`resume_offset=` cmdline entries. Regenerating the cmdline touches the boot image: follow the gate in section 3 and AGENTS.md first. Then re-run the guard (section 1 "Verify afterwards").
2. Otherwise a reviewed re-publication is needed, meaning a new archived tuple for the new location. **The code offers no way to do this**: the resume tuple is written once, before the archived intent and marker exist (`_transition`), and the publisher refuses while the marker exists (`Existing package maintenance intent refuses new transition`). `maintenance-resume.json` is bound to the intent by canonical-byte equality, so editing it, or the marker, fails `Exact archived resume target evidence required`. Re-publication would require a reviewed retirement of the current maintenance state and a fresh publisher run under the physical lock; that is outside this runbook and needs a code review first (reactivation, section 6, does not re-publish anything: it requires an unchanged qualified generation, the same pinned tuple).

Note the archived resume tuple is deliberately not re-derived (`_maintenance_gate`, phase `retained`), because a kernel or UKI update legitimately changes what a qualified audit would report; only the live topology has to keep matching the pinned tuple.

## 3. Kernel transaction failed halfway (UKI and `limine.conf` incoherent)

### Recognize

The guard's fallback check requires canonical stock `default_entry: 2` whose `//linux-t2` entry has a `path:` of `boot():/EFI/Linux/omarchy_linux-t2.efi#<128 hex>` where the hash equals the BLAKE2b of the actual `/boot/EFI/Linux/omarchy_linux-t2.efi` (`package_maintenance._fallback`, `boot_policy_transition.verify_fallback`), read twice. Refusal messages, printed with the `T2 hibernation update guard: ` prefix:

- `Stock entry does not bind actual production UKI bytes`: the UKI was replaced (or partially replaced) but `limine.conf` still carries the old hash, or the reverse. This is the expected incoherent state.
- `Stock configuration changed while reading UKI`: something is still writing (check `pgrep -ax 'pacman|mkinitcpio|limine'`).
- `Bounded owned regular fallback bytes required` (missing, truncated, wrong owner/mode/link count UKI), `Inactive updates require canonical stock default 2`, `Stock index 2 must select Omarchy's production linux-t2 child`, `Stock index 2 must use the fixed production UKI path`.

```bash
sudo ls -la --time-style=full-iso /boot/EFI/Linux/
sudo grep -n 'default_entry\|linux-t2\|path:' /boot/limine.conf
sudo b2sum /boot/EFI/Linux/omarchy_linux-t2.efi
```

Compare the `#` suffix of the `path:` line under `//linux-t2` with the `b2sum` output. A mismatch, plus a pacman log showing a failed kernel/initramfs transaction (`grep -n 'linux-t2\|mkinitcpio\|limine' /var/log/pacman.log | tail`), is this state.

### Repair (outside pacman)

Because the hook blocks every pacman transaction until coherence returns, the repair cannot use pacman. Regenerate the production UKI and Limine config with Omarchy's own tooling, which this repo calls as `sudo limine-mkinitcpio` after boot-affecting changes (`bin/omarchy-hibernation-setup`, `bin/omarchy-hibernation-remove`, `bin/omarchy-plymouth-set`); `limine-update` rebuilds the config and entry hashes (`bin/omarchy-refresh-limine` runs `limine-update` and `limine-snapper-sync`).

Gate before running anything (AGENTS.md "T2 Hibernation Hardware Safety"): read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json` and [HIBERNATION.md](HIBERNATION.md); confirm you are on the ordinary stock `Omarchy linux-t2` entry with the production `.linux` (this repairs the ordinary production kernel, never a replacement-kernel image); confirm the production UKI is what the transaction was updating, not one of the rejected hashes. If the state does not match that description, stop.

```bash
# REPAIR (reviewed, on the ordinary production boot only). This is not a pacman transaction.
pgrep -x pacman && echo "STOP: pacman running" 
sudo limine-mkinitcpio
```

`limine-mkinitcpio` is the normal Omarchy route; the maintainer-facing `omarchy-refresh-limine` also replaces `limine.conf` with the repo default and is **not** appropriate here because it discards the retained stock config the archive pins. **Unverified:** that `limine-mkinitcpio`/`limine-update` in this configuration keeps the canonical `default_entry: 2` and re-embeds the `#<blake2b>` hash in the `//linux-t2` `path:` line; verify with the commands below and, if the config no longer matches the guard's canonical form, stop for review instead of hand-editing `limine.conf` or the archive.

### Verify coherence before retrying

```bash
sudo grep -n 'default_entry\|remember_last_entry' /boot/limine.conf      # exactly: default_entry: 2 ; no remember_last_entry
sudo b2sum /boot/EFI/Linux/omarchy_linux-t2.efi
sudo sed -n '/^\/\/linux-t2/,/^\/\//p' /boot/limine.conf                    # path hash must equal the b2sum above
sudo /usr/bin/python3 -I -B "$GUARD"; echo "exit=$?"                        # expect 0
```

The marker's `fallback_limine_sha256` will no longer match the new `limine.conf` after a legitimate rebuild. This is expected and accepted: "current coherent bytes may legitimately be NEW" (`update_guard._maintenance`). Retry the interrupted update through the normal Omarchy update flow only after the guard exits 0. Coherent stock bytes prove the fallback entry binds the UKI, not that the machine boots; the owner decides when to test boot, and hibernation still needs the separate reviewed reactivation.

## 4. Leftover `/var/lib/pacman/db.lck` from the adapter or publisher

### Recognize

Two writers create `db.lck` with `O_EXCL`, mode 0600, empty: the publisher lock context (`boot_policy_transition._locks`) and the runtime-upgrade adapter (`runtime_upgrade_native`). Normal exit unlinks it; a crash, SIGKILL or a failed cleanup leaves it. The adapter's own note says: `our db.lck may remain and block pacman; remove it only after confirming no pacman process is running, e.g. pgrep -x pacman shows none`. Pacman then refuses with `unable to lock database` and `failed to init transaction`. Foreign or altered locks are deliberately never removed by these tools (`Foreign pacman lock replacement must remain preserved`, `Outstanding pacman lock preserved at phase boundary`).

### Checks (read-only)

```bash
pgrep -ax pacman || echo "no pacman process"
pgrep -ax 'python3|systemd-inhibit' | grep -E 'boot_policy_native|runtime_upgrade|update_guard' || echo "no publisher/adapter process"
sudo stat -c '%n owner=%U mode=%a links=%h size=%s mtime=%y' /var/lib/pacman/db.lck
sudo fuser -v /var/lib/pacman/db.lck 2>&1 || true
sudo systemd-inhibit --list | grep -i omarchy-t2-source-default || echo "no owner inhibitor"
sudo flock -n /var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock true && echo "physical lock free" || echo "physical lock HELD"
sudo journalctl -b --no-pager | grep -iE 'omarchy|t2 hibernation|db.lck' | tail -40
```

Ours has the exact fingerprint: root-owned, mode 0600, link count 1, size 0 (`_locks`: `os.O_CREAT | os.O_EXCL`, mode 0600). A pacman-created lock normally contains the pacman PID text; a size other than 0 or a different owner means foreign, so leave it and ask. The lock is stale only if all of these hold: no pacman, publisher or adapter process, no owner inhibitor, physical lock free, and its mtime predates the last known aborted run (see journal). If the physical lock is HELD, a hibernation cycle or another owner is live: do nothing.

### Remove (REPAIR, only after every check passes)

```bash
sudo rm -- /var/lib/pacman/db.lck
sudo /usr/bin/python3 -I -B "$GUARD"; echo "exit=$?"
```

A crash between marker write and pending retirement (section 1) usually needs this first; do not remove any other lock. Never remove `physical-cycle.lock`: it is a persistent flock file whose inode identity is checked (`Physical exclusion inode changed`, `Fixed private physical cycle lock required`); the lock is released by process exit, so a held one means a live process.

## 5. Is maintenance active and healthy

Read-only indicators:

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo ls "$S"                                       # expect package-maintenance.pending, and NOT boot-policy.json, source-default-*.pending, runtime-upgrade.pending, .runtime-pending
sudo jq . "$S/package-maintenance.pending"
sudo ls /etc/omarchy/t2-hibernate-product.enabled 2>&1   # expect: No such file (routine opt-in removed)
sudo grep -n default_entry /boot/limine.conf       # default_entry: 2 (stock Omarchy linux-t2)
sudo /usr/bin/python3 -I -B "$GUARD"; echo "exit=$?"   # 0 and silent when the whole chain, fallback coherence and no-image proof hold
sudo /usr/bin/python3 -I -B "$NATIVE" maintenance | jq .  # re-entry; expect "already_inactive": true, "qualification_issued": false
systemctl show systemd-hibernate.service -p DropInPaths,ExecStart --no-pager
```

While maintenance is healthy the sleep route refuses (`Incomplete source-default transition or package maintenance blocks hibernation`); that is the intended veto, not a fault. `qualification_issued: false` and `reactivation_evaluated: false` are expected: the guard admits updates only and never reactivates hibernation.

Logs: the guard prints to pacman's output and the terminal running the update; the pacman log records the abort at `/var/log/pacman.log`. The product service logs to the journal (`omarchy-t2-hibernate-product.service`, `StandardOutput=journal`). Useful queries:

```bash
sudo journalctl -b --no-pager -u omarchy-t2-hibernate-product.service -u systemd-hibernate.service | tail -100
sudo journalctl -b --no-pager | grep -E 'T2 hibernation update guard|omarchy-t2' | tail -50
grep -n 'T2 hibernation\|hook' /var/log/pacman.log | tail -20
```

Whether the publisher or guard log to the journal by their own identifier beyond stderr is **unverified**; the update runner's own log (where `omarchy-update` is used) carries the hook text.

Reactivating hibernation after updates is the separate, operator-approved `reactivate` action (gate H5 in [DEPLOYMENT.md](DEPLOYMENT.md)); it is only possible while `assess` reports `unchanged`. An unchanged marker without that approval means hibernation stays unavailable and updates stay possible, which is the designed default.

## 6. Interrupted or failed `reactivate`

`boot_policy_native.py reactivate` re-applies the retained source default and retires the marker (DEPLOYMENT.md, gate H5). It shares the filename `source-default-activation.pending` with the runtime upgrade's barrier but writes its own protocol (`omarchy-t2-package-reactivation-intent-v1`); neither command ever adopts the other's bytes.

### Recognize

`source-default-activation.pending` exists and `jq -r .protocol` on it prints `omarchy-t2-package-reactivation-intent-v1` (anything else is the runtime upgrade's barrier: section 1 style rules apply, do not run `reactivate`, escalate). `maintenance` refuses with a message naming `reactivate`, and every update and every sleep route is refused. Depending on where it stopped the marker may still exist, `boot-policy.json`, the opt-in and the one changed `default_entry` line may already be present, and `/var/lib/pacman/db.lck` may be left over (section 4, only after its checks: a killed process cannot release it).

```bash
S=/var/lib/omarchy/t2-hibernate-product
sudo jq . "$S/source-default-activation.pending"
sudo ls -la "$S/boot-policy-transitions/$(sudo jq -r .transition_id "$S/source-default-activation.pending")"
sudo ls "$S/package-maintenance.pending" "$S/boot-policy.json" /etc/omarchy/t2-hibernate-product.enabled 2>&1
sudo grep -n default_entry /boot/limine.conf
```

### Do not reboot

Sleep is vetoed until the pending is retired, but a reboot is not vetoed once the `default_entry` line was written. Do not reboot, power-cycle or suspend while a reactivation pending exists.

### Resolution

Re-run the same command; there is nothing else to run and nothing to delete by hand:

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" reactivate
```

It authenticates the pending (byte-equal to its archived intent, bound to the current marker and baseline hashes, Limine unchanged apart from the snapshot region) and then, by state:

| State found | What re-running does |
| --- | --- |
| Pending only, or archive partly written | Writes `rollback.json` in the archive and removes the pending |
| `boot-policy.json` written, boot config untouched | Removes `boot-policy.json`, writes `rollback.json`, removes the pending; a stray `limine.conf.source-default-<id>` temporary is removed |
| Boot-config line changed, with or without the opt-in, or the post-checks failed | Reverses that one line on the current bytes (snapshot entries are kept and only the canonical form is compared with the retained backup), removes the opt-in and `boot-policy.json`, re-verifies the inactive maintenance state, writes `rollback.json`, removes the pending |
| `completion.json` present, marker still present | Re-runs the active-state checks; if they pass it removes the marker and the pending, otherwise it rolls back as above |
| Marker already gone, completion present | Verifies the active state and removes the pending |

It never continues forward past the boot-config write, so after a rollback (`"rolled_back": true`, `"reactivated": false`) the machine is in ordinary inactive maintenance again and a new `reactivate` may be attempted. If the re-run refuses (pending not authentic, unrelated Limine drift, a failed retained gate), it changes nothing: stop and ask for review.

### Verify afterwards

Section 5 indicators: after a rollback the marker exists, `boot-policy.json`, the opt-in and `source-default-*.pending` are absent and `default_entry: 2`. After a completed reactivation the marker and pending are gone and `boot-policy.json`, the opt-in and the source `default_entry` are present; the blanket guard then refuses updates until `maintenance` is run again.

## 7. Unrecognized snapshot region in `/boot/limine.conf`

While hibernation is active, and at H3, Limine checks ignore only the region that `limine-snapper-sync` writes (`boot_policy.limine_canonical`). The recognizer is strict: a line it does not recognize makes the check refuse, which keeps hibernation unavailable and, before H3, keeps updates blocked. The error names the file line, for example `Unexpected line inside snapshot region (line 42: '...')`.

1. Read the named line with `sudo sed -n '<N>p' /boot/limine.conf` and compare it with a normal snapshot sub-entry (5-space indent; `comment:`, `///N │ date`, `////linux…`, `protocol: efi`, `path: boot():/<machine-id>/limine_history/…`, `cmdline:`).
2. If a `limine-snapper-sync` update changed its output format, stop and report the line: the recognizer needs a reviewed update. Do not edit `/boot/limine.conf` by hand, and do not restore it from a backup; the retained backups pin the approved bytes and a hand edit can break both hibernation and the maintenance evidence.
3. Snapshot sub-entries that reuse a top-level entry name, point outside `limine_history`, or set `default_entry` are refused on purpose.

## 8. Stale snapshot entries after H3

Entering maintenance writes back the retained stock bytes, whose snapshot list reflects the time hibernation was staged. Until `limine-snapper-sync` runs again (at the next snapshot, including the one `omarchy update` creates), the boot menu may list snapshots that were since deleted or miss newer ones. Selecting a missing snapshot entry fails to boot; it is never the default. To refresh immediately after H3, run `sudo limine-snapper-sync` (attended). This does not affect maintenance, which ignores the snapshot region.

## 9. Retiring the staged UKI pair after a kernel update

After a kernel update changes `/boot/EFI/Linux/omarchy_linux-t2.efi`, `stage-hibernation-uki-pair.py rollback` and `clear` fail closed (`Production UKI changed during pair staging`) and `stage` refuses while the old receipt or images exist. `retire-after-production-change` is the reviewed way out. It never touches the production UKI, other Limine entries, or the consumed-guard and vector evidence directories in `/var/lib/omarchy-t2-hibernation-pair/`.

Preconditions (all checked, all read-only until they pass; any failure changes nothing): the maintenance marker `package-maintenance.pending` exists; `boot-policy.json`, the opt-in `/etc/omarchy/t2-hibernate-product.enabled`, the activation, deactivation and runtime-upgrade pendings, and any `LoaderEntryOneShot` or `LoaderEntryDefault` are absent; no `.pending*` entry under `/var/lib/omarchy/t2-hibernate-trial`; the current boot is the stock `Omarchy.linux-t2`; the receipt state is one of `staged`, `source-arming`, `restore-arming`, `restore-disarmed`, `rolled-back` or `stage-failed-recovered`; both ESP images still match the receipt SHA-256 and BLAKE2b; the production UKI SHA-256 differs from the receipt; and the Limine judgement below passes. It then takes `pacman` `db.lck` and the physical-cycle `flock`, as the product transitions do.

Limine drift is judged with `boot_policy.limine_canonical`, imported and not reimplemented. The exact pair block rebuilt from the receipt is removed from the current bytes; both that remainder and the pre-staging backup are canonicalised (snapshot region removed) and the production path line hash is masked. The two must then be byte-equal, so only the production hash, the `limine-snapper-sync` snapshots and the kernel release comment may differ. The comment is the single `comment: Kernel version: <release>` line that `limine-entry-tool` writes inside the entry owning the production path line; `limine-entry-tool` rewrites it on every kernel update, so it is masked there and nowhere else (exactly one such line in that entry on both sides, exact formatting including the trailing-space `kernel-id` line beside it). When it changed, the new release must equal the release in the `.uname` section of the current production UKI (read from the ESP file, which is also what the new-hash check binds); an unreadable `.uname`, a different release, a removed or added line, or a change in any other entry refuses. The running kernel is deliberately not consulted, since maintenance may run before the reboot into the new kernel. The new hash must equal the BLAKE2b of the current production UKI, which proves the kernel update finished. Foreign entries, `default_entry`, cmdline, any other drift, unrecognised snapshot text or edited pair text refuse. Only retirement (and its rollback) tolerates the release drift: `stage`, `rebind` and `reactivate` compare the post-update Limine byte-exactly against backups taken after the update, so they need no such allowance. Do not edit `limine.conf` by hand to make it pass (section 7).

Steps: archive to `/var/lib/omarchy-t2-hibernation-pair-retired/<receipt-sha16>-<n>/` (0700: images, receipt, backup, current `limine.conf`, `manifest.json` of hashes), fsync, write `journal.json`, remove only the pair block from the current Limine bytes (the new production hash and snapshots are kept; the old backup is never restored over them), remove the two ESP images, the backup and the receipt, then write `retirement.json` (in the archive) chaining to the old receipt SHA-256. Before the live receipt is removed it also leaves the receipt custody files `pair-retired-receipt.json` and `pair-retirement.json` in `/var/lib/omarchy/t2-hibernate-product` (contract in `hibernate/pair_custody.py`), so the maintenance chain keeps validating; a stale record of an earlier generation is replaced atomically and `retire-rollback` removes only custody that chains to the receipt it restores. Rebinding onto the new pair is [section 10](#10-requalify-and-rebind-a-new-generation). Each step is detected from disk, so an interrupted run is finished by running it again; `retire-rollback` instead restores the archived images, backup, block and receipt of an interrupted (not completed) retirement. A second run after success only reports `already-retired`. `stage` may then run for the new generation.

Prerequisites and recovery for retirement: the fixed physical-cycle lock `/var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock` (0600) must already exist, since maintenance entry needs it too; retire refuses if it is missing and never creates it. SIGTERM, SIGHUP and SIGINT are handled so an interrupted run releases the `db.lck` it created and only that one. If a `SIGKILL` or power loss leaves a stale `/var/lib/pacman/db.lck` (the next run refuses with `db.lck is held`), confirm no pacman is running (`pgrep -ax pacman`), remove the stale `db.lck`, then rerun `retire-after-production-change`. Limine is re-read immediately before it is written, so a concurrent `limine-snapper-sync` rewrite is re-judged and preserved, not reverted. After `retire-rollback` the aborted archive keeps `journal.aborted.json` and the next retirement uses a fresh archive index.

```bash
P=/home/jjc/Projects/MBA_9_1/packages/t2-suspend/experiments/stage-hibernation-uki-pair.py
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change --dry-run   # read-only plan
sudo /usr/bin/python3 -I -B "$P" retire-after-production-change             # attended; run once, re-run if interrupted
sudo /usr/bin/python3 -I -B "$P" retire-rollback                            # only to undo an interrupted retirement
```

## 10. Requalify and rebind a new generation

Use this when `assess` reports `requalification-required` (a kernel update changed the production UKI, kernel, control files or the stock Limine projection) and you want ACTIVE source-default hibernation again on the new kernel. Design rationale: [REBIND-DESIGN.md](REBIND-DESIGN.md). The whole sequence is an operator gate list in [DEPLOYMENT.md, gate H6](DEPLOYMENT.md); this section is the reference for the states you can meet. `rebind` issues no qualification and is not power permission; hibernation is not proven until the attended qualification evidence exists and one routine S4 has been run afterwards.

### Sequence at a glance

1. Runtime upgrade UNDER MAINTENANCE, first, while the old pair and its receipt are still intact (the installed guard reads the fixed receipt path). It deploys a runtime that contains the rebind engine, the receipt custody resolver and the volatile-state baseline fix. It uses the maintenance approval protocol (DEPLOYMENT.md, gate H6a).
2. Retire the old pair with the stager `retire-after-production-change` mode (section 9). It deletes the old receipt, images and Limine entries and leaves `pair-retired-receipt.json` and `pair-retirement.json` in the product state directory. Updates stay allowed and `assess` keeps reporting `requalification-required`.
3. Build and audit the new pair from the new production UKI (private candidate stack; never restage a replacement `.linux`), stage it, and run the attended ordinary boots, `test_resume` and S4 qualification. A one-use trial for the new manifest uses `trial.py --generation <manifest12>`; the original trial root and its consumed guard are never reused or reset.
3a. After a successful S4 vector, retire its two EFI stage slots with `cleanup-successful-pair-slots.py --vector <vector>` (read-only) then `--execute` (DEPLOYMENT.md, gate H6e-clean). Trial readiness refuses while the V3 source and V2 restore stage variables exist. An interrupted execute is finished by rerunning it; a refusal means read the message, do not delete variables by hand.
4. Run the one-use generation trial (`trial.py --generation <manifest12>`, with `retire_slots: true`), then externally issue the qualification, the product config (schema v2, battery policy) and the boot policy review for the new receipt. The qualification's `evidence_sha256` must be the SHA-256 of the trial's reconciled `generations/<manifest12>/ledger/cycle-<id>.json`. Stage them, root-owned mode 0600, as `rebind-qualification.json`, `rebind-config.json` and `rebind-boot-policy-review.json` in the product state directory.
5. `sudo /usr/bin/python3 -I -B "$NATIVE" rebind`.
6. One routine S4 with the product dispatcher, attended.

### Read-only check before `rebind`

```bash
S=/var/lib/omarchy/t2-hibernate-product
NATIVE=$S/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
sudo /usr/bin/python3 -I -B "$NATIVE" assess | jq '{class, changed_items, unknown_items}'   # expect requalification-required
sudo jq . "$S/pair-retirement.json"                                                             # protocol omarchy-t2-pair-retirement-v1
sudo sha256sum "$S/pair-retired-receipt.json" /var/lib/omarchy-t2-hibernation-pair/receipt.json
sudo jq -r .staged_receipt_sha256 "$S/package-maintenance.pending"                              # equals retired_receipt_sha256 and the retained receipt's hash
sudo sha256sum "$S/rebind-config.json" "$S/rebind-qualification.json" "$S/rebind-boot-policy-review.json"
sudo jq -r .staged_receipt_sha256 "$S/rebind-config.json"                                       # equals the LIVE (new) receipt hash
```

### Refusals (all with zero writes; the marker stays and updates stay allowed)

| Message | Meaning |
| --- | --- |
| `generation unchanged: use reactivate` | Nothing changed; this is class (a). |
| `compatibility unknown: ...` | The baseline is missing or invalid, or an item could not be read. `rebind` needs a definite `requalification-required`; there is no override. |
| `Reviewed runtime differs from the maintenance intent; upgrade the runtime under maintenance first` | Step 1 was skipped. |
| `The old pair is still staged` | Step 2 was skipped. |
| `Pair retirement record required` / `does not chain` / `Retained retired receipt` | The stager's custody files are missing, foreign or for another receipt. The guard refuses updates in the same way. |
| `Staged replacement authority required` / `does not bind the staged pair receipt` / `not bound to this product manifest` | A staged file is missing or does not bind the new pair and manifest. |
| `Unrelated Limine drift: ... staged pair bytes` | `/boot/limine.conf` differs from the staged pair by more than the snapshot region (for example another update ran after staging); restage the pair. |
| a product validation, resume, deployment or saved-image refusal | The staged generation is not qualified as staged. |
| `Qualification evidence does not bind the generation trial's reconciled cycle`, `Generation trial state required`, `Consumed generation trial guard required`, `Generation trial cycle is not reconciled`, `Exactly one generation trial cycle required`, `Private real generation trial directory required` | The qualification does not point at a real, successful, consumed trial of this manifest under `/var/lib/omarchy/t2-hibernate-trial/generations/<manifest12>/`; a record of the original trial root never counts. |
| `A retired ... image is still on the ESP` | The guard's retirement check: an ESP image still has a retired image's hash; re-run the stager retire. |

### Interrupted or failed `rebind`

A dropped ssh session, Ctrl-C or SIGTERM is converted to an exit that releases `/var/lib/pacman/db.lck`, leaving the pending in place (sleep and updates stay vetoed): re-run `rebind`. SIGKILL or power loss cannot be caught and can leak `db.lck` (the next run then refuses with a `db.lck` error): confirm no pacman is running, remove it only after the section 4 checks, and re-run.

`source-default-activation.pending` exists and `jq -r .protocol` prints `omarchy-t2-package-rebind-intent-v1` (anything else is the runtime upgrade barrier or a reactivation: do not run `rebind`; use section 6 or the DEPLOYMENT.md failure table). Sleep and updates are refused; `maintenance` and `reactivate` name `rebind`. Do not reboot while it exists: the boot line may already be changed.

Re-run the same command; never delete the pending, an archive file or a staged file by hand:

```bash
sudo /usr/bin/python3 -I -B "$NATIVE" rebind
```

| State found | What re-running does |
| --- | --- |
| Pending only, or archive partly written | Writes `rollback.json` and removes the pending; a torn archive directory is left as noise |
| Some authority files installed, boot config untouched | Restores each installed file from the archived old bytes, writes `rollback.json`, removes the pending |
| Boot-config line changed, with or without the opt-in, or the post-checks failed | Reverses that one line on the current bytes, removes the opt-in and `boot-policy.json`, restores the old authority, re-verifies inactive maintenance, writes `rollback.json`, removes the pending |
| `completion.json` present, marker present | Re-runs the ACTIVE checks; if they pass it removes the marker and the pending, otherwise it rolls back |
| Marker gone, completion present | Verifies ACTIVE and removes the pending |

After `"rolled_back": true` the machine is in ordinary inactive maintenance again, byte-identical to before, with the retired-pair evidence and the new pair still in place, and a new `rebind` may be attempted. A refusal on re-run (`... is neither the old nor the new bytes`, `Archived ... differs`, `Unrelated Limine drift`) changes nothing and means a foreign write happened: stop and ask for review.

### After a runtime upgrade under maintenance that failed

What is left depends on where the adapter stopped. The core writes, in this order and each after a guard check: `source-default-activation.pending` (the barrier, protocol `omarchy-t2-runtime-upgrade-maintenance-intent-v1`), `runtime-upgrade.pending` (same bytes), `runtime-upgrade-approval-consumed-<approval>.json` (same bytes), the retained old runtime files, the new runtime, and only then the marker rebind. A stop before the barrier leaves nothing. A stop right after the barrier (the guard refusing) leaves ONLY the barrier: no `runtime-upgrade.pending`, no consumed file, the old runtime, config, review and marker untouched. A later stop leaves the barrier and `runtime-upgrade.pending` (and the consumed file from the third write on). The barrier alone is never sufficient evidence that nothing moved; the proof below is.

The adapter's recovery restores the durable veto and then settles the marker binding: marker, `boot-policy-transitions/<id>/maintenance-intent.json` and `generation-baseline.json` all become exactly the new form when the new runtime review is installed, or exactly the old bytes when the old one is. The old bytes are always retained first as `maintenance-intent.before-runtime-<new12>.json` and `generation-baseline.before-runtime-<new12>.json` next to `runtime-rebind-<new12>.json`, even when nothing moved (the retained copies then equal the current files: that is old-form evidence, not proof of a rebind). A process killed mid-rewrite cannot run that recovery; compare the three files with those copies (the marker's only difference is `runtime_review_sha256`; the baseline's is `maintenance_intent_sha256`) and escalate rather than editing by hand.

Updates stay refused by the installed guard (`Active or incomplete source state prevents maintenance evidence`) until the barrier is retired. Never delete it by hand and never re-run the failed approval: its adapter bytes are pinned and it is dead once a defect is found.

#### Adopting the barrier of an earlier, unconsumed approval

A maintenance approval may carry an optional `leftover` object, `{"approval_id": "<earlier UUID4>", "intent_sha256": "<SHA-256 of the exact barrier bytes>"}`. Its reviewed adapter then, under the same locks and inhibitor, before it calls the core:

1. proves nothing moved: the barrier is byte-exact the pinned intent, canonical, for THIS approval's old review, config and marker digest, from the named earlier approval and a different new review; no `runtime-upgrade.pending`, no `.runtime-pending`, no consumed file for either approval, no completion or retained-runtime evidence for either review; the installed review, bootstrap and config are exactly the old pins and the whole runtime tree verifies against the old review; the marker equals the pinned bytes, the archived intent equals the marker and the baseline is bound to it in the old form; the retained old copies and the rebind record under the earlier review's tag, if present, are byte-exact old-form evidence; no rebind evidence exists for this approval's review;
2. writes `runtime-upgrade-approval-consumed-<earlier approval>.json` with the barrier's bytes, so the earlier approval can never be replayed (the core and the adapter refuse a consumed approval);
3. renames the barrier to `runtime-upgrade-abandoned-intent-<earlier approval>.json` (archived, never deleted);
4. continues with this approval's own upgrade.

Each step is preceded by the guard and is idempotent: a crash after step 2 or 3 is resumed by re-running the same approval; any other bytes or any moved state refuses with zero writes and the barrier stays. If the upgrade then stops before writing its own barrier (a precheck refusal), the machine is back in ordinary inactive maintenance on the old runtime.

#### The 2026-09-29 leftover (approval `c6051717-6c93-4183-9d5f-eba64bd6182e`, reviewed commit `0807b7d7`)

The first live maintenance upgrade stopped at its first guard after writing the barrier (`Active source-default state is present under a maintenance upgrade: source-default-activation.pending`), because the adapter's own guard refused the core's own barrier. A second defect would have followed: after the marker rebind the guard compared the marker with its pinned OLD bytes. Both are fixed by the reviewed replacement adapter, which also adopts the leftover. The state to expect (read-only):

```bash
S=/var/lib/omarchy/t2-hibernate-product
A=$S/boot-policy-transitions/f5be4683-011d-40ca-85b2-815508a9bdb1
sudo sha256sum "$S/source-default-activation.pending"    # 248927bfdce50c394d955c85c15ce1d483aa703b696188e3058d46a0dd2d022b (the exact intent, 603 bytes)
sudo ls "$S"/runtime-upgrade.pending "$S"/.runtime-pending "$S"/runtime-upgrade-approval-consumed-c6051717-* 2>&1   # all absent
sudo sha256sum "$S/runtime-deployment-review.json" "$S/package-maintenance.pending"   # c31e1a43... (old review) and 6d6ccc4a... (old marker)
sudo ls "$A"        # includes the two *.before-runtime-14107eedf06a.json copies and runtime-rebind-14107eedf06a.json: old-form evidence left by the failed run's recovery
```

Operator steps: build and review the fixed source commit; author the new approval (new adapter pin and new review, same old pins, a fresh `approval_id`, `unchanged` = qualification, hook and the marker digest 6d6ccc4a...) with `"leftover": {"approval_id": "c6051717-6c93-4183-9d5f-eba64bd6182e", "intent_sha256": "248927bfdce50c394d955c85c15ce1d483aa703b696188e3058d46a0dd2d022b"}`. Archive the earlier staged set beside the new one (the stage script's `prior-<commit12>.` copies, prefix `0807b7d7`) before installing the new one, and make the pre-run checks expect exactly this one leftover in place of "markers absent". Run the adapter once, as in H6a. On success the leftover is archived as `runtime-upgrade-abandoned-intent-c6051717-....json` and consumed as `runtime-upgrade-approval-consumed-c6051717-....json`. On a refusal nothing has been written: diagnose read-only; do not edit state.

## Summary of gaps

- No code path re-publishes a new resume tuple, or retires maintenance, when the swapfile or cmdline changed; only restoring the original topology is supported today. `rebind` requires the derived resume target to equal the archived one.
- `rebind` needs the stager `retire` mode's custody files (section 9) and an externally authored boot policy review; neither is produced by this repository's runtime code.
- Regenerating the production UKI with `limine-mkinitcpio` is the repo's normal tool, but this configuration's preservation of `default_entry: 2` and the entry hash was not confirmed from code.
- Journal identifiers for the publisher and guard are unconfirmed.
