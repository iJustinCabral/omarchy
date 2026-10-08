# Upstream-model hibernation test (MacBookAir9,1, linux-t2 7.2.7)

Attended hardware-test tooling. Nothing in this page has been built, staged or run on the machine; the tools exist in source with fixture tests only. Checkout reference: `packages/t2-suspend/upstream-model/` at the commit that added it. Status words follow [HIBERNATION-GUIDE.md](HIBERNATION-GUIDE.md): everything here is implemented and unit-tested, none of it is observed on hardware.

Goal: one UKI with the production `.linux` and `.cmdline` byte-for-byte, the stock mkinitcpio configuration, the patched `t2bce_*` family (candidate-7.2.7-h1) substituted, no marker hook, no cold PCI guard and no minimal-restore initramfs. The same image boots, hibernates with plain `systemctl hibernate` and restores through the stock `resume` hook. This is the model an upstream kernel package would have, which is why it is tested separately from the private source/restore pair that the product uses today.

A successful run would show that the patched drivers alone, without the cold guard machinery, survive a real S4 round trip. A failed run is evidence about the restore kernel with BCE alive and is not a regression of the product. No result here changes the product's qualification.

## 0. Findings that shaped the design

1. **The Wi-Fi detach helper is not in the rootfs.** `/usr/lib/omarchy/omarchy-t2-hibernate-wifi` does not exist (the 0008 README says it is not installed by package 1.5). Today Wi-Fi detach, Bluetooth power-off and bolt stop are done by the product's preparation adapter (`hibernate/preparation.py`), which this test bypasses. The test therefore carries its own transient preparation, `prepare.py`, which reuses the repo helper `experiments/0008-wifi-hibernate-isolation/omarchy-t2-hibernate-wifi` and the same bolt, Bluetooth and Wi-Fi order as the pair runner.
2. **The stock initramfs already contains radios and a GPU.** The `omarchy-t2-suspend` mkinitcpio build hook unconditionally adds `brcmfmac`, `brcmfmac-wcc`, `brcmfmac-cyw` and `brcmfmac-bca` (plus the Apple Wi-Fi firmware), and the stock configuration adds `t2bce_vhci`, `thunderbolt` and `i915`. It does not contain `t2bce_audio` or `hci_bcm4377`. So "stock configuration" and "no Wi-Fi driver bound in the restore kernel" contradict each other unless an initramfs-only blacklist is added (decision D2).
3. **`t2bce_audio` is loaded late from the rootfs**, and the rootfs copy is the unpatched module. A patched core/dma/vhci with unpatched audio is a mixed family: patch 0002 (audio hibernation callbacks) would be missing from the session that gets saved (decision D1).
4. **The omarchy-t2-suspend hook needs support files in the module root.** It reads `usr/src/omarchy-t2-radio-1.6`, `var/lib/dkms/omarchy-t2-radio/1.6/<release>` and the Apple firmware relative to `--moduleroot`, and it refuses unless every `t2bce_*` resolves under `kernel/drivers/staging/t2bce/`. The builder copies those trees into its private module root and substitutes the four modules in place, so the hook runs unmodified (the source builder removes the hook instead; this builder keeps it so the hooks list stays equal to production).
5. **mkinitcpio `FILES` cannot choose a destination** (`map add_file "${FILES[@]}"` passes one path), so the blacklist file cannot be added by `FILES+=()` without writing under `/etc` on the host. The builder uses a build-time-only install hook (`upstream-model/initcpio/install/omarchy-t2-upstream-model-blacklist`, no runtime script) that places the private file at `/etc/modprobe.d/zz-omarchy-t2-upstream-model.conf` inside the image only. The image's runtime `config` hook lists stay identical to production; the audit enforces that.
6. **The current cmdline** carries `resume=/dev/mapper/root resume_offset=<n> cryptkey=rootfs:/etc/cryptsetup-keys.d/root.key`. The effective HOOKS come from the `/etc/mkinitcpio.conf.d/` drop-ins, not from `/etc/mkinitcpio.conf`, so the private configuration must source the stock file and every drop-in, exactly like the existing builders, and never write under `/etc`.

### Decisions taken (orchestrator)

- **D1, yes:** `t2bce_audio` (patched) is added to `MODULES` in the private configuration only, so the whole t2bce family in the image is the candidate.
- **D2, variant U1b:** an initramfs-only `modprobe.d` blacklist of the brcmfmac family (`brcmfmac`, `brcmfmac-bca`, `brcmfmac-cyw`, `brcmfmac-wcc`). `.cmdline` is untouched. Wi-Fi and Bluetooth load after switch_root from the rootfs radio DKMS stack as usual. The harsher pure-stock variant (U1) is not implemented. **Finding from the first live build:** the production initramfs and ours both carry `updates/dkms/brcmfmac{,-bca,-cyw,-wcc}.ko.zst`, `cfg80211` and `brcmutil` (mkinitcpio does not skip blacklisted modules). The first `verify_blacklist` failed because kmod applies `blacklist` entries to alias lookups even without `--use-blacklist`, so the "alias resolves without the blacklist" probe was run against a configuration that contained our own blacklist and always came back empty. The probe now uses a copy of `etc/modprobe.d` without our file, and the check also requires that the Wi-Fi module files equal production's (never vacuous) and that module file counts follow production through the declared delta.
- **D3:** the transient drop-in does Wi-Fi detach (required), Bluetooth off and bolt stop before `systemd-sleep`, and the reverse afterwards, matching `preparation.py`. Dropping Bluetooth or bolt is a separate later experiment.
- **Routing:** `/run/systemd/system/systemd-hibernate.service.d/zz-upstream-model.conf` resets `ExecStart` to stock `/usr/lib/systemd/systemd-sleep hibernate` and adds the prepare steps; helpers are copied root-owned and hash-pinned under `/run/omarchy-t2-upstream-model/`.
- **Machine state:** the product must be in inactive package maintenance (the tools refuse otherwise) and is reactivated after the campaign only if `assess` reports `unchanged`.

## 1. Machine state and what the test changes

The product goes into maintenance first. In ACTIVE, `/boot/limine.conf` must equal the staged bytes, so any extra block makes the product fail closed, and the update guard refuses transactions while a LoaderEntryOneShot/Default exists. In ACTIVE the `/etc` drop-in `omarchy-t2.conf` routes `systemd-hibernate.service` to `sleep_entry.py`, which vetoes while `package-maintenance.pending` exists; the `/run` drop-in sorts after it and overrides only `ExecStart` and the pre/post steps. The `/etc` drop-in is never edited, so `assess` sees no `control_inventory` drift. `systemctl suspend` (S3) is unaffected.

| Item | Test change | Undo |
| --- | --- | --- |
| `/boot/limine.conf` | one appended owned block (`# BEGIN omarchy T2 upstream model` ... `# END ...`) | the stager removes exactly that block from the current bytes and requires `limine_canonical(current) == limine_canonical(backup)`, robust to snapper rewriting the snapshot region (the backup is never restored verbatim) |
| ESP | new file `/boot/EFI/Linux/mba_t2_upstream_model.efi` | deleted by `rollback`, verified absent |
| EFI variables | LoaderEntryOneShot (set by the stager, consumed by the resume boot); HibernateLocation (set and cleared by systemd-sleep) | both checked absent before and after every cycle |
| Swap header | `S1SUSPEND` to `SWAPSPACE2` after a resume; the flags word changes | nothing; raw header captured before and after every cycle |
| State | new directory `/var/lib/omarchy-t2-upstream-model/` (receipt, guards, attempts, terminal markers) | evidence is preserved; never deleted by the tools |
| `/run` | transient drop-in and helpers | removed by the runner (post-return and on any failure) or by any reboot |
| Product state, pair receipt and custody, ledger, qualification, production UKI, `/etc` drop-in | none | n/a |

Kernel, DKMS radio, firmware and `/etc` must not change during the test window, and no `pacman` runs. An armed one-shot vetoes pacman through the update guard.

## 2. Boot selection and failure handling

One hash-bound one-shot entry of the same image, re-armed before each S4. Limine consumes `LoaderEntryOneShot` at the next boot whatever happens after, so power-on after S4 picks the test entry and the restore happens in that boot. If it fails or hangs, the operator power-cycles and the default (stock `Omarchy.linux-t2`, `default_entry: 2`) boots. A persistent default is never set (`LoaderEntryDefault` must be absent at all times; a temporary default would loop a failing image).

History says a failed restore usually consumes the image (`swsusp_check()` resets the swap signature as soon as it reads the header; every earlier failed vector ended with stock reporting `PM: Image not found (code -22)`). The dangerous residual case is a hang before `swsusp_check`: the image is intact and the stock UKI's own `resume` hook would restore it with an unpatched BCE and no 0005 gate, a never-run vector. The recovery checklist (printed by the runner on every failure and by `run-upstream-model.py recovery`) therefore tells the operator to record observations first, power-cycle, read `journalctl -b` for `Image not found`, read the swap header, never retry, and treat the image hash as terminal. **Stale-image mitigation (do this first after any failed S4).** On the first boot after a failed S4 the stock resume hook could still restore an intact image with an unpatched BCE. Power on, and at the Limine menu highlight the stock `Omarchy` entry, press `E`, move to the `cmdline:` line, press `End`, type a space followed by `noresume`, then press `F10` to boot once. `noresume` is not persistent (nothing is written). Read the swap header from that boot (`sudo python3 packages/t2-suspend/experiments/audit-hibernation-swap-header.py --device /dev/mapper/root --page-offset <resume_offset>`) and only then boot normally. An Arch live-USB header repair (copy `orig_sig` over `sig`) writes the owner's swap file and is not authorised here.

## 3. Tooling (all under `packages/t2-suspend/upstream-model/`)

| File | Purpose |
| --- | --- |
| `build-upstream-model-uki.py` | Private UKI builder. Production `.linux`/`.cmdline` and every other non-`.initrd` section byte-for-byte; stock `/etc/mkinitcpio.conf` plus `/etc/mkinitcpio.conf.d/*.conf` with only the D1/D2 deltas; root-owned inputs required (candidate tree, production UKI, the sourced mkinitcpio files); output directory must not exist and is never on the ESP; the rejected-hash list (including `974246c0...`) refuses the result; the extracted initramfs file manifest is diffed against the production initramfs and recorded in provenance (`initrd-manifest-diff.json`). Allowed differences are only the four `t2bce_*` modules, the module-tree indexes, the `.ko` dependencies of `t2bce_audio`, the blacklist file and a `config` whose runtime hook lists are equal and whose `MODULES` gains at most `t2bce_audio`. Any other difference, removed file or marker/guard-like path refuses. The blacklist is proved effective by resolving the BCM4377 PCI alias with and without `--use-blacklist`. |
| `stage-upstream-model.py` | Single-image stager: `stage`, `verify`, `arm`, `arm-s4`, `mark-booted`, `disarm`, `rollback`, `clear`, `status`. Own state directory, own receipt, entry prefix `MBA-T2-upstream-model-`, BLAKE2b path binding, canonical Limine handling through `boot_policy.limine_canonical`, refuses unless the product is in inactive maintenance, refuses rejected, pair-consumed or terminal hashes, checks the production-kernel policy on the actual PE sections. Never touches the pair receipt, pair custody or product state. |
| `run-upstream-model.py` | Gates G0 to G4: `preflight`, `verify-boot`, `s3`, `s4 --cycle N`, `cleanup`, `recovery`. |
| `prepare.py` | The transient pre/post steps run by the drop-in. Copied to `/run` by the runner; stdlib only. |
| `common.py` | Shared names and pure helpers (phrases, drop-in text, rejected hashes). |
| `initcpio/install/omarchy-t2-upstream-model-blacklist` | Build-time-only mkinitcpio hook for the blacklist file. |

The builder, `common.py` and the install hook must be root-owned and not group/world writable, like every other builder input, so run the builder from a root-owned export of the reviewed commit (step 1 below), never from the working tree. The stager and runner likewise run from the export, and the stager takes `db.lck` and the physical cycle lock around `stage`, `arm`, `arm-s4` and `rollback`, re-reading `limine.conf` immediately before each write.

**Pair interplay.** The pair receipt's steady `source-arming` state (ACTIVE product) is normal and allowed; the stager refuses while a pair transaction is in a transient state (`preparing`, `restore-arming`, `rolling-back`, `stage-failed-recovered`). It records the pair receipt hash at staging and refuses to arm if it changes. Our rollback must therefore precede any pair retire, rollback or rebind step; `reactivate` and the maintenance runbook steps come after `rollback` and `clear`.

Tests: `packages/t2-suspend/tests/test-upstream-model-{builder,stage,prepare,runner}.py` with the shared fixture `upstream_model_fixture.py`; registered in `test/shell.d/t2-suspend-installer-test.sh`.

### Gates

- **G0 preconditions** (`preflight`, and the start of every phase): model MacBookAir9,1; product in inactive maintenance and the update guard exits 0; `assess` runnable; no other pending or active product file and no opt-in; no EFI default and (outside the armed window) no one-shot; production UKI, Limine and ESP image match the stager receipt; swap header `SWAPSPACE2`; `/sys/power/resume_offset` equals the cmdline value and Btrfs `map-swapfile`; `/proc/swaps` has exactly one non-zram candidate, `/swap/swapfile`; `disk` is `[platform]`; `pm_test` is `[none]`; `systemd-inhibit --list` shows only delay locks; the image hash is not rejected or terminal.
- **G1 ordinary boot** (`verify-boot`): selected entry equals the test entry; `/proc/cmdline` equals the production UKI `.cmdline`; the four loaded `t2bce_*` srcversions equal the candidate pins (so the patched audio is what runs); the first brcmfmac kernel message comes after PID 1 starts on the real root (the blacklist worked); no failed units; the six PCI functions are bound; the internal keyboard and trackpad are registered; typed physical-input confirmation. The existing capture-physical-input monitor is not copied into the repo, so this gate uses the typed confirmation only.
- **G2 S3** (`s3`): plain `systemctl suspend` with the same health checks before and after, the S3 entry and exit journal lines, no `HC died`, `t2bce` errors or call traces, and a typed confirmation. S3 must pass on the boot before any S4. The error classifier matches real error reports only (a `t2bce*:` driver prefix with error/failed/timed out, a `status=`/`error`/`ret`/`rc` label with a negative errno, `-EIO` style names, `PM: ... failed` or `returns -N`, `HC died`, `Call Trace`, `BUG:`, `Oops`) and never device or bus names such as `usb-t2bce_vhci-5`. The Bluetooth `Injecting HCI hardware error event` after S3 is the radio package's transport rebuild (patches/bluetooth/0003), not a fault, and is not flagged. A genuine S3 failure is not repeatable on that image (no-repeat rule). `s3` may be repeated on the same boot only when the previous run was interrupted (state `started`, no saved journal) or when it was a classifier-only failure: re-assessed with the current classifier its saved journal has zero problems and every recorded problem was just a journal line. The old `s3.json` is archived as `s3-<n>.json` and its capture files move to `prior-s3-<n>/`, never deleted; the new record carries `rerun_reason`. A passed record always blocks a re-run. The classifier also flags `Freezing of tasks failed` and `PM: Error -N creating image`, accepts the dev_err form `t2bce_core 0000:74:00.1: ...`, and ignores `module verification failed` (taint notice). `run-upstream-model.py s3-reassess` is read-only: it re-evaluates the saved S3 journal with the current classifier and prints a verdict without changing any state; a fresh S3 is still what qualifies S4. The S4 post-return check uses the same classifier.
- **G3 S4 cycle N** (`s4 --cycle N`): G0 again; cycle order 1 and 2 on AC, 3 on battery (charger unplugged before starting, `Discharging` and at least 70%); cycle N+1 requires N `returned-and-cleaned` on the same original boot id; a typed attendance phrase bound to the image prefix, boot id prefix, cycle number and power source (`I am at the MacBook with the power button reachable; image <12 hex> boot <8 hex> cycle <N> on <AC|battery>; stock is the recovery choice`), written to a root 0600 acceptance file that expires after 30 minutes and is re-verified immediately before the power write; the desktop is locked with `omarchy-system-sleep-lock`; the `/run` drop-in is installed and read back from `systemctl show`; the one-shot is armed through the stager and read back; power source, swap target, header, inhibitors and HibernateLocation are re-read; the durable guard `guards/<image>/cycle-N` is created `O_EXCL` and fsynced; only then `systemctl hibernate` runs.
- **G4 post-return** (same process after the restore): boot id unchanged; drop-in and helpers removed and the product routing shown again by `systemctl show`; no one-shot or default; selected entry equals the test entry; swap target unchanged and header `SWAPSPACE2`; health with a 90 second settle window (Wi-Fi rebound on `0000:73:00.0`, input, units); the journal has the hibernation entry line and no `HC died`, `t2bce` error or call trace; `mark-booted`; typed confirmation; attempt state `returned-and-cleaned`.
- **Terminal on failure:** any failure after the guard is created marks the image hash terminal (`terminal/<sha>.json`, exclusive create, never removed) and prints the recovery checklist. A failure before the guard (a mistyped phrase, a failed lock, an expired acceptance) unwinds the drop-in and the one-shot, leaves the cycle retryable and is not terminal. `cleanup` settles an interrupted runner the same way: no guard means retryable, a guard means terminal.

### Evidence recorded per step

Raw swap header (before, after), `journalctl -b` slice from a pre-write cursor filtered on `PM:`, `t2bce`, `bce`, `vhci`, `HC died`, `timeout`, `brcmfmac`, `hci_bcm4377`, `thunderbolt`, `i915`, `nvme`, `btrfs`, `Call Trace`, the hibernation entry line, the kernel taint flag, srcversions and PCI driver bindings for `74:00.0` to `74:00.3` and `73:00.0`, `lspci -k`, `lsmod`, input devices, `bluetoothctl show`, Wi-Fi link, `wpctl status` and `aplay -l`, `boltctl list`, `systemctl --failed`, `btrfs device stats`, battery and AC state, the EFI variable listing, the acceptance and guard records and the typed-phrase hashes. They land in `/var/lib/omarchy-t2-upstream-model/attempts/<image sha256>/<phase>/` as root 0600 files. The restore kernel's own messages are not recoverable (no markers, no persistent journal); that loss is the accepted cost of the test. Operator photos and notes of a failed screen are the substitute.

## 4. Operator procedure

Run everything in your own terminal (typed phrases are read from `/dev/tty`; the agent shell has none). Do not run privileged Python from the writable workspace: export a reviewed commit to a root-owned directory first. Reconcile state before starting: `docs/t2-suspend/RESUME.md`, `handoff.json`, `git log -5 --oneline`, `cat /proc/sys/kernel/random/boot_id`, no other autonomous agent.

```bash
REPO=/home/jjc/Projects/MBA_9_1
COMMIT=$(git -C "$REPO" rev-parse HEAD)    # the reviewed commit that contains packages/t2-suspend/upstream-model
TOOLS_ROOT=/var/lib/omarchy-t2-upstream-model-tools
TOOLS=$TOOLS_ROOT/packages/t2-suspend/upstream-model
CANDIDATE_SRC=/home/jjc/.local/state/codex-mba-autonomous/t2bce-7.2.7-hardening/candidate-7.2.7-h1
BUILD=$TOOLS_ROOT/build-$(date +%Y%m%d)
```

1. **Export the tools and the candidate to root-owned locations.**

   ```bash
   sudo install -d -m 0755 "$TOOLS_ROOT"
   git -C "$REPO" archive "$COMMIT" packages/t2-suspend | sudo tar -x -C "$TOOLS_ROOT"
   sudo cp -a --reflink=auto "$CANDIDATE_SRC" "$TOOLS_ROOT/candidate-7.2.7-h1"
   sudo chown -R root:root "$TOOLS_ROOT"
   sudo chmod -R go-w "$TOOLS_ROOT"
   ```

2. **Run the offline tests from the export** (no hardware): `python3 "$TOOLS_ROOT/packages/t2-suspend/tests/test-upstream-model-runner.py"` and the stage, prepare and builder tests.

3. **Build the image** (offline; changes no installed file):

   ```bash
   sudo python3 "$TOOLS/build-upstream-model-uki.py" --candidate-source "$TOOLS_ROOT/candidate-7.2.7-h1" --output "$BUILD" --experiment-id upstream-model-h1-$(date +%Y%m%d)
   ```

   The builder refuses unless the running kernel release equals the candidate's, the production cmdline equals the running one, and every input is root-owned. Read `$BUILD/provenance.json` and `$BUILD/initrd-manifest-diff.json` with `sudo`: the diff must list only the four `t2bce_*` modules, module-tree indexes, `snd*` dependencies of `t2bce_audio`, and the blacklist file. An independent audit of the build output is required before staging (AGENTS.md).

4. **Pause the product** (maintenance) through the reviewed native path, see [MAINTENANCE-RUNBOOK.md](MAINTENANCE-RUNBOOK.md):

   ```bash
   NATIVE=/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py
   sudo /usr/bin/python3 -I -B "$NATIVE" maintenance
   sudo /usr/bin/python3 -I -B "$NATIVE" assess
   ```

5. **Stage, then refresh Limine with one stock boot.** Staging appends the block, writes the ESP image and arms nothing.

   ```bash
   sudo python3 "$TOOLS/stage-upstream-model.py" stage --build "$BUILD"
   sudo python3 "$TOOLS/run-upstream-model.py" preflight
   ```

   Reboot into stock once so Limine advertises the entry. After the reboot, from stock:

   ```bash
   sudo python3 "$TOOLS/stage-upstream-model.py" arm
   ```

   Reboot. The one-shot boots the image once.

6. **G1, on the test boot:** `sudo python3 "$TOOLS/run-upstream-model.py" verify-boot`. Type the printed confirmation only after checking keyboard, trackpad, Wi-Fi and audio.

7. **G2:** `sudo python3 "$TOOLS/run-upstream-model.py" s3`. Press Enter, wake with a key, type the confirmation.

8. **G3/G4, cycles 1 and 2 on AC, cycle 3 on battery:**

   Run the S4 runner as a transient systemd unit with a pty, so a dying terminal (SIGHUP) cannot kill it mid-cycle; it also converts SIGHUP, SIGTERM and SIGINT to a clean exit that removes the drop-in and disarms the one-shot:

   ```bash
   S4="sudo --preserve-env=OMARCHY_PATH systemd-run --pty --wait --collect --setenv=SUDO_UID --setenv=SUDO_USER --setenv=OMARCHY_PATH python3 $TOOLS/run-upstream-model.py s4"
   $S4 --cycle 1
   $S4 --cycle 2
   # unplug the charger; wait for Discharging at 70% or more
   $S4 --cycle 3
   ```

   The runner needs the desktop user via `sudo` (it reads `SUDO_UID` and `SUDO_USER` to run `omarchy-system-sleep-lock`) and `OMARCHY_PATH`, which it passes to the helper together with `PATH=$OMARCHY_PATH/bin:/usr/local/bin:/usr/bin` and invokes the helper by absolute path, because `omarchy-shell` fails at once without it and the helper hides that error; if the runner environment lacks it, the user's `systemctl --user show-environment` is consulted, and the value must be an absolute Omarchy checkout (`bin/omarchy-system-sleep-lock` and `shell/shell.qml` present). A cycle refused at the lock is `refused-before-guard`: nothing is consumed and the same cycle is re-run, the old attempt files moving to `cycle-N/prior-<time>/`. If `systemctl hibernate` returns non-zero while the swap header is still `SWAPSPACE2` and the journal since the guard has no `PM: hibernation: hibernation entry` line (a `prepare.py` pre failure or a swap refusal), the attempt is recorded as `refused-before-transition`: not terminal, the guard is renamed to `cycle-N.refused-<time>` and kept as evidence, the prior attempt files move to `cycle-N/prior-<time>/`, and the same cycle can be retried after a fresh typed phrase. Any evidence of a transition (header changed, entry line present, unreadable header or journal) makes the image terminal; a repeat then needs a new image hash and a new design review. If the runner itself died on the test-image boot (terminal closed, killed), run `sudo python3 "$TOOLS/run-upstream-model.py" recover` there: it removes the drop-in, disarms a still-armed one-shot, settles attempts (with a guard: terminal; without: retryable), never deletes guards or evidence, and leaves the receipt `booted` (run `verify-boot` again on that boot) or `disarmed`. From the stock boot use `cleanup`. `recover` adopts the current boot through the stager's `adopt_boot`, which deliberately skips the boot-id checks of `mark-booted` (the adopted boot is by definition not the one the receipt expected); that is safe because every attempt that owned a guard is made terminal first, arming refuses terminal images, and `verify-boot` must be re-run on the adopted boot before S3 or S4 proceeds. From the moment the guard exists the runner ignores SIGHUP, SIGTERM and SIGINT through `systemctl hibernate` and the post-return checks, because the hibernate job continues in pid 1 even if the client dies; if the power call itself is aborted the runner unwinds nothing (drop-in and one-shot stay), marks the image terminal and prints the stale-image warning: on the next boot use the `noresume` edit, read the swap header, then run `recover` (test boot) or `cleanup` (stock boot). A non-zero return is judged retryable only if every source agrees that nothing began: `journalctl --sync`, the SWAPSPACE2 header, no HibernateLocation variable, no freeze/swsusp/Image/entry lines in the kernel journal or new `dmesg` output since the cursor, and no systemd-sleep sleep lines in the journal; an unreadable source counts as a hit. All mutating runner phases (`verify-boot`, `s3`, `s4`, `cleanup`, `recover`) hold a non-blocking flock on `/var/lib/omarchy-t2-upstream-model/runner.lock` and refuse if another runner holds it. Stay at the machine with the power button reachable; the display goes dark, the machine powers off, and after you press the power button the restore boot selects the test entry and the same terminal session returns. On any failure follow the printed checklist and stop: the image is terminal.

9. **Return to stock and undo.** Reboot to stock (the default), then:

   ```bash
   sudo python3 "$TOOLS/run-upstream-model.py" cleanup
   sudo python3 "$TOOLS/stage-upstream-model.py" rollback
   sudo python3 "$TOOLS/stage-upstream-model.py" clear
   sudo /usr/bin/python3 -I -B "$NATIVE" assess
   ```

   Then `sudo python3 "$TOOLS/run-upstream-model.py" pre-reactivate-check`, which refuses while the `/run` drop-in, `/run/omarchy-t2-upstream-model`, a one-shot, the receipt or an unsettled attempt remains (a reboot also clears `/run`, but run `cleanup` anyway so attempts are settled). Only if both `assess` reports `unchanged` and the check passes: `sudo /usr/bin/python3 -I -B "$NATIVE" reactivate`. Anything else keeps hibernation off (fail-closed; nothing to repair by hand; see the maintenance runbook and [REQUALIFICATION.md](REQUALIFICATION.md)). After reactivation run `omarchy-update-t2-hibernation post` if the update hook is in use. The product's routine ledger chain is not advanced by test cycles; its next cycle goes from a fresh boot, as after any reboot.

10. **Record the outcome** in `RESUME.md` and `EVIDENCE-7.2.7.md` with the evidence directory path and the image SHA-256 before doing anything else.

## 5. Risks, ranked

1. **BCE alive in the restore kernel, then frozen by the boot kernel's own patched callbacks.** The core of the model. v9 (BCE and Wi-Fi forced into the restore initramfs) failed real S4 before restored userspace, but v9 predates 0005 to 0017. A teardown stall in the restore kernel is a hang before the image copy: safe (image intact or consumed), costs a power cycle.
2. **Wi-Fi bound during the atomic copy.** Removed by D2 (U1b). The G1 log-order check proves the blacklist took effect before the image is used.
3. **Firmware state.** Every successful S4 so far restored with the T2 firmware cold and untouched by BCE. Here it sits nearer the S3 `test_resume` state. A failure would show as lost keyboard and trackpad after a session that otherwise returns; recoverable by reboot.
4. **i915, Thunderbolt and Plymouth in the restore kernel.** All removed by `--minimal-restore-devices` in every image that restored successfully. Thunderbolt NHI freeze/restore on Titan Ridge is the less certain. Attach nothing to the USB-C ports; bolt is stopped by `prepare.py`.
5. **Stale-image hazard after a failure before `swsusp_check`:** stock `resume` could restore with an unpatched BCE (section 2). Procedure only.
6. **Loss of evidence on failure** (no markers, restore kernel messages not persisted): not a safety risk.
7. **Harness risks:** a `/run` drop-in left after a failed cycle (cleared by any reboot and by `cleanup`), an armed one-shot (removed by `disarm`), snapper rewriting `limine.conf` (handled by the canonical compare and block-only removal).

## 6. Open questions (unverified)

- Whether `systemd-sleep hibernate` on this machine selects `/swap/swapfile` rather than zram (zram has priority 100, the swapfile 0). G0 requires exactly one non-zram swap candidate and verifies `/sys/power/resume(_offset)` against the cmdline and Btrfs before the write and again after the return, but systemd writes them inside the power transition, so a wrong pick can only be detected after the fact.
- Whether `omarchy-system-sleep-lock` succeeds when invoked through `runuser` from a root runner (it needs the user's session bus); a failed lock refuses before any guard.
- The exact `systemctl show` rendering of several `ExecStartPre`/`ExecStopPost` entries (the parser reads every `argv[]=` in each line).
- Whether the installed DKMS radio modules equal the hardened `radio-h1` candidate (not compared; this test substitutes only `t2bce_*`).
- Whether the current ordinary-boot `dmesg` records PID 1 messages early enough for the initramfs Wi-Fi log-order check; if not, G1 refuses rather than guessing.

## 7. Observed cycle 1 (2026-10-08)

Image `58e41e2972eec3013adc5c48e05d8b318d1652df9fcb969c0190333c5fd86100`, test boot `c6ed6685-6ddc-4828-bf30-5d850ac8f58f`, AC. Observed. The gates after G2 were not completed. The attempt did not reach `returned-and-cleaned` and carries no qualification. The product stays in package maintenance.

The test boot journal has `PM: hibernation: hibernation entry` (monotonic 156267.510075) and `PM: hibernation: hibernation exit` (156273.895061). `attempt.json` is `returned` with `hibernate_attempted` true, `hibernate_returncode` 0, and `real_s4_attempted` true. `post.json` was not written. Guard `cycle-1` exists. `require_sequence` refuses another cycle 1 while that guard or that attempt state remains, and it refuses cycles 2 and 3 until cycle 1 is `returned-and-cleaned` on that same boot. Do not repeat the cycle.

Resume radio captures on that test boot: `post-wifi-link.txt` is rc 0 with an empty `iw` body. `post-bluetooth.txt` has `Powered: no` and `PowerState: on`. `prepare.post` calls `set_bluetooth(True)` when `bluetooth_was_powered` is set, and `set_bluetooth` raises `Bluetooth did not power on` after `bluetoothctl power on` does not leave `Powered: yes`. The test boot logged that sentence at monotonic 156277.733887. Stock boot `8f22e906-1679-47b2-89c9-8e9b4f5e3a04` (Limine `Omarchy.linux-t2`) is a later fresh boot. It logged `PM: Image not found (code -22)`. Its Wi-Fi and Bluetooth came up, so the miss is the test-image resume path.

The 2026-10-06 userspace refusal is a different event, archived as `prior-1791480678` with `reclassified_from` `failed-terminal` and `real_s4_attempted` false. Its error text says the journal lacks the hibernation entry line.

Hypothesis only: the runner stopped during `post_return` after saving `returned` and before `post.json`, and S4 may need the `hci_bcm4377` half of `experiments/0005`. Those are not verified causes and this section does not change the runner or the radio drivers.
