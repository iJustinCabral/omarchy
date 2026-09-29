# Unattended agent loop on the MacBookAir9,1 test machine

## Purpose and scope

This document records the host infrastructure that lets a coding agent keep working on T2 hibernation across repeated reboots of the MacBookAir9,1 ("kenobi", user `jjc`, Omarchy/Hyprland, repo `/home/jjc/Projects/MBA_9_1`, branch `fix-t2-vintage-mac-support`) with nobody at the keyboard. It exists so that, if the laptop is lost or reinstalled, a person can rebuild the loop.

This is reference-machine infrastructure. It is not an Omarchy feature, it is not installed by this repository, and nothing under `install/` or `bin/` depends on it. Every artifact below lives in the operator's home directory, in `/etc`, or in `/boot`, and none of it is tracked in git.

The loop was originally driven by Codex (`codex-mba-*` scripts). It is now being driven by Claude Code (Opus orchestrator, Sonnet sub-agents). Both variants are documented: the Claude Code variant is primary (section 4) and the Codex variant is kept as an alternative (section 5). Layers (a) to (d) and (g) to (i) are agent-independent.

The design was adapted from a reference runbook written for a different machine (MacBookPro16,1, user `bromarch`, project `t2-touchid-linux`, with Limine, kitty and `codex resume --last`). Machine-specific values from that machine are not reused here.

Differences from that reference design:

- Hibernation resume configuration is deliberately kept (`resume=` on the kernel command line and the `resume` initramfs hook), because hibernation is the project being developed.
- `sshd` is disabled here and `~/.ssh` does not exist. There is currently no remote recovery path. Adding one is recommended optional hardening (layer c).
- The terminal is `foot`, launched with a working directory, and the agent is started by a wrapper script instead of `resume --last` from `$HOME`.

Related documents: [RESUME.md](RESUME.md) is the in-repo resume source of truth, [HIBERNATION.md](HIBERNATION.md) holds the hardware evidence, and [AGENTS.md](../../AGENTS.md) holds the hardware safety rules the agent must obey.

## Security boundary

This setup is only for a dedicated test machine. It deliberately weakens several protections:

- A LUKS key is embedded in the initramfs inside the UKI on the unencrypted EFI System Partition. Anyone who can copy both the disk and the ESP can decrypt the root volume. The original recovery passphrase stays in its keyslot.
- A LUKS header backup is stored on `/boot`. A header backup together with its matching key should never be stored together off-machine.
- The login user has passwordless `sudo`. On this machine `sudo -n -l` shows a blanket `(ALL : ALL) NOPASSWD: ALL` rule in addition to the narrow delayed-reboot rule (layer g), and the machine autologins to a desktop session.
- The agent runs unattended with prompts bypassed or pre-approved. It can run arbitrary commands as the user, and privileged commands where sudo is passwordless.

Do not use this on a machine holding data you cannot afford to expose. Never commit any of the following to this repository or any other:

- the LUKS key (`/etc/cryptsetup-keys.d/root.key`) or any copy of it
- LUKS header backups (`/boot/luks-header-before-codex-autonomy.img`)
- agent authentication state (`~/.codex/auth.json`, Claude Code credentials under `~/.claude/`, API tokens)
- NetworkManager connection files (`/etc/NetworkManager/system-connections/`), which contain Wi-Fi secrets
- private SSH keys and `~/.ssh` contents
- the extracted unlock assets, including the mkinitcpio and Limine drop-ins if they reference key paths, and any UKI, initramfs or `.efi` image, since the UKI contains the key
- `handoff.json` and other files under `~/.local/state/codex-mba-autonomous/` (local-only state, may contain hardware evidence and approval records)

## Layer-by-layer rebuild on a fresh install

Assumptions: Omarchy with classic mkinitcpio `encrypt` hook, Limine UKIs, SDDM, NetworkManager, LUKS root on `/dev/nvme0n1p2` mapped as `/dev/mapper/root`. Confirm before changing anything:

```bash
#!/bin/bash
findmnt -no SOURCE,FSTYPE /
lsblk -o NAME,PATH,FSTYPE,TYPE,MOUNTPOINTS,UUID,PARTUUID
mkinitcpio -H encrypt
[[ -x /usr/bin/limine-mkinitcpio ]] && echo "limine-mkinitcpio present"
```

The current helper `~/.local/bin/codex-mba-enable-unattended-boot` (present) performs layers (a) and (b) and part of (d) in one interactive run. It hard-codes this machine's LUKS UUID and PARTUUID, so on a rebuilt machine edit those values first. Its assets are in `~/.local/share/codex-mba-autonomous/` (present): `auto-unlock-mkinitcpio.conf`, `auto-unlock-limine.conf` and `80-codex-mba-limine-timeout`. The layers below show the manual equivalent.

### (a) Limine auto-boot and timeout hook

Limine must pick Linux without waiting indefinitely. Regeneration of `/boot/limine.conf` rewrites the timeout, so a post hook reapplies it every time. The installed hook is `/etc/boot/hooks/post.d/80-codex-mba-limine-timeout` (directory listing verified; file mode not verified as root) with this content:

```bash
#!/bin/bash

set -euo pipefail

config=/boot/limine.conf
if grep -Eq '^[#[:space:]]*timeout:' "$config"; then
  sed -i -E '0,/^[#[:space:]]*timeout:[[:space:]]*.*/s//timeout: 3/' "$config"
else
  sed -i '1itimeout: 3' "$config"
fi
```

Install and verify:

```bash
sudo install -d -o root -g root -m 0755 /etc/boot/hooks/post.d
sudo install -o root -g root -m 0755 ~/.local/share/codex-mba-autonomous/80-codex-mba-limine-timeout /etc/boot/hooks/post.d/80-codex-mba-limine-timeout
sudo /usr/bin/limine-mkinitcpio
sudo grep -Fxq 'timeout: 3' /boot/limine.conf && echo "timeout ok"
sudo sed -n '1,35p' /boot/limine.conf
```

Also confirm `default_entry` points at the intended Linux entry. The reference machine needed `ENABLE_VERIFICATION=no` in `/etc/default/limine` because its UKI is signed after generation; apply that only if you observe a post-signing hash mismatch that blocks auto-boot (this machine's setting is root-only; not verified).

### (b) LUKS unattended unlock

Back up the header, create a 64-byte key, add it to a free keyslot without removing the passphrase slot, and prove it works:

```bash
ROOT_LUKS=/dev/nvme0n1p2
ROOT_KEY=/etc/cryptsetup-keys.d/root.key
HEADER_BACKUP=/boot/luks-header-before-codex-autonomy.img
sudo cryptsetup luksHeaderBackup "$ROOT_LUKS" --header-backup-file "$HEADER_BACKUP"
sudo chmod 0600 "$HEADER_BACKUP"
sudo install -d -o root -g root -m 0700 /etc/cryptsetup-keys.d
sudo dd if=/dev/urandom of="$ROOT_KEY" bs=64 count=1 conv=fsync status=none
sudo chmod 0600 "$ROOT_KEY"
sudo cryptsetup luksAddKey "$ROOT_LUKS" "$ROOT_KEY"
sudo cryptsetup open --test-passphrase --key-file "$ROOT_KEY" "$ROOT_LUKS"
sudo cryptsetup luksDump "$ROOT_LUKS"
```

Embed the key and point the `encrypt` hook at it. The installed drop-ins are `/etc/mkinitcpio.conf.d/20-codex-mba-auto-unlock.conf` and `/etc/limine-entry-tool.d/20-codex-mba-auto-unlock.conf` (both exist). Their effective lines are:

```bash
# /etc/mkinitcpio.conf.d/20-codex-mba-auto-unlock.conf
FILES+=(/etc/cryptsetup-keys.d/root.key)

# /etc/limine-entry-tool.d/20-codex-mba-auto-unlock.conf
KERNEL_CMDLINE[default]+=" cryptkey=rootfs:/etc/cryptsetup-keys.d/root.key"
```

Do not remove the hibernation settings from the base configuration: the command line must still contain `resume=/dev/mapper/root` (and the resume offset arguments used by the project) and the initramfs must still carry the `resume` hook. Rebuild and verify, keeping [AGENTS.md](../../AGENTS.md) hibernation safety rules in mind (any rebuilt image must keep the production kernel policy):

```bash
UKI=/boot/EFI/Linux/omarchy_linux-t2.efi
sudo /usr/bin/limine-mkinitcpio
sudo lsinitcpio "$UKI" | grep -F 'etc/cryptsetup-keys.d/root.key'
sudo objcopy --dump-section .cmdline=/dev/stdout "$UKI" /dev/null 2>/dev/null | tr '\0' '\n' | grep -E 'cryptkey=rootfs:|resume='
```

Final proof is a real reboot with nobody typing a passphrase.

### (c) Network, optional sshd, optional wayvnc

Network must return without a desktop login. Observed connections on this machine: Wi-Fi `Yavin-4` and `Wired connection 1`, both with autoconnect `yes`. On a rebuild:

```bash
nmcli connection modify '<connection-name>' connection.autoconnect yes connection.autoconnect-retries 0
sudo systemctl enable NetworkManager.service
systemctl is-enabled NetworkManager.service
nmcli -f NAME,AUTOCONNECT,DEVICE connection show
```

Current state: `NetworkManager` is enabled and `sshd` is disabled (both verified). `~/.ssh` does not exist, so there is no remote path to recover a stuck machine. Recommended optional hardening, not part of the current setup:

```bash
install -d -m 0700 ~/.ssh
# append the operator's public key to ~/.ssh/authorized_keys, mode 0600
sudo tee /etc/ssh/sshd_config.d/50-key-only.conf >/dev/null <<'EOF'
PasswordAuthentication no
PermitRootLogin no
AllowUsers jjc
EOF
sudo systemctl enable --now sshd.service
```

Only do this on a trusted network. `wayvnc` is not installed here; if remote screen access is wanted, install it and run it as a user service under `graphical-session.target`, again only on a trusted network.

### (d) SDDM autologin and linger

`/etc/sddm.conf.d/autologin.conf` (verified) contains:

```ini
[Autologin]
User=jjc
Session=omarchy.desktop
```

Enable services and user lingering:

```bash
sudo systemctl enable sddm.service
sudo loginctl enable-linger jjc
ls /var/lib/systemd/linger
systemctl is-enabled sddm NetworkManager
```

`/var/lib/systemd/linger` lists `jjc` on this machine (verified).

### (e) Agent autostart via Hyprland autostart.lua

Omarchy's Hyprland configuration loads `~/.config/hypr/autostart.lua`, and `o.launch_on_start` hands the command to UWSM. Back the file up before editing (the current backup is `~/.config/hypr/autostart.lua.bak.codex-mba-1789910828`). The line currently present is the Codex one:

```lua
o.launch_on_start("foot -a codex-mba-autostart -T Codex-MBA -D /home/jjc/Projects/MBA_9_1 /home/jjc/.local/bin/codex-mba-autoresume")
```

The Claude Code equivalent is given in section 4. Use exactly one agent autostart line. The window class and title make the single expected agent window identifiable in `hyprctl clients`. This file is host-local and is not installed by the repository.

### (f) Agent runtime config

The agent must be able to run without prompts, while the repository rules in [AGENTS.md](../../AGENTS.md) still bind it. Codex uses the profile `~/.codex/mba-autonomous.config.toml` (section 5). Claude Code uses flags in the wrapper and/or settings files (section 4). Verify by starting the wrapper by hand once and confirming the agent starts in the repo directory with the intended model and permission mode. Never copy authentication state between machines or into the repo; log in again on the new machine.

### (g) Passwordless privilege scope for the delayed reboot

The reboot dispatcher runs `sudo -n /usr/bin/systemd-run ...`, so the login user needs non-interactive sudo for that command. `sudo -n -l` on this machine lists that exact rule, and also a blanket `(ALL : ALL) NOPASSWD: ALL`, which the project's privileged helpers currently rely on. The files under `/etc/sudoers.d` are root-only, so which file grants each rule was not verified. The narrow rule alone looks like this, validated with `visudo -c`:

```bash
sudo tee /etc/sudoers.d/50-agent-reboot >/dev/null <<'EOF'
jjc ALL=(root) NOPASSWD: /usr/bin/systemd-run --unit=codex-mba-delayed-reboot --on-active=8s --timer-property=AccuracySec=100ms /usr/bin/systemctl reboot
EOF
sudo chmod 0440 /etc/sudoers.d/50-agent-reboot
sudo visudo -c
sudo -l -U jjc
```

The project also performs other privileged actions (staging boot images, installing the runtime) through its own reviewed helpers, which is why the blanket rule exists. Narrowing it to the reviewed helpers is recommended hardening, but it must be done carefully: an unattended agent that loses a needed grant will stall at a password prompt.

### (h) Delayed-reboot dispatcher

`~/.local/bin/codex-mba-reboot` (present) is the only supported way for the agent to reboot. Behaviour, in order:

1. Refuses in a snapshot recovery session (overlay root or `/.snapshots/` on the command line).
2. Refuses if the worktree is dirty, HEAD is detached, no upstream exists, local HEAD differs from the upstream tracking ref, or `origin/<branch>` differs from local HEAD (checked with `git ls-remote`).
3. Refuses if a pacman lock, a T2 hibernation diagnostic, a DKMS/make build, or a source-preparation script is running, or if the delayed reboot unit is already armed.
4. `--check` runs those checks and exits without changing anything.
5. Otherwise writes `handoff.json` (boot_id, boot_started, branch, head, upstream, created, plus fields merged from any existing handoff or `handoff-details.json`, mode 0600), creates the `continue` marker, removes `continue.dispatched`, and arms the timer:

```bash
sudo -n /usr/bin/systemd-run \
  --unit=codex-mba-delayed-reboot \
  --on-active=8s \
  --timer-property=AccuracySec=100ms \
  /usr/bin/systemctl reboot
```

If arming fails, the continue marker is removed. The 8 second delay lets the agent's final tool result be persisted before the machine goes down. The script and unit keep their `codex-mba-` names for both agent variants so that the sudoers rule and the state directory stay unchanged. On a rebuild, copy the script from a backup or rewrite it from this description; the project path, state directory and unit name are the only machine-specific values.

### (i) Post-boot reconciliation

After every boot the agent must reconcile from machine evidence before doing any hardware work. See section 6 for the exact checks. The startup wrapper only decides whether to inject the resume prompt; reconciliation is the agent's job.

## Claude Code variant (primary)

### Wrapper

Create `~/.local/bin/claude-mba-autoresume` (mode 0755). It changes to the repository and runs `claude --continue`, which resumes the most recent session for that working directory. It passes a resume prompt only when the continue marker exists, moving the marker to `continue.dispatched` first so the prompt is delivered at most once per reboot:

```bash
#!/bin/bash

set -euo pipefail

project="/home/jjc/Projects/MBA_9_1"
state_dir="/home/jjc/.local/state/codex-mba-autonomous"
continuation="$state_dir/continue"
dispatched="$state_dir/continue.dispatched"

cd "$project"

claude_args=(
  --continue
  --model opus
)

if [[ -f $continuation ]]; then
  mkdir -p "$state_dir"
  mv "$continuation" "$dispatched"
  exec claude "${claude_args[@]}" \
    "Resume the autonomous hibernation goal as the Opus orchestrator. Delegate implementation and independent audits to Sonnet sub-agents with disjoint file ownership and bounded task context. First reconcile the current boot against $state_dir/handoff.json, docs/t2-suspend/RESUME.md and the repository checkpoint. Do not repeat a failed hardware test; continue from durable machine evidence. Keep physical boot, EFI, module-load and power transitions serialized under the orchestrator."
else
  exec claude "${claude_args[@]}"
fi
```

Notes:

- The state directory keeps its `codex-mba-autonomous` name so the reboot dispatcher and existing handoff files work for either agent.
- If `claude --continue` finds no prior session it starts a fresh one; the operator should then paste the resume prompt or point the agent at [RESUME.md](RESUME.md).
- `--continue` resumes the most recent session for the current directory. Do not start any other Claude Code session in the repo directory, or it may become the "most recent" one and be resumed instead. Use a worktree or another directory for side sessions.
- `claude` is installed through mise at `~/.local/share/mise/installs/claude/latest/claude` (verified). Make sure that location is on `PATH` for the UWSM-launched process, or use the absolute path in the wrapper.

### Autostart line

Replace the Codex line in `~/.config/hypr/autostart.lua` (after backing the file up) with:

```lua
o.launch_on_start("foot -a claude-mba-autostart -T Claude-MBA -D /home/jjc/Projects/MBA_9_1 /home/jjc/.local/bin/claude-mba-autoresume")
```

Do not keep both lines active, or two agents will fight over the repository and hardware.

### Permissions for unattended operation

Unattended operation needs Claude Code to run tools without stopping for approval. This document does not configure that; it is an operator decision. The options:

- A `--permission-mode` flag in the wrapper's `claude_args`. Modes range from prompting (default) through auto-accepting edits and an automatic classifier-gated mode to a full bypass of all permission checks.
- Permission rules in the user settings file `~/.claude/settings.json` (present on this machine) or a project-level `.claude/settings.json` (absent on this machine): `permissions.allow`, `permissions.ask` and `permissions.deny` lists, and `defaultMode`.
- An explicit allowlist of the commands the loop actually needs (git, the repo's `bin/omarchy-*` helpers, `~/.local/bin/codex-mba-reboot`, read-only inspection commands), with deny rules for the dangerous ones.

Recommendation: prefer a scoped allowlist, or the auto mode with a reviewed allowlist, over a blanket bypass. A blanket bypass combined with autologin, passwordless sudo and an embedded LUKS key gives an unattended process unlimited authority, so a single bad instruction can be unrecoverable. Deny rules should cover, at minimum, the hardware safety rules in [AGENTS.md](../../AGENTS.md): restaging the rejected UKI images, replacement-kernel images, and anything that re-arms a consumed power-management guard. Because prompts cannot be answered by anyone while unattended, any action outside the allowlist will stall the loop with a visible prompt; that is a safe failure mode and is preferable to bypassing.

### Model routing

- The orchestrator (the resumed top-level session, Opus) plans, discovers, reviews and integrates.
- Implementation and independent audits are delegated to Sonnet sub-agents with explicit bounded task context and disjoint file ownership, so parallel agents never edit the same file.
- Physical boot, EFI, module-load and power transitions are serialized under the orchestrator only. Sub-agents never reboot, stage boot images or load modules.
- Delegation must not weaken the hardware safety rules and must not reinterpret a diagnostic boundary as successful hibernation.

## Codex variant (alternative)

This is what runs today, kept as documented. Files (all present):

- `~/.local/bin/codex-mba-autoresume`: the wrapper. It changes to the repository and runs Codex with the profile and model overrides:

  ```bash
  codex_args=(
    -p mba-autonomous
    -m gpt-6-astra
    -c 'model_reasoning_effort="medium"'
    -c 'agents.default_subagent_model="gpt-6-sol"'
    -c 'agents.default_subagent_reasoning_effort="high"'
    -C "$project"
  )
  ```

  If the `continue` marker exists it is moved to `continue.dispatched` and Codex is executed as `codex "${codex_args[@]}" resume "$session" "<resume prompt>"`; otherwise it runs `codex "${codex_args[@]}" resume "$session"` with no prompt. The session id is a hard-coded UUID inside the script. If that session is ever lost or rotated, the wrapper must be edited to a new id (`codex resume` lists candidates).
- `~/.codex/mba-autonomous.config.toml`: the profile. It sets `model = "gpt-6-astra"`, `model_reasoning_effort = "medium"`, `sandbox_mode = "danger-full-access"`, `approval_policy = "never"`, `agents.default_subagent_model = "gpt-6-sol"`, `agents.default_subagent_reasoning_effort = "high"` and `features.prevent_idle_sleep = true`. Recreate it by hand; never copy `~/.codex/auth.json` or any token, and log in again on a new machine.
- Autostart (currently active in `~/.config/hypr/autostart.lua`):

  ```lua
  o.launch_on_start("foot -a codex-mba-autostart -T Codex-MBA -D /home/jjc/Projects/MBA_9_1 /home/jjc/.local/bin/codex-mba-autoresume")
  ```

Unlike the reference machine, the wrapper runs from the project directory and resumes a named session, not `resume --last` from `$HOME`. This machine has no remote app-server bridge, so the active-writer race described in the reference design (a remote client and the local TUI both attaching) does not apply unless one is added.

## Reboot protocol

Every power transition follows this order:

1. Read [AGENTS.md](../../AGENTS.md) and [RESUME.md](RESUME.md) again.
2. Persist findings and evidence, and update the local `handoff.json` details (`handoff-details.json` is merged into it by the dispatcher).
3. Confirm no hardware operation is ambiguous or still running.
4. Commit the complete checkpoint and push the current branch; confirm the remote branch equals local HEAD.
5. Confirm the worktree is clean (`git status --short` empty). `codex-mba-reboot --check` verifies steps 4 and 5 without side effects.
6. Run `~/.local/bin/codex-mba-reboot` as the final action of the turn. Run no further commands on this boot.
7. Never re-arm a live timer. If `codex-mba-delayed-reboot.timer` or `.service` is active, wait; the dispatcher refuses in that case.

Mandatory post-boot reconciliation, before any further work:

1. Read `/proc/sys/kernel/random/boot_id` and `uptime -s`, and compare them with the values in `handoff.json`. A different boot_id proves a new boot; the same boot_id means the reboot did not happen.
2. Read the EFI `LoaderImageIdentifier` variable to learn which image Limine actually booted, and compare it with the image the checkpoint expected. It is readable without root; the value is UTF-16 after a 4-byte attribute prefix:

   ```bash
   f=$(ls /sys/firmware/efi/efivars/LoaderImageIdentifier-*)
   tail -c +5 "$f" | tr -d '\0'; echo
   ```

   On 2026-09-29 this printed `EFI\Linux\mba_t2_hibernation_source.efi`. `LoaderEntrySelected-*` gives the Limine entry name the same way.
3. Check `git status --short`, `git log -5 --oneline` and the branch against the checkpoint recorded in `handoff.json`.
4. Compare `handoff.json` with [RESUME.md](RESUME.md) and [HIBERNATION.md](HIBERNATION.md). The local handoff is not in git; a missing file is not permission to reconstruct authority from prose or to rerun a consumed action.
5. Never treat conversation continuity as evidence. A resumed chat that "remembers" a reboot proves nothing; only machine evidence (boot_id, uptime, EFI variable, journal) does.
6. Preserve consumed power-management guards and do not repeat a failed hardware vector, per [AGENTS.md](../../AGENTS.md).

## Failure handling

- No agent window after login: check that SDDM logged in (`loginctl list-sessions`), that Hyprland is running, and that the autostart line and wrapper exist and are executable. Run the wrapper by hand from a terminal. Check `hyprctl clients` for class `claude-mba-autostart` (or `codex-mba-autostart`).
- Active-writer or duplicate client: Codex may refuse to resume a session another client owns; Claude Code `--continue` may pick up the wrong session if a second session was started in the repo. Find the duplicate agent processes (`pgrep -af 'claude|codex'`), close the extra client, and restart the wrapper. Never run two agents at once against the hardware.
- Black screen or hang needing operator power: hold the power button to force off, then boot normally. If Limine or the UKI fails to reach the root volume, stop and follow [RECOVERY-GATE.md](RECOVERY-GATE.md) and [HIBERNATION.md](HIBERNATION.md). Use the recovery passphrase, which remains in its LUKS keyslot, if the embedded key is unavailable. Replacement `.linux` kernels have repeatedly failed to mount the root volume; do not try them again.
- No remote recovery: with sshd disabled and no `~/.ssh`, a stuck machine can only be recovered at the keyboard. Add key-only sshd (layer c) if that is unacceptable.
- S3 caution: the hibernation source image froze on ordinary S3 resume twice on 2026-09-28. The operator should not lid-sleep (or otherwise suspend) that image until this is investigated. The wrapper's `prevent_idle_sleep = true` (Codex) does not cover a lid close.
- Lost continue marker: if the reboot happened but the agent came up without its resume prompt (for example after a manual boot), start it by hand and point it at [RESUME.md](RESUME.md) and `handoff.json`.

## What this setup has and has not proven

Proven, from the operator's history and current files:

- Limine auto-boots with a short timeout, and the embedded key unlocks the root volume without a passphrase (the drop-ins and hook exist; the reboots that exercised them are in the project history).
- SDDM autologin, lingering, and NetworkManager autoconnect bring the machine to a desktop with the agent window and network without local input.
- The dispatcher reboots the machine after the final tool result is persisted, and the wrapper resumes the agent with a one-shot prompt.
- The Codex variant has crossed many reboots this way.

Not proven:

- The Claude Code variant has not yet crossed a full unattended reboot end to end. `claude --continue` resumption and the chosen permission mode need to be exercised before relying on it.
- A successful ordinary boot does not establish that S4 or cold hibernation image restoration is safe (see [HIBERNATION.md](HIBERNATION.md) and [AGENTS.md](../../AGENTS.md)).
- Recovery from a hang without a person at the machine. No remote path exists.
- Root-only facts here (sudoers scope, `/etc/default/limine` settings, hook file mode, key slot layout) were not verified when this document was written.
- Rebuild from scratch on a fresh install has not been rehearsed; treat the commands as a reconstruction from the live files, and verify each layer before the next.
