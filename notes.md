# Agent-runnable T2 install after a fresh Omarchy boot

This is how the T2 vintage branch should install on a machine that just came up from the stock Omarchy ISO, the way this MacBookAir9,1 did on 2026-09-17. It is a design note for making that path one command an agent can run, not a record of the workaround we used.

## What a fresh boot actually is

Stock Omarchy 4.0.4 already did the packaged T2 baseline: `linux-t2`, headers, `apple-bcm-firmware`, `apple-t2-audio-config`, `t2fanrd`, module load, and the T2 kernel cmdline. Wi-Fi, keyboard, and a session are up.

This branch's extra work is not on that ISO: trackpad udev fallback, BCM4377 Wi-Fi stall recovery, Bluetooth startup ordering, measured speaker/mic DSP, and the DKMS suspend/radio drivers. Those exist as separate leaves, migrations, and setup commands. An agent should not have to discover or sequence them.

`omarchy dev link` is the wrong installer. It is a development overlay. T2 hardware support has to land at fixed system paths so systemd, DKMS, and the next boot work even if the checkout is not `OMARCHY_PATH`.

## Target interface

After clone, one command:

```bash
git clone --branch fix-t2-vintage-mac-support https://github.com/iJustinCabral/omarchy.git
cd omarchy
./bin/omarchy-setup-t2
```

That command owns detection, privilege, packages, units, DSP, and verify. It prints one line at the end: reboot to load the new radio modules and Bluetooth ordering. The agent does not reboot unless the user asked.

Do not require `omarchy dev link`, `omarchy migrate`, a floating terminal, or a second resume script.

## Add `omarchy setup t2`

New `bin/omarchy-setup-t2` (group `setup`, requires root). Idempotent. Skip unsupported hardware with a clear message and exit 0 only when this machine is not a T2 Mac; fail on a supported MacBookAir9,1 if a required step fails.

Order, matching `install/hardware/all.sh` plus the user-session DSP that the ISO chroot cannot apply:

1. Trackpad udev fallback (`fix-t2-touchpad.sh` / migration `1788537572`)
2. DSP packages (`fix-t2-audio-dsp.sh`) then `omarchy-t2-audio-dsp on` and a user WirePlumber restart
3. Wi-Fi recovery (`fix-wifi-recovery.sh`)
4. Bluetooth gate (`omarchy-setup-t2-bluetooth`)
5. Retire the old Wi-Fi-unload sleep unit if it is the one we shipped
6. Suspend DKMS (`omarchy-setup-t2-suspend`)
7. `--verify` each installed component and print a single reboot reminder

Keep the existing per-component setup commands. `omarchy setup t2` is the only thing an agent or a human on a fresh boot should run. ISO install keeps calling the leaves from `install/hardware/all.sh`; it should call the same managers so ISO and post-boot cannot drift.

Do not run the full migration list from this checkout against a 4.0.4 system. Quattro-only migrations are unrelated and unsafe to apply as a side effect of T2 setup.

## Make privilege work without a TTY

ISO hardware setup already runs as root via `omarchy apply hardware`. The gap is post-boot: every T2 setup command calls `sudo`, an agent has no password prompt, and `gcr-ssh-askpass` cannot be used as `SUDO_ASKPASS`.

`omarchy-setup-t2` should escalate once, then do all privileged work in that context:

- If `EUID` is 0, run.
- If stdin is a TTY, use `sudo` so a visible terminal can take a password.
- If stdin is not a TTY, use `pkexec` so the session polkit agent can show one graphical prompt.
- Refuse to spawn a floating terminal as the install path.

After the command exists in `/usr/bin` (package or a copy the script installs first), a tight sudoers drop-in in the same style as `etc/sudoers.d/omarchy-tzupdate` can make later runs passwordless for `%wheel`. That is a follow-on, not a substitute for the first-run pkexec/sudo choice.

## Install Wi-Fi recovery like Bluetooth, not like a packaged binary

The Wi-Fi recovery unit currently does this:

```
Environment=OMARCHY_PATH=/usr/share/omarchy
ExecStart=/usr/bin/omarchy-t2-wifi-recovery
ProtectHome=yes
```

On a stock 4.0.4 system those paths do not contain this branch's helper, so `systemctl enable --now` fails with `status=203/EXEC`. A home checkout cannot save it either: `ProtectHome=yes` hides `/home`.

Change `fix-wifi-recovery.sh` to copy a self-contained helper to a system path (Bluetooth already uses `/usr/local/sbin/bluetooth-after-wifi`) and point `ExecStart` at that file. Bake the Python in, or install it next to the helper under `/usr/lib/omarchy/`. The unit must not read `$OMARCHY_PATH` from a git tree and must not assume `/usr/bin/omarchy-t2-wifi-recovery` exists until this installer put it there.

ISO install should only `systemctl enable` (next boot). Post-boot `omarchy setup t2` may `enable --now`, but a start failure after a successful enable must not abort the rest of T2 setup. Recovery is for saved-off Wi-Fi stalls; a machine that already has working Wi-Fi should still get Bluetooth and suspend.

## Make AUR installs non-interactive

`omarchy-pkg-aur-add` uses `yay -S --noconfirm --needed`. That still prompted for cleanBuild, diffs, and proceed while installing `bankstown` and `triforce`. An agent cannot answer those.

Change the AUR helper (or the T2 DSP leaf) to pass `--answerclean None --answerdiff None --answeredit None` as well as `--noconfirm`. DSP package install is part of `omarchy setup t2`, not a separate yay session.

## Do not block the rest of setup on DSP graph attachment

`omarchy-t2-audio-dsp on` writes the WirePlumber drop-in. The graph is live only after a user-session audio restart. Setup should restart WirePlumber/PipeWire for the installing user and report sink names, but a "DSP not in graph yet" status is not a hard failure. Packages and config being present is enough; the graph attaching is verify, not install.

## One reboot, at the end, optional

Bluetooth ordering and the DKMS radio modules already take effect on the next ordinary boot. The installer must not reboot itself and must not require a reboot in the middle (dev-link currently does). After `omarchy setup t2` succeeds, the machine is installed; reboot is the user's activation step.

## What the agent should not do

- Point the whole distro at the checkout with `omarchy dev link` just to get T2 hardware
- Run `omarchy migrate` against this branch on a 4.0.4 system
- Call `omarchy setup t2-wifi-recovery`, `t2-bluetooth`, `t2-suspend`, and `t2 audio-dsp` as separate steps
- Overlay files into `/usr/share/omarchy` by hand
- Treat a Wi-Fi recovery start failure as "T2 install failed"

Once `omarchy setup t2` exists and the Wi-Fi unit is self-contained, a fresh-boot session is: clone this branch, run that command, reboot when ready.
