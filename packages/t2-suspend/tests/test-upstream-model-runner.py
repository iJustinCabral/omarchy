#!/usr/bin/python3
"""Exercise the upstream-model runner gates G0-G4 against a fake host (no hardware, no power writes)."""

import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_model_fixture import *  # noqa: F401,F403 (shared fake ESP, Limine, efivars and product state)

script = Path(__file__).resolve().parents[1] / "upstream-model/run-upstream-model.py"
spec = importlib.util.spec_from_file_location("upstream_model_runner", script)
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

OFFSET = 5
HIBERNATE_LOCATION = run.HIBERNATE_LOCATION
KERNEL = "[    1.000000] host kernel: Linux version 7.2.7-test\n"
SWITCH_ROOT = "[    5.000000] host systemd[1]: systemd 261 running in system mode\n"
LATE_WIFI = "[   20.000000] host kernel: brcmfmac: Wi-Fi attach\n"


def header_page(signature=b"SWAPSPACE2", flags=4):
  page = bytearray(4096)
  struct.pack_into("<IIQI10s10s", page, 4096 - 40, 0, 0, 0, flags, b"\0" * 10, signature.ljust(10, b"\0"))
  return bytes(page)


class Env:
  """Scripted fake host: sysfs/proc under the fixture root plus a command table."""

  def __init__(self, base, *, names=None):
    self.root, self.build, self.limine, self.original, self.production = fixture(base)
    self.receipt = stage.stage(self.root, self.build)
    advertise(self.root, self.receipt)
    self.entry = self.receipt["entry_id"]
    self.clock = 1_000_000.0
    self.calls = []
    self.answers = []
    self.journal = KERNEL + SWITCH_ROOT + LATE_WIFI
    self.suspend_lines = "[  100.0] host kernel: PM: suspend entry (deep)\n[  110.0] host kernel: ACPI: PM: Waking up from system sleep state S3\n"
    self.hibernate_lines = "[  200.0] host kernel: PM: hibernation: hibernation entry\n"
    self.hibernate_rc = 0
    self.hibernate_hook = None
    self.suspend_hook = None
    self.guard_rc = 0
    self.failed_units = ""
    self.inhibit = "Xwayland 1000 jjc 99 Xwayland sleep:idle Xwayland delay\n"
    self.map_offset = str(OFFSET)
    self.lock_hook = None
    self._sysfs()
    self.host = run.Host(self.root, run=self.command, ask=self.ask, now=lambda: self.clock, sleep=self.sleep, euid=lambda: 0,
                         sync=lambda: self.calls.append("sync"), stager_runner=bootctl_for(self.root), lock=self.lock)

  # -- fake sysfs ---------------------------------------------------------------
  def write(self, relative, text):
    path = self.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

  def _sysfs(self):
    self.write("sys/class/dmi/id/product_name", "MacBookAir9,1\n")
    cmdline = run.production_cmdline(type("H", (), {"root": self.root})())
    self.write("proc/cmdline", cmdline + " initrd=\\EFI\\x\n")
    self.write("sys/power/resume", "253:0\n")
    self.write("sys/power/resume_offset", str(OFFSET) + "\n")
    self.write("sys/power/disk", "[platform] shutdown reboot\n")
    self.write("sys/power/pm_test", "[none] core processors\n")
    self.write("proc/swaps", "Filename Type Size Used Priority\n/dev/zram0 partition 100 0 100\n/swap/swapfile file 100 0 -2\n")
    self.write("proc/sys/kernel/tainted", "0\n")
    self.write("proc/uptime", "100.00 20.00\n")
    for name in C.T2BCE_MODULES:
      self.write("sys/module/" + name + "/srcversion", self.receipt["modules"][name]["srcversion"] + "\n")
    for function in C.T2_FUNCTIONS + (C.WIFI_FUNCTION,):
      directory = self.root / "sys/bus/pci/devices" / function
      directory.mkdir(parents=True)
      (directory / "driver").symlink_to("../../../bus/pci/drivers/" + ("brcmfmac" if function == C.WIFI_FUNCTION else "t2bce"))
    self.write("sys/bus/pci/devices/" + C.WIFI_FUNCTION + "/net/wlan0/operstate", "up\n")
    self.write("proc/bus/input/devices", 'N: Name="Apple Internal Keyboard / Trackpad"\nN: Name="Apple Inc. Apple Internal Keyboard"\nN: Name="bcm5974 Trackpad"\n')
    self.power("1", "Charging", 80)
    device = self.root / "dev/mapper/root"
    device.parent.mkdir(parents=True)
    device.write_bytes(b"\0" * (OFFSET * 4096) + header_page())
    (self.root / "sys/firmware/efi/efivars").mkdir(parents=True, exist_ok=True)
    self.product_unit = "ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/sleep_entry.py ; ignore_errors=no }\nExecStartPre=\nExecStopPost=\n"

  def power(self, online, status, percent):
    self.write("sys/class/power_supply/ADP1/type", "Mains\n")
    self.write("sys/class/power_supply/ADP1/online", online + "\n")
    self.write("sys/class/power_supply/BAT0/type", "Battery\n")
    self.write("sys/class/power_supply/BAT0/status", status + "\n")
    self.write("sys/class/power_supply/BAT0/capacity", str(percent) + "\n")

  def header(self, signature, flags=4):
    with open(self.root / "dev/mapper/root", "r+b") as stream:
      stream.seek(OFFSET * 4096)
      stream.write(header_page(signature, flags))

  # -- boot simulation ----------------------------------------------------------
  def boot_test_entry(self, boot_id=BOOT_B):
    stage.arm(self.root, runner=bootctl_for(self.root))
    (self.root / stage.ONESHOT).unlink()
    set_boot(self.root, self.entry, boot_id)
    self.write("proc/sys/kernel/random/boot_id", boot_id + "\n")

  # -- fake commands ------------------------------------------------------------
  def dropin_present(self):
    return (self.root / C.DROPIN).is_file()

  def show(self):
    if not self.dropin_present():
      return self.product_unit
    script = "/" + str(C.RUNTIME_DIR) + "/prepare.py"
    return ("ExecStart={ path=/usr/lib/systemd/systemd-sleep ; argv[]=/usr/lib/systemd/systemd-sleep hibernate ; ignore_errors=no }\n"
            "ExecStartPre={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B " + script + " pre ; ignore_errors=no }\n"
            "ExecStopPost={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B " + script + " post ; ignore_errors=no }\n")

  def command(self, arguments, timeout=None):
    arguments = tuple(str(item) for item in arguments)
    self.calls.append(arguments)
    done = lambda out="", rc=0, err="": subprocess.CompletedProcess(arguments, rc, out, err)
    if arguments[:3] == ("/usr/bin/python3", "-I", "-B"):
      return done("unchanged\n" if arguments[-1] == "assess" else "", self.guard_rc, "guard refused" if self.guard_rc else "")
    if arguments[:3] == ("/usr/bin/btrfs", "inspect-internal", "map-swapfile"):
      return done(self.map_offset + "\n")
    if arguments[0] == "systemd-inhibit":
      return done(self.inhibit)
    if arguments[0] == "journalctl":
      if "--show-cursor" in arguments:
        return done("-- cursor: s=cursor1\n")
      return done(self.journal)
    if arguments[:2] == ("systemctl", "--failed"):
      return done(self.failed_units)
    if arguments[:2] == ("systemctl", "daemon-reload"):
      return done()
    if arguments[:2] == ("systemctl", "show"):
      return done(self.show())
    if arguments == ("systemctl", "suspend"):
      if self.suspend_hook:
        self.suspend_hook()
      self.journal += self.suspend_lines
      return done()
    if arguments == ("systemctl", "hibernate"):
      if self.hibernate_hook:
        self.hibernate_hook()
      if self.hibernate_rc:
        return done("", self.hibernate_rc, "Failed to hibernate")
      # What the real S4 does to observable state: the one-shot is consumed, the header is reset, the journal grows.
      assert self.dropin_present(), "hibernate ran without the drop-in"
      assert (self.root / stage.ONESHOT).is_file(), "hibernate ran without the one-shot armed"
      guards = list((self.root / C.GUARDS).rglob("cycle-*"))
      assert guards, "hibernate ran without a durable guard"
      (self.root / stage.ONESHOT).unlink()
      self.header(b"SWAPSPACE2", 5)
      self.journal += self.hibernate_lines
      return done()
    return done()

  def ask(self, prompt):
    self.calls.append(("ask", prompt))
    if self.answers:
      answer = self.answers.pop(0)
      return answer if answer is not None else prompt.split("\n  ", 1)[1].split("\n> ", 1)[0]
    if prompt.startswith("Press Enter"):
      return ""
    return prompt.split("\n  ", 1)[1].split("\n> ", 1)[0]

  def sleep(self, seconds):
    self.clock += seconds

  def lock(self):
    self.calls.append("lock")
    if self.lock_hook:
      self.lock_hook()

  def called(self, *prefix):
    return [call for call in self.calls if isinstance(call, tuple) and call[:len(prefix)] == prefix]

  def terminal(self):
    return (self.root / C.TERMINAL / (self.receipt["image_sha256"] + ".json")).exists()

  def attempt(self, cycle):
    path = self.root / C.ATTEMPTS / self.receipt["image_sha256"] / ("cycle-" + str(cycle)) / "attempt.json"
    return json.loads(path.read_text()) if path.exists() else None

  def guard(self, cycle):
    return self.root / C.GUARDS / self.receipt["image_sha256"] / ("cycle-" + str(cycle))

  def to_s3_passed(self):
    self.boot_test_entry()
    run.verify_boot(self.host)
    run.s3(self.host)


# ---- phrases are bound to image, boot, cycle and power ------------------------------
image = "a" * 64
phrases = {
  C.attendance_phrase(image, BOOT_A, 1, "AC"), C.attendance_phrase(image, BOOT_A, 2, "AC"), C.attendance_phrase(image, BOOT_A, 1, "battery"),
  C.attendance_phrase(image, BOOT_B, 1, "AC"), C.attendance_phrase("b" * 64, BOOT_A, 1, "AC"),
}
assert len(phrases) == 5
assert image[:12] in C.attendance_phrase(image, BOOT_A, 1, "AC") and BOOT_A[:8] in C.attendance_phrase(image, BOOT_A, 1, "AC")
rejects(lambda: C.attendance_phrase(image, BOOT_A, 4, "AC"), "invalid")
rejects(lambda: C.attendance_phrase(image, BOOT_A, 1, "solar"), "invalid")
assert len({C.confirmation_phrase(kind, image, BOOT_A) for kind in ("boot", "s3", "s4")}) == 3

with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-") as temporary:
  base = Path(temporary)

  # ---- G0 refusals --------------------------------------------------------------
  env = Env(base / "g0")
  env.boot_test_entry()
  facts = run.preconditions(env.host, env.receipt)
  assert facts["swap_target"] == {"device": "/dev/mapper/root", "devnum": "253:0", "offset": OFFSET}
  (env.root / stage.MAINTENANCE).unlink()
  rejects(lambda: run.preconditions(env.host, env.receipt), "not in package maintenance")
  (env.root / stage.MAINTENANCE).write_text("pending\n")
  env.guard_rc = 1
  rejects(lambda: run.preconditions(env.host, env.receipt), "Update guard does not admit")
  env.guard_rc = 0
  env.inhibit += "Steam 1000 jjc 1 steam sleep Playing block\n"
  rejects(lambda: run.preconditions(env.host, env.receipt), "blocking inhibitor")
  env.inhibit = "x 1 u 1 c sleep w delay\n"
  (env.root / stage.ONESHOT).write_bytes(efi_string(env.entry))
  rejects(lambda: run.preconditions(env.host, env.receipt), "one-shot is present")
  assert run.preconditions(env.host, env.receipt, efi_clear=False)
  (env.root / stage.ONESHOT).unlink()
  (env.root / "etc/omarchy").mkdir(parents=True)
  (env.root / "etc/omarchy/t2-hibernate-product.enabled").write_text("")
  rejects(lambda: run.preconditions(env.host, env.receipt), "not inactive")
  (env.root / "etc/omarchy/t2-hibernate-product.enabled").unlink()
  env.write("sys/power/disk", "platform [shutdown]\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "[platform]")
  env.write("sys/power/disk", "[platform] shutdown\n")
  env.write("sys/power/pm_test", "none [core]\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "pm_test")
  env.write("sys/power/pm_test", "[none] core\n")
  env.header(b"S1SUSPEND")
  rejects(lambda: run.preconditions(env.host, env.receipt), "SWAPSPACE2")
  env.header(b"SWAPSPACE2")
  env.write("sys/power/resume_offset", "6\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "resume_offset differs")
  env.write("sys/power/resume_offset", str(OFFSET) + "\n")
  env.map_offset = "9"
  rejects(lambda: run.preconditions(env.host, env.receipt), "Btrfs swapfile mapping")
  env.map_offset = str(OFFSET)
  env.write("proc/swaps", "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -3\n/swap/swapfile file 100 0 -2\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "Swap candidates")
  env.write("proc/swaps", "Filename Type Size Used Priority\n/swap/swapfile file 100 0 -2\n")
  env.write("proc/cmdline", "root=/dev/mapper/root resume=/dev/sda resume_offset=5\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "resume=")
  assert stage.mark_terminal(env.root, env.receipt["image_sha256"], "test")
  env.write("proc/cmdline", run.production_cmdline(env.host) + "\n")
  rejects(lambda: run.preconditions(env.host, env.receipt), "terminal")

  # ---- G1 -----------------------------------------------------------------------
  env = Env(base / "g1")
  rejects(lambda: run.verify_boot(env.host), "not armed")
  env.boot_test_entry()
  env.write("proc/cmdline", run.production_cmdline(env.host) + " nomodeset\n")
  rejects(lambda: run.verify_boot(env.host), "cmdline differs")
  env.write("proc/cmdline", run.production_cmdline(env.host) + "\n")
  env.write("sys/module/t2bce_audio/srcversion", "STOCKAUDIO\n")
  rejects(lambda: run.verify_boot(env.host), "t2bce_audio srcversion")
  env.write("sys/module/t2bce_audio/srcversion", env.receipt["modules"]["t2bce_audio"]["srcversion"] + "\n")
  env.journal = KERNEL + "[    2.000000] host kernel: brcmfmac: attached from the initramfs\n" + SWITCH_ROOT
  rejects(lambda: run.verify_boot(env.host), "before switch_root")
  env.journal = KERNEL + LATE_WIFI
  rejects(lambda: run.verify_boot(env.host), "locate the switch to the real root")
  env.journal = KERNEL + SWITCH_ROOT + LATE_WIFI
  env.failed_units = "broken.service loaded failed failed Broken\n"
  rejects(lambda: run.verify_boot(env.host), "Failed systemd units")
  env.failed_units = ""
  (env.root / "sys/bus/pci/devices" / C.WIFI_FUNCTION / "driver").unlink()
  rejects(lambda: run.verify_boot(env.host), "no bound driver")
  (env.root / "sys/bus/pci/devices" / C.WIFI_FUNCTION / "driver").symlink_to("../../../bus/pci/drivers/brcmfmac")
  env.write("proc/bus/input/devices", 'N: Name="Something"\n')
  rejects(lambda: run.verify_boot(env.host), "keyboard or trackpad")
  env.write("proc/bus/input/devices", 'N: Name="Apple Internal Keyboard"\nN: Name="bcm5974 Trackpad"\n')
  assert stage.load_receipt(env.root)["state"] == "armed"
  env.answers = ["wrong phrase"]
  rejects(lambda: run.verify_boot(env.host), "Typed phrase does not match")
  assert stage.load_receipt(env.root)["state"] == "armed"
  result = run.verify_boot(env.host)
  assert result["hibernate_attempted"] is False and result["boot_id"] == BOOT_B
  receipt = stage.load_receipt(env.root)
  assert receipt["state"] == "booted" and receipt["test_boot_id"] == BOOT_B
  assert run.verify_boot(env.host)["boot_id"] == BOOT_B
  directory = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("g1-" + BOOT_B)
  assert json.loads((directory / "g1.json").read_text())["state"] == "passed"
  assert (directory / "boot.json").stat().st_mode & 0o777 == 0o600 and (directory / "boot-lspci-k.txt").exists()
  # Another boot of the image must be verified again.
  env.write("proc/sys/kernel/random/boot_id", BOOT_C + "\n")
  set_boot(env.root, env.entry, BOOT_C)
  rejects(lambda: run.verify_boot(env.host), "verified on another boot")

  # ---- G2 -----------------------------------------------------------------------
  env = Env(base / "g2")
  env.boot_test_entry()
  rejects(lambda: run.s3(env.host), "Ordinary-boot verification")
  run.verify_boot(env.host)
  env.suspend_lines = "[  100.0] host kernel: PM: suspend entry (deep)\n"
  rejects(lambda: run.s3(env.host), "lacks the S3 entry/exit")
  assert json.loads((env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("s3-" + BOOT_B) / "s3.json").read_text())["state"] == "failed"
  rejects(lambda: run.s3(env.host), "already run")
  env = Env(base / "g2-ok")
  env.boot_test_entry()
  run.verify_boot(env.host)
  env.suspend_lines += "[  111.0] host kernel: t2bce_vhci: HC died; cleaning up\n"
  rejects(lambda: run.s3(env.host), "HC died")
  env = Env(base / "g2-input")
  env.boot_test_entry()
  run.verify_boot(env.host)
  env.suspend_hook = lambda: (env.root / "sys/bus/pci/devices" / C.WIFI_FUNCTION / "net/wlan0/operstate").write_text("down\n")
  rejects(lambda: run.s3(env.host), "Wi-Fi interface is absent or not up")
  env = Env(base / "g2-pass")
  env.boot_test_entry()
  run.verify_boot(env.host)
  assert env.called("systemctl", "suspend") == []
  assert run.s3(env.host)["qualification"] == "upstream-model-s3-passed"
  assert len(env.called("systemctl", "suspend")) == 1
  assert env.called("systemctl", "hibernate") == []

  # ---- G3/G4 refusals before any guard -------------------------------------------
  env = Env(base / "s4-gates")
  env.boot_test_entry()
  rejects(lambda: run.s4_cycle(env.host, 1), "Ordinary-boot verification")
  run.verify_boot(env.host)
  rejects(lambda: run.s4_cycle(env.host, 1), "S3 has not passed")
  run.s3(env.host)
  rejects(lambda: run.s4_cycle(env.host, 2), "Cycle 1 is not returned-and-cleaned")
  rejects(lambda: run.s4_cycle(env.host, 4), "1, 2 or 3")
  env.power("0", "Discharging", 90)
  rejects(lambda: run.s4_cycle(env.host, 1), "requires AC")
  env.power("1", "Charging", 90)
  assert not env.called("systemctl", "hibernate") and not env.guard(1).exists()

  # A wrong attendance phrase changes nothing durable and is retryable.
  env.answers = ["I am at the MacBook"]
  rejects(lambda: run.s4_cycle(env.host, 1), "Typed phrase does not match")
  assert not env.guard(1).exists() and not env.dropin_present() and not (env.root / C.RUNTIME_DIR).exists()
  assert not (env.root / stage.ONESHOT).exists() and env.attempt(1)["state"] == "refused-before-guard" and not env.terminal()
  assert not env.called("systemctl", "hibernate")
  # The phrase for another cycle, another power source or another boot does not satisfy this cycle.
  for wrong in (C.attendance_phrase(env.receipt["image_sha256"], BOOT_B, 2, "AC"), C.attendance_phrase(env.receipt["image_sha256"], BOOT_B, 1, "battery"),
                C.attendance_phrase(env.receipt["image_sha256"], BOOT_A, 1, "AC"), C.attendance_phrase("c" * 64, BOOT_B, 1, "AC")):
    env.answers = [wrong]
    rejects(lambda: run.s4_cycle(env.host, 1), "Typed phrase does not match")
    assert not env.guard(1).exists()

  # An expired acceptance (the lock step takes too long) stops before the guard and unwinds.
  env.lock_hook = lambda: setattr(env, "clock", env.clock + 31 * 60)
  rejects(lambda: run.s4_cycle(env.host, 1), "expired")
  env.lock_hook = None
  assert not env.guard(1).exists() and not env.dropin_present() and not (env.root / stage.ONESHOT).exists() and not env.terminal()
  assert env.attempt(1)["state"] == "refused-before-guard"

  # Power source changing after attendance is accepted stops before the guard.
  env.lock_hook = lambda: env.power("0", "Discharging", 90)
  rejects(lambda: run.s4_cycle(env.host, 1), "Power source changed")
  env.lock_hook = None
  env.power("1", "Charging", 90)
  assert not env.guard(1).exists() and not env.dropin_present() and not (env.root / stage.ONESHOT).exists()
  # A swap target change after acceptance stops before the guard.
  env.lock_hook = lambda: env.write("sys/power/resume_offset", "7\n")
  rejects(lambda: run.s4_cycle(env.host, 1), "resume_offset differs")
  env.lock_hook = None
  env.write("sys/power/resume_offset", str(OFFSET) + "\n")
  # A failed desktop lock stops before any arming.
  env.lock_hook = lambda: (_ for _ in ()).throw(ValueError("Desktop lock was not secured"))
  rejects(lambda: run.s4_cycle(env.host, 1), "Desktop lock")
  env.lock_hook = None
  assert not (env.root / stage.ONESHOT).exists() and not env.dropin_present() and stage.load_receipt(env.root)["state"] in ("booted", "disarmed")
  # A pre-existing runtime drop-in must be cleaned first, never reused.
  (env.root / C.RUNTIME_DIR).mkdir(parents=True)
  rejects(lambda: run.s4_cycle(env.host, 1), "already exist")
  (env.root / C.RUNTIME_DIR).rmdir()
  # A drop-in that systemd does not show as expected is refused and removed.
  env.show = lambda: env.product_unit
  rejects(lambda: run.s4_cycle(env.host, 1), "does not show the expected stock ExecStart")
  del env.show
  assert not env.dropin_present() and not (env.root / C.RUNTIME_DIR).exists() and not env.guard(1).exists()
  assert not env.called("systemctl", "hibernate")

  # ---- a full successful campaign -------------------------------------------------
  env = Env(base / "campaign")
  env.to_s3_passed()
  guard_seen = {}

  def at_hibernate():
    guard_seen.update(json.loads(env.guard(guard_seen["cycle"]).read_text()))
    assert env.guard(guard_seen["cycle"]).stat().st_mode & 0o777 == 0o600

  env.hibernate_hook = at_hibernate
  guard_seen["cycle"] = 1
  attempt = run.s4_cycle(env.host, 1)
  assert attempt["state"] == "returned-and-cleaned" and attempt["hardware_qualified"] is False
  assert guard_seen["cycle"] == 1 and guard_seen["boot_id"] == BOOT_B and guard_seen["power"] == "AC"
  assert guard_seen["transition_vector"] == run.vector(env.receipt, 1, BOOT_B, "AC")
  assert "lock" in env.calls and env.calls.index("lock") < env.calls.index(("systemctl", "hibernate"))
  assert not env.dropin_present() and not (env.root / C.RUNTIME_DIR).exists()
  assert not (env.root / stage.ONESHOT).exists() and stage.load_receipt(env.root)["state"] in ("booted", "disarmed")
  assert stage.load_receipt(env.root)["last_armed_cycle"] == 1 and not env.terminal()
  cycle_dir = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / "cycle-1"
  for name in ("pre.json", "post.json", "acceptance.json", "attempt.json", "pre-lspci-k.txt", "post-bluetooth.txt"):
    assert (cycle_dir / name).stat().st_mode & 0o777 == 0o600, name
  post = json.loads((cycle_dir / "post.json").read_text())
  assert post["swap_header_after"]["signature_hex"] == b"SWAPSPACE2".hex() and post["swap_header_after"]["flags"] == 5
  assert json.loads((cycle_dir / "pre.json").read_text())["swap_header"]["flags"] == 4
  assert any("hibernation entry" in line for line in post["journal"])
  assert json.loads((cycle_dir / "acceptance.json").read_text())["expires"] - json.loads((cycle_dir / "acceptance.json").read_text())["issued"] == 1800
  rejects(lambda: run.s4_cycle(env.host, 1), "never repeated")
  # Cycle 2 on AC, then cycle 3 needs battery at or above 70% and Discharging.
  guard_seen["cycle"] = 2
  assert run.s4_cycle(env.host, 2)["state"] == "returned-and-cleaned"
  rejects(lambda: run.s4_cycle(env.host, 3), "requires battery")
  env.power("0", "Discharging", 69)
  rejects(lambda: run.s4_cycle(env.host, 3), "at or above 70%")
  env.power("0", "Charging", 90)
  rejects(lambda: run.s4_cycle(env.host, 3), "at or above 70%")
  assert not env.guard(3).exists()
  env.power("0", "Discharging", 73)
  guard_seen["cycle"] = 3
  third = run.s4_cycle(env.host, 3)
  assert third["state"] == "returned-and-cleaned" and third["power"] == "battery"
  assert len(env.called("systemctl", "hibernate")) == 3
  assert [env.guard(cycle).exists() for cycle in (1, 2, 3)] == [True] * 3 and not env.terminal()
  # Cleanup afterwards is a no-op and preserves guards.
  assert run.cleanup(env.host)["state"] == "cleaned" and env.guard(1).exists()

  # ---- failure semantics ---------------------------------------------------------
  def failed_cycle(name, prepare, expected):
    case = Env(base / name)
    case.to_s3_passed()
    prepare(case)
    rejects(lambda: run.s4_cycle(case.host, 1), expected)
    return case

  case = failed_cycle("hibernate-error", lambda e: setattr(e, "hibernate_rc", 1), "returned 1")
  assert case.guard(1).exists() and case.terminal() and case.attempt(1)["state"] == "failed-terminal"
  assert not case.dropin_present() and not (case.root / C.RUNTIME_DIR).exists() and not (case.root / stage.ONESHOT).exists()
  assert case.attempt(1)["hibernate_attempted"] is True
  rejects(lambda: run.s4_cycle(case.host, 1), "never repeated")
  rejects(lambda: run.s4_cycle(case.host, 2), "not returned-and-cleaned")
  rejects(lambda: run.verify_boot(case.host), "not armed or verified")
  rejects(lambda: stage.arm_s4(case.root, 2, runner=bootctl_for(case.root)), "terminal")

  case = failed_cycle("wifi-down", lambda e: setattr(e, "hibernate_hook", lambda: e.write("sys/bus/pci/devices/" + C.WIFI_FUNCTION + "/net/wlan0/operstate", "down\n")), "Wi-Fi interface")
  assert case.terminal() and case.guard(1).exists() and not case.dropin_present()

  case = failed_cycle("no-journal", lambda e: setattr(e, "hibernate_lines", ""), "hibernation entry")
  assert case.terminal()

  case = failed_cycle("bad-pm", lambda e: setattr(e, "hibernate_lines", "[ 1.0] host kernel: PM: hibernation: hibernation entry\n[ 2.0] host kernel: t2bce_vhci: HC died\n"), "HC died")
  assert case.terminal()

  def interrupt(e):
    def hook():
      raise KeyboardInterrupt
    e.hibernate_hook = hook

  case = Env(base / "interrupted")
  case.to_s3_passed()
  interrupt(case)
  try:
    run.s4_cycle(case.host, 1)
  except KeyboardInterrupt:
    pass
  else:
    raise AssertionError("interrupt swallowed")
  assert case.terminal() and case.guard(1).exists() and not case.dropin_present() and not (case.root / stage.ONESHOT).exists()

  def swap_changed(e):
    e.hibernate_hook = lambda: e.write("sys/power/resume_offset", "8\n")

  case = failed_cycle("swap-changed", swap_changed, "Swap target or header after the resume")
  assert case.terminal()

  case = failed_cycle("selected-wrong", lambda e: setattr(e, "hibernate_hook", lambda: set_boot(e.root, C.STOCK_ENTRY, BOOT_B)), "did not select")
  assert case.terminal()

  # Failure before the guard is not terminal, and a failed cycle never unlocks later ones.
  case = Env(base / "pre-guard-failure")
  case.to_s3_passed()
  case.guard_rc = 1
  rejects(lambda: run.s4_cycle(case.host, 1), "Update guard")
  case.guard_rc = 0
  assert not case.terminal() and case.attempt(1) is None and not case.guard(1).exists()

  # Guard files are durable evidence: a cycle whose attempt record vanished is still never repeated.
  case = Env(base / "guard-only")
  case.to_s3_passed()
  run.s4_cycle(case.host, 1)
  (case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1" / "attempt.json").unlink()
  rejects(lambda: run.s4_cycle(case.host, 1), "never repeated")
  rejects(lambda: run.s4_cycle(case.host, 2), "Cycle 1 is not returned-and-cleaned")
  assert run.cleanup(case.host)["state"] == "cleaned"

  # ---- standalone cleanup and interrupted attempts --------------------------------
  case = Env(base / "cleanup")
  case.to_s3_passed()
  run.install_dropin(case.host)
  assert case.dropin_present()
  dropin_text = (case.root / C.DROPIN).read_text()
  pins = json.loads((case.root / C.RUNTIME_DIR / "pins.json").read_text())
  assert "ExecStart=\nExecStart=/usr/lib/systemd/systemd-sleep hibernate\n" in dropin_text
  assert pins["prepare_sha256"] in dropin_text and "sleep_entry.py" not in dropin_text
  assert C.sha256((case.root / C.RUNTIME_DIR / "prepare.py").read_bytes()) == pins["prepare_sha256"]
  assert C.sha256((case.root / C.RUNTIME_DIR / "omarchy-t2-hibernate-wifi").read_bytes()) == pins["wifi_helper_sha256"]
  rejects(lambda: run.install_dropin(case.host), "already exist")
  (case.root / C.RUNTIME_DIR / "prepare-state.json").write_text("{}")
  rejects(lambda: run.cleanup(case.host), "prepare state still pending")
  (case.root / C.RUNTIME_DIR / "prepare-state.json").unlink()
  directory = case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1"
  directory.mkdir(parents=True)
  (directory / "attempt.json").write_text(json.dumps({"state": "armed"}))
  (case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-2").mkdir()
  (case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-2" / "attempt.json").write_text(json.dumps({"state": "transition-started"}))
  stage.arm_s4(case.root, 1, runner=bootctl_for(case.root))
  cleaned = run.cleanup(case.host)
  assert cleaned["settled_attempts"] == {"cycle-1": "refused-before-guard", "cycle-2": "failed-terminal"}
  assert not case.dropin_present() and not (case.root / stage.ONESHOT).exists() and case.terminal()
  assert run.cleanup(case.host)["state"] == "cleaned"


with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-audit-") as temporary:
  base = Path(temporary)

  # A partial arm (one-shot written, then the stager dies) is always disarmed and unwound.
  case = Env(base / "partial-arm")
  case.to_s3_passed()
  real_arm = run.STAGE.arm_s4

  def partial(root, cycle, runner=None, sync=None):
    record = stage.load_receipt(root)
    record.update(state="arming", arming={"purpose": "s4", "cycle": cycle, "boot_id": BOOT_B})
    stage.save_receipt(root, record)
    (root / stage.ONESHOT).write_bytes(efi_string(case.entry))
    raise RuntimeError("stager died after setting the one-shot")

  run.STAGE.arm_s4 = partial
  try:
    rejects(lambda: run.s4_cycle(case.host, 1), "stager died")
  finally:
    run.STAGE.arm_s4 = real_arm
  assert not (case.root / stage.ONESHOT).exists() and not case.dropin_present() and not case.guard(1).exists() and not case.terminal()

  # pre-reactivate-check refuses every kind of leftover and clears only when nothing remains.
  case = Env(base / "reactivate")
  case.to_s3_passed()
  rejects(lambda: run.pre_reactivate_check(case.host), "receipt still exists")
  run.s4_cycle(case.host, 1)
  (case.root / C.RUNTIME_DIR).mkdir(parents=True)
  rejects(lambda: run.pre_reactivate_check(case.host), "omarchy-t2-upstream-model exists")
  (case.root / C.RUNTIME_DIR).rmdir()
  (case.root / C.DROPIN).parent.mkdir(parents=True, exist_ok=True)
  (case.root / C.DROPIN).write_text("[Service]\n")
  rejects(lambda: run.pre_reactivate_check(case.host), "drop-in")
  (case.root / C.DROPIN).unlink()
  (case.root / stage.ONESHOT).write_bytes(efi_string(case.entry))
  rejects(lambda: run.pre_reactivate_check(case.host), "one-shot")
  (case.root / stage.ONESHOT).unlink()
  rejects(lambda: run.pre_reactivate_check(case.host), "receipt still exists")
  set_boot(case.root, C.STOCK_ENTRY, BOOT_C)
  stage.rollback(case.root)
  stage.clear_rolled_back(case.root)
  path = case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-2"
  path.mkdir()
  (path / "attempt.json").write_text(json.dumps({"state": "armed"}))
  rejects(lambda: run.pre_reactivate_check(case.host), "unsettled attempt")
  (path / "attempt.json").write_text(json.dumps({"state": "refused-before-guard"}))
  assert run.pre_reactivate_check(case.host)["state"].startswith("clear")
  assert "noresume" in run.CHECKLIST and "press E" in run.CHECKLIST

print("PASS: upstream-model runner unwinds partial arms and gates product reactivation")
