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
    self.consume_transition = True
    self.hibernate_active = None
    self.hibernate_invoked = False
    self.pre_guard_state = None
    self.reset_failed_error = None
    self.cat_override = None
    self.hibernate_hook = None
    self.suspend_hook = None
    self.guard_rc = 0
    self.failed_units = ""
    self.inhibit = "Xwayland 1000 jjc 99 Xwayland sleep:idle Xwayland delay\n"
    self.map_offset = str(OFFSET)
    self.lock_hook = None
    self.dmesg = ""
    self.bootctl_log = []
    self._sysfs()
    self.host = run.Host(self.root, run=self.command, ask=self.ask, now=lambda: self.clock, sleep=self.sleep, euid=lambda: 0,
                         sync=lambda: self.calls.append("sync"), stager_runner=bootctl_for(self.root, self.bootctl_log), lock=self.lock,
                         monotonic_clock=lambda: self.clock)

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
    # Real shape: the Secure Enclave (74:00.2) has no driver; the others are bound to their real drivers.
    drivers = {**C.T2_DRIVERS, C.WIFI_FUNCTION: "brcmfmac", C.BLUETOOTH_FUNCTION: "hci_bcm4377"}
    for function in C.T2_FUNCTIONS + (C.WIFI_FUNCTION, C.BLUETOOTH_FUNCTION):
      directory = self.root / "sys/bus/pci/devices" / function
      directory.mkdir(parents=True)
      if function in drivers:
        (directory / "driver").symlink_to("../../../bus/pci/drivers/" + drivers[function])
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

  def cat(self):
    if self.cat_override is not None:
      return self.cat_override
    product = (
      "# /etc/systemd/system/systemd-hibernate.service.d/omarchy-t2.conf\n"
      "[Service]\n"
      "ExecStart=\n"
      "ExecStart=/usr/bin/python3 -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/sleep_entry.py\n"
    )
    if not self.dropin_present():
      return product
    script = "/" + str(C.RUNTIME_DIR) + "/prepare.py"
    return product + (
      "\n# /run/systemd/system/systemd-hibernate.service.d/zz-upstream-model.conf\n"
      "[Service]\n"
      "ExecStart=\n"
      "ExecStart=/usr/lib/systemd/systemd-sleep hibernate\n"
      "ExecStartPre=/usr/bin/python3 -I -B " + script + " pre\n"
      "ExecStopPost=/usr/bin/python3 -I -B " + script + " post\n"
    )

  def unit_state(self):
    # The pre-guard idle check must not consume the post-hibernate script. A missing ActiveState
    # is what the runner treats as the test double.
    if not self.hibernate_invoked:
      state = self.pre_guard_state
    else:
      state = self.hibernate_active() if callable(self.hibernate_active) else self.hibernate_active
    if not state:
      return ""
    job = "123" if state in ("activating", "active", "deactivating") else ""
    sub = "start" if state == "activating" else "dead"
    if state == "failed":
      sub = "failed"
    return "ActiveState=" + state + "\nSubState=" + sub + "\nJob=" + job + "\n"

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
    if arguments[0] == "dmesg":
      return done(self.dmesg)
    if arguments[0] == "journalctl" and "-k" in arguments:
      after = [item for item in arguments if item.startswith("--after-cursor=s=")]
      text = self.journal[int(after[0].split("=")[-1]):] if after else self.journal
      return done("".join(line + "\n" for line in text.splitlines() if "kernel:" in line))
    if arguments[0] == "journalctl":
      if "--show-cursor" in arguments:
        return done("-- cursor: s=" + str(len(self.journal)) + "\n")
      after = [item for item in arguments if item.startswith("--after-cursor=s=")]
      return done(self.journal[int(after[0].split("=")[-1]):] if after else self.journal)
    if arguments[:2] == ("systemctl", "--failed"):
      return done(self.failed_units)
    if arguments[:2] == ("systemctl", "daemon-reload"):
      return done()
    if arguments[:2] == ("systemctl", "reset-failed"):
      if self.reset_failed_error:
        return done("", 1, self.reset_failed_error)
      return done()
    if arguments[:2] == ("systemctl", "cat"):
      return done(self.cat())
    if arguments[:2] == ("systemctl", "show") and "ActiveState" in arguments:
      return done(self.unit_state())
    if arguments[:2] == ("systemctl", "show"):
      return done(self.show())
    if arguments == ("systemctl", "suspend"):
      if self.suspend_hook:
        self.suspend_hook()
      self.journal += self.suspend_lines
      return done()
    if arguments == ("systemctl", "hibernate"):
      self.hibernate_invoked = True
      if self.hibernate_hook:
        self.hibernate_hook()
      if self.hibernate_rc:
        return done("", self.hibernate_rc, "Failed to hibernate")
      if not self.consume_transition:
        # logind answered before ExecStart. The one-shot, header and journal stay as they were.
        return done()
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
  # A genuine S3 failure is not repeatable on this image (no-repeat rule); reassess is read-only.
  s3_directory = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("s3-" + BOOT_B)
  failed_text = (s3_directory / "s3.json").read_text()
  verdict = run.s3_reassess(env.host)
  assert verdict["verdict"] == "would-fail" and verdict["state_changed"] is False and verdict["recorded_state"] == "failed"
  assert (s3_directory / "s3.json").read_text() == failed_text
  env.suspend_lines = "[  100.0] host kernel: PM: suspend entry (deep)\n[  110.0] host kernel: ACPI: PM: Waking up from system sleep state S3\n"
  env.journal = KERNEL + SWITCH_ROOT + LATE_WIFI
  rejects(lambda: run.s3(env.host), "genuinely failed on this image and is not repeatable")
  assert (s3_directory / "s3.json").read_text() == failed_text and not list(s3_directory.glob("s3-*.json"))
  rejects(lambda: run.s4_cycle(env.host, 1), "S3 has not passed")

  # Classifier-only failure (the live false positive): the saved journal holds only the bus-number line.
  false_positive = "[19158.200892] kenobi kernel: apple 0003:05AC:0280.0009: hiddev97,hidraw2: USB HID v1.01 Device [Apple Inc. Apple Internal Keyboard / Trackpad] on usb-t2bce_vhci-5/input0"
  env = Env(base / "g2-classifier-only")
  env.boot_test_entry()
  run.verify_boot(env.host)
  s3_directory = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("s3-" + BOOT_B)
  s3_directory.mkdir(parents=True)
  saved = ["[1.0] kernel: PM: suspend entry (deep)", false_positive, "[2.0] kernel: PM: suspend exit"]
  (s3_directory / "s3.json").write_text(json.dumps({"state": "failed", "boot_id": BOOT_B, "problems": [false_positive]}))
  (s3_directory / "after.json").write_text(json.dumps({"problems": [], "journal": saved}))
  failed_text = (s3_directory / "s3.json").read_text()
  assert run.s3_reassess(env.host)["verdict"] == "would-pass"
  assert run.s3(env.host)["qualification"] == "upstream-model-s3-passed"
  assert (s3_directory / "s3-1.json").read_text() == failed_text and (s3_directory / "prior-s3-1" / "after.json").exists()
  record = json.loads((s3_directory / "s3.json").read_text())
  assert record["state"] == "passed" and "classifier-only" in record["rerun_reason"]
  rejects(lambda: run.s3(env.host), "already passed")
  assert run.s3_reassess(env.host)["verdict"] == "would-pass"
  run.require_s3(env.host, env.receipt, BOOT_B)

  # A recorded non-journal problem (health, systemctl failure) keeps the failure genuine even if the journal is clean.
  env = Env(base / "g2-mixed")
  env.boot_test_entry()
  run.verify_boot(env.host)
  s3_directory = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("s3-" + BOOT_B)
  s3_directory.mkdir(parents=True)
  (s3_directory / "s3.json").write_text(json.dumps({"state": "failed", "boot_id": BOOT_B, "problems": ["systemctl suspend failed: x"]}))
  (s3_directory / "after.json").write_text(json.dumps({"problems": [], "journal": saved}))
  rejects(lambda: run.s3(env.host), "not repeatable")
  (s3_directory / "s3.json").write_text(json.dumps({"state": "failed", "boot_id": BOOT_B, "problems": [false_positive]}))
  (s3_directory / "after.json").write_text(json.dumps({"problems": ["Wi-Fi interface is absent or not up"], "journal": saved}))
  rejects(lambda: run.s3(env.host), "not repeatable")

  # An interrupted run (started, no journal) may be repeated, with the reason recorded.
  env = Env(base / "g2-interrupted")
  env.boot_test_entry()
  run.verify_boot(env.host)
  s3_directory = env.root / C.ATTEMPTS / env.receipt["image_sha256"] / ("s3-" + BOOT_B)
  s3_directory.mkdir(parents=True)
  (s3_directory / "s3.json").write_text(json.dumps({"state": "started", "boot_id": BOOT_B}))
  assert run.s3(env.host)["qualification"] == "upstream-model-s3-passed"
  assert "interrupted in state started" in json.loads((s3_directory / "s3.json").read_text())["rerun_reason"]
  assert json.loads((s3_directory / "s3-1.json").read_text())["state"] == "started"
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

  def nonzero_with_transition(e):
    e.hibernate_rc = 1
    e.hibernate_hook = lambda: setattr(e, "journal", e.journal + e.hibernate_lines)

  case = failed_cycle("hibernate-error", nonzero_with_transition, "returned 1")
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
  # An abort inside the power call unwinds nothing: the transition may be in flight.
  assert case.terminal() and case.guard(1).exists() and case.dropin_present() and (case.root / stage.ONESHOT).exists()
  assert case.attempt(1)["state"] == "failed-terminal" and case.attempt(1)["unwound"] is False and "noresume" in case.attempt(1)["stale_image_warning"]
  assert "" not in case.bootctl_log

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

with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-signals-") as temporary:
  base = Path(temporary)
  import signal

  # Non-terminal refusal: hibernate fails, header still SWAPSPACE2, no entry line -> retry the same cycle.
  case = Env(base / "refused")
  case.to_s3_passed()
  case.hibernate_rc = 1
  rejects(lambda: run.s4_cycle(case.host, 1), "returned 1")
  record = case.attempt(1)
  assert record["state"] == "refused-before-transition" and record["real_s4_attempted"] is False
  assert not case.terminal() and not case.guard(1).exists() and not case.dropin_present() and not (case.root / stage.ONESHOT).exists()
  archived = sorted((case.root / C.GUARDS / case.receipt["image_sha256"]).glob("cycle-1.refused-*"))
  assert len(archived) == 1 and json.loads(archived[0].read_text())["cycle"] == 1
  assert record["guard_archived_as"] == archived[0].name
  asked = len([call for call in case.calls if isinstance(call, tuple) and call[0] == "ask"])
  case.hibernate_rc = 0
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  assert len([call for call in case.calls if isinstance(call, tuple) and call[0] == "ask"]) > asked, "a fresh phrase is required"
  prior = list((case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1").glob("prior-*/attempt.json"))
  assert len(prior) == 1 and json.loads(prior[0].read_text())["state"] == "refused-before-transition"
  assert case.guard(1).exists() and not case.terminal() and len(sorted((case.root / C.GUARDS / case.receipt["image_sha256"]).glob("cycle-1.refused-*"))) == 1
  assert (prior[0].parent / "acceptance.json").exists()
  # A second refusal archives a second guard; evidence accumulates.
  case.hibernate_rc = 1
  rejects(lambda: run.s4_cycle(case.host, 2), "returned 1")
  assert case.attempt(2)["state"] == "refused-before-transition" and not case.terminal()

  # Any evidence of a transition stays terminal: header changed, or the entry line is in the journal.
  case = failed_cycle("rc-header", lambda e: (setattr(e, "hibernate_rc", 1), setattr(e, "hibernate_hook", lambda: e.header(b"S1SUSPEND"))), "returned 1")
  assert case.terminal() and case.attempt(1)["state"] == "failed-terminal" and case.guard(1).exists()
  case = failed_cycle("rc-journal", lambda e: (setattr(e, "hibernate_rc", 1), setattr(e, "hibernate_hook", lambda: setattr(e, "journal", e.journal + e.hibernate_lines))), "returned 1")
  assert case.terminal()
  case = failed_cycle("rc-unreadable", lambda e: (setattr(e, "hibernate_rc", 1), setattr(e, "hibernate_hook", lambda: e.header(b"GARBAGE"))), "returned 1")
  assert case.terminal()

  # Terminal death: signals become SystemExit and the cleanup runs.
  previous = signal.getsignal(signal.SIGTERM)
  case = Env(base / "sigterm-before-guard")
  case.to_s3_passed()
  case.lock_hook = lambda: os.kill(os.getpid(), signal.SIGTERM)
  try:
    with run.terminating_signals():
      try:
        run.s4_cycle(case.host, 1)
      except SystemExit as error:
        assert error.code == 128 + signal.SIGTERM
      else:
        raise AssertionError("SIGTERM ignored")
  finally:
    case.lock_hook = None
  assert signal.getsignal(signal.SIGTERM) == previous
  assert not case.dropin_present() and not (case.root / C.RUNTIME_DIR).exists() and not (case.root / stage.ONESHOT).exists()
  assert case.attempt(1)["state"] == "refused-before-guard" and not case.terminal() and not case.guard(1).exists()
  assert stage.load_receipt(case.root)["state"] == "booted"
  case.lock_hook = None
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"

  # After the guard, terminating signals are ignored through the power call and post-return: nothing is
  # disarmed or unwound while a transition may be in flight.
  for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    case = Env(base / ("signal-after-guard-" + str(int(number))))
    case.to_s3_passed()
    seen = {}

    def hook(number=number, case=case, seen=seen):
      os.kill(os.getpid(), number)
      seen["dropin"] = case.dropin_present()
      seen["oneshot"] = (case.root / stage.ONESHOT).exists()
      seen["disarms"] = list(case.bootctl_log)

    case.hibernate_hook = hook
    with run.terminating_signals():
      installed = signal.getsignal(number)
      assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
      assert signal.getsignal(number) == installed
    assert seen["dropin"] is True and seen["oneshot"] is True and "" not in seen["disarms"]
    assert "" not in case.bootctl_log and case.guard(1).exists() and not case.terminal()

  # recover: a dead runner on the test boot.
  case = Env(base / "recover-same-boot")
  case.to_s3_passed()
  run.install_dropin(case.host)
  stage.arm_s4(case.root, 1, runner=bootctl_for(case.root))
  (case.root / stage.ONESHOT).unlink()
  cycle_dir = case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1"
  cycle_dir.mkdir(parents=True)
  (cycle_dir / "attempt.json").write_text(json.dumps({"state": "armed"}))
  (cycle_dir / "evidence.txt").write_text("keep")
  assert stage.load_receipt(case.root)["state"] == "s4-armed"
  result = run.recover(case.host)
  assert result["receipt_state"] == "booted" and result["terminal"] is False and result["test_boot_id"] == BOOT_B
  assert not case.dropin_present() and not (case.root / C.RUNTIME_DIR).exists()
  assert case.attempt(1)["state"] == "refused-before-guard" and (cycle_dir / "evidence.txt").read_text() == "keep"
  assert run.recover(case.host)["receipt_state"] == "booted"

  case = Env(base / "recover-new-boot")
  case.to_s3_passed()
  stage.arm_s4(case.root, 1, runner=bootctl_for(case.root))
  (case.root / stage.ONESHOT).unlink()
  guard = run.create_guard(case.host, case.receipt, 1, {"cycle": 1})
  cycle_dir = case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1"
  cycle_dir.mkdir(parents=True)
  (cycle_dir / "attempt.json").write_text(json.dumps({"state": "transition-started"}))
  case.write("proc/sys/kernel/random/boot_id", BOOT_C + "\n")
  set_boot(case.root, case.entry, BOOT_C)
  run.install_dropin(case.host)
  result = run.recover(case.host)
  assert result["terminal"] is True and result["receipt_state"] == "booted" and result["test_boot_id"] == BOOT_C
  assert guard.exists() and cycle_dir.exists() and case.terminal() and case.attempt(1)["state"] == "failed-terminal"
  assert not case.dropin_present()
  rejects(lambda: stage.arm_s4(case.root, 2, runner=bootctl_for(case.root)), "terminal")

  # A still-armed one-shot on the test boot is disarmed, never left for the next boot.
  case = Env(base / "recover-armed")
  case.to_s3_passed()
  stage.arm_s4(case.root, 1, runner=bootctl_for(case.root))
  result = run.recover(case.host)
  assert not (case.root / stage.ONESHOT).exists() and result["receipt_state"] == "disarmed"

  # From stock, recover refuses.
  case = Env(base / "recover-stock")
  case.to_s3_passed()
  set_boot(case.root, C.STOCK_ENTRY, BOOT_C)
  rejects(lambda: run.recover(case.host), "from the stock boot use cleanup")

print("PASS: upstream-model runner cleans up on signals, recovers a dead runner and retries non-transitions")


with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-evidence-") as temporary:
  base = Path(temporary)
  import fcntl

  # Refusal evidence: every source must agree that no transition began.
  def refusal(name, prepare, retryable):
    case = Env(base / name)
    case.to_s3_passed()
    prepare(case)
    rejects(lambda: run.s4_cycle(case.host, 1), "returned 1")
    assert case.terminal() is (not retryable), name
    assert case.attempt(1)["state"] == ("refused-before-transition" if retryable else "failed-terminal"), name
    return case

  def set_rc(e):
    e.hibernate_rc = 1

  pre_failure_text = "[  50.0] host systemd[1]: systemd-hibernate.service: Control process exited, code=exited, status=1/FAILURE\n[  50.1] host systemd[1]: Failed to start System Hibernate.\n"
  refusal("pre-refusal", lambda e: (set_rc(e), setattr(e, "hibernate_hook", lambda: setattr(e, "journal", e.journal + pre_failure_text))), True)
  refusal("dmesg-freeze", lambda e: (set_rc(e), setattr(e, "hibernate_hook", lambda: setattr(e, "dmesg", e.dmesg + "[   60.0] PM: Freezing user space processes failed\n"))), False)
  for text in ("Syncing filesystems ... done.", "PM: Preparing system for sleep (hibernation)", "swsusp: Basic memory bitmaps created", "Image not found"):
    refusal("dmesg-" + text[:6], lambda e, text=text: (set_rc(e), setattr(e, "hibernate_hook", lambda: setattr(e, "dmesg", e.dmesg + "[   61.0] " + text + "\n"))), False)
  refusal("kernel-journal", lambda e: (set_rc(e), setattr(e, "hibernate_hook", lambda: setattr(e, "journal", e.journal + "[ 62.0] host kernel: PM: Preparing system for sleep (hibernation)\n"))), False)
  refusal("sleep-journal", lambda e: (set_rc(e), setattr(e, "hibernate_hook", lambda: setattr(e, "journal", e.journal + "[ 63.0] host systemd-sleep[99]: Performing sleep operation 'hibernate'...\n"))), False)
  refusal("hibernate-location", lambda e: (set_rc(e), setattr(e, "hibernate_hook", lambda: e.write(HIBERNATE_LOCATION, "x"))), False)
  # Unreadable sources are terminal, never retryable.
  class Unreadable(Env):
    def command(self, arguments, timeout=None):
      if tuple(arguments)[:2] == ("journalctl", "--sync") and getattr(self, "broken", None) == "sync":
        return subprocess.CompletedProcess(arguments, 1, "", "no journal")
      if tuple(arguments)[0] == "dmesg" and getattr(self, "broken", None) == "dmesg" and self.armed_broken:
        return subprocess.CompletedProcess(arguments, 1, "", "dmesg: read kernel buffer failed")
      return super().command(arguments, timeout)

  for broken in ("sync", "dmesg"):
    case = Unreadable(base / ("unreadable-" + broken))
    case.to_s3_passed()
    case.hibernate_rc = 1
    case.broken, case.armed_broken = broken, False
    case.hibernate_hook = lambda case=case: setattr(case, "armed_broken", True)
    rejects(lambda: run.s4_cycle(case.host, 1), "returned 1")
    assert case.terminal() and case.attempt(1)["state"] == "failed-terminal"
  # A dmesg baseline taken at the cursor hides earlier, unrelated kernel lines.
  case = Env(base / "baseline")
  case.to_s3_passed()
  case.dmesg = "[ 5.0] PM: Freezing user space processes (from an earlier cycle)\n"
  case.hibernate_rc = 1
  rejects(lambda: run.s4_cycle(case.host, 1), "returned 1")
  assert not case.terminal() and case.attempt(1)["state"] == "refused-before-transition"
  assert ("journalctl", "--sync") in case.calls

  # Runner lock: a held lock refuses every mutating phase; read-only phases are not gated.
  case = Env(base / "lock")
  case.to_s3_passed()
  descriptor = os.open(case.root / C.STATE / "runner.lock", os.O_RDWR | os.O_CREAT, 0o600)
  fcntl.flock(descriptor, fcntl.LOCK_EX)
  for action in (lambda: run.verify_boot(case.host), lambda: run.s3(case.host), lambda: run.s4_cycle(case.host, 1),
                 lambda: run.cleanup(case.host), lambda: run.recover(case.host)):
    rejects(action, "runner lock")
  assert not case.dropin_present() and not case.guard(1).exists() and len(case.called("systemctl", "suspend")) == 1
  fcntl.flock(descriptor, fcntl.LOCK_UN)
  os.close(descriptor)
  assert run.cleanup(case.host)["state"] == "cleaned"
  # The lock file does not block the stager's state validation or clear.
  set_boot(case.root, C.STOCK_ENTRY, BOOT_C)
  stage.rollback(case.root)
  assert stage.clear_rolled_back(case.root)["state"] == "cleared"
  assert (case.root / C.STATE / "runner.lock").exists()

print("PASS: upstream-model runner ignores signals in flight, weighs all refusal evidence and serialises runners")


with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-pci-") as temporary:
  base = Path(temporary)
  case = Env(base / "pci")
  case.boot_test_entry()
  devices = case.root / "sys/bus/pci/devices"
  facts, problems = run.health(case.host, case.receipt)
  assert problems == [] and facts["driver_" + C.T2_ENCLAVE] is None and facts["enclave_present"] is True
  assert facts["driver_0000:74:00.0"] == "nvme" and facts["driver_0000:74:00.1"] == "t2bce_core" and facts["driver_0000:74:00.3"] == "t2bce_audio"
  # The enclave being unbound is expected; absent is a failure.
  __import__("shutil").rmtree(devices / C.T2_ENCLAVE)
  assert any("Secure Enclave" in item and "not present" in item for item in run.health(case.host, case.receipt)[1])
  (devices / C.T2_ENCLAVE).mkdir()
  # Every other function must be bound to its own driver.
  for function, driver in {**C.T2_DRIVERS, C.WIFI_FUNCTION: "brcmfmac", C.BLUETOOTH_FUNCTION: "hci_bcm4377"}.items():
    link = devices / function / "driver"
    target = os.readlink(link)
    link.unlink()
    assert any(function + " has no bound driver" in item for item in run.health(case.host, case.receipt)[1]), function
    link.symlink_to("../../../bus/pci/drivers/wrong")
    assert any(function + " is bound to wrong" in item for item in run.health(case.host, case.receipt)[1]), function
    link.unlink()
    link.symlink_to(target)
  assert run.health(case.host, case.receipt)[1] == []

print("PASS: upstream-model health accepts the unbound Secure Enclave and requires every other function's driver")


# The real terminal path: a pty slave, not a stub. A single "r+" open of a tty raised UnsupportedOperation.
import pty
import threading

with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-tty-") as temporary:
  base = Path(temporary)
  phrase = C.confirmation_phrase("boot", "a" * 64, BOOT_B)
  master, slave = pty.openpty()
  try:
    host = run.Host(base, tty_path=os.ttyname(slave), euid=lambda: 0)
    # Old behaviour, for the record: text-mode r+ cannot open a tty.
    try:
      open(os.ttyname(slave), "r+")
    except OSError as error:
      assert "seekable" in str(error)
    else:
      raise AssertionError("r+ unexpectedly worked")
    os.write(master, (phrase + "\n").encode())
    assert host.ask("prompt> ") == phrase
    assert b"prompt> " in os.read(master, 4096)
    # A wrong or empty answer is returned as typed (the caller compares).
    os.write(master, b"\n")
    assert host.ask("again> ") == ""
    # The same path works for the real confirm() flow end to end.
    os.write(master, (phrase + "\n").encode())
    assert run.confirm(host, phrase) == C.sha256(phrase.encode())
  finally:
    os.close(master)
    os.close(slave)
  # A genuinely missing terminal keeps the original refusal.
  absent = run.Host(base, tty_path=str(base / "no-such-dir" / "tty"), euid=lambda: 0)
  rejects(lambda: absent.ask("x> "), "controlling terminal (/dev/tty) is required")
  assert run.Host(base).tty_path == "/dev/tty"

print("PASS: upstream-model typed confirmation works on a real pty and refuses without a terminal")


# The classifier flags real error reports and never device or bus names (real lines from the live S3).
REAL_OK = [
  "[19158.200892] kenobi kernel: apple 0003:05AC:0280.0009: hiddev97,hidraw2: USB HID v1.01 Device [Apple Inc. Apple Internal Keyboard / Trackpad] on usb-t2bce_vhci-5/input0",
  "[19158.195013] kenobi kernel: input: Apple Inc. Apple Internal Keyboard / Trackpad as /devices/pci0000:00/0000:00:1c.4/0000:74:00.1/t2bce_core/t2bce_core/t2bce_vhci/usb5/5-5/5-5:1.0/0003:05AC:0280.0009/input/input79",
  "[19158.100000] kenobi kernel: t2bce_core: resume: exit status=0 path=stateful elapsed=312ms",
  "[19158.150000] kenobi kernel: usb 5-1: reset high-speed USB device number 2 using t2bce_core",
  "[19157.900000] kenobi kernel: PM: suspend entry (deep)",
  "[19158.300000] kenobi kernel: PM: suspend exit",
  "[19158.310000] kenobi kernel: ACPI: PM: Waking up from system sleep state S3",
  "[19158.400000] kenobi bluetoothd[900]: Bluetooth: hci0: Injecting HCI hardware error event",
  "[19158.410000] kenobi kernel: Bluetooth: hci0: Injecting HCI hardware error event",
  "[19158.420000] kenobi kernel: t2bce_core: suspend: exit status=0",
  "[19158.430000] kenobi kernel: t2bce_core: module verification failed: signature and/or required key missing - tainting kernel",
  "[19158.440000] kenobi kernel: module verification failed: signature and/or required key missing - tainting kernel",
  "[19158.450000] kenobi kernel: t2bce_core 0000:74:00.1: resume: exit status=0 path=stateful",
]
REAL_BAD = [
  "[1.0] kenobi kernel: t2bce_core: suspend: exit status=-5",
  "[1.0] kenobi kernel: t2bce_vhci: command timed out",
  "[1.0] kenobi kernel: xhci_hcd 0000:00:14.0: xHCI host controller not responding, HC died",
  "[1.0] kenobi kernel: Call Trace:",
  "[1.0] kenobi kernel: t2bce_core: resume failed",
  "[1.0] kenobi kernel: t2bce_dma: error -5 while mapping",
  "[1.0] kenobi kernel: t2bce_core: resume: ret=-110",
  "[1.0] kenobi kernel: t2bce_vhci: urb dequeue returned -EIO",
  "[1.0] kenobi kernel: PM: Device 0000:74:00.1 failed to suspend: error -5",
  "[1.0] kenobi kernel: PM: dpm_run_callback(): pci_pm_suspend+0x0/0x1a0 returns -5",
  "[1.0] kenobi kernel: BUG: unable to handle page fault",
  "[1.0] kenobi kernel: Oops: 0000 [#1] SMP",
  "[1.0] kenobi kernel: t2bce_core 0000:74:00.1: command timed out",
  "[1.0] kenobi kernel: t2bce_vhci 0000:74:00.1: resume failed",
  "[1.0] kenobi kernel: t2bce_core 0000:74:00.1: suspend: exit status=-5",
  "[1.0] kenobi kernel: Freezing of tasks failed after 20.003 seconds (1 tasks refusing to freeze, wq_busy=0):",
  "[1.0] kenobi kernel: PM: Error -12 creating image",
]
for line in REAL_OK:
  assert not run.is_bad_pm(line), line
for line in REAL_BAD:
  assert run.is_bad_pm(line), line

# End to end: the live false positive no longer fails S3, and the S4 post-return classifier shares the rule.
with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-classifier-") as temporary:
  base = Path(temporary)
  case = Env(base / "false-positive")
  case.boot_test_entry()
  run.verify_boot(case.host)
  case.suspend_lines += "".join(line.split("kenobi ", 1)[1].join(["[200.0] host ", ""]) + "\n" for line in REAL_OK[:4])
  assert run.s3(case.host)["qualification"] == "upstream-model-s3-passed"
  bad = Env(base / "true-positive")
  bad.boot_test_entry()
  run.verify_boot(bad.host)
  bad.suspend_lines += "[ 200.0] host kernel: t2bce_core: suspend: exit status=-5\n"
  rejects(lambda: run.s3(bad.host), "status=-5")
  # Reassess uses the current classifier on the saved journal and changes nothing.
  before = (bad.root / C.ATTEMPTS / bad.receipt["image_sha256"] / ("s3-" + BOOT_B) / "s3.json").read_text()
  assert run.s3_reassess(bad.host)["verdict"] == "would-fail"
  assert (bad.root / C.ATTEMPTS / bad.receipt["image_sha256"] / ("s3-" + BOOT_B) / "s3.json").read_text() == before
  # An old failed record that only tripped on the bus-number false positive reassesses as would-pass.
  old = Env(base / "old-false-positive")
  old.boot_test_entry()
  run.verify_boot(old.host)
  old_dir = old.root / C.ATTEMPTS / old.receipt["image_sha256"] / ("s3-" + BOOT_B)
  old_dir.mkdir(parents=True)
  (old_dir / "s3.json").write_text(json.dumps({"state": "failed", "problems": ["old"]}))
  (old_dir / "after.json").write_text(json.dumps({"problems": [], "journal": ["[1.0] kernel: PM: suspend entry (deep)", REAL_OK[0], "[2.0] kernel: PM: suspend exit"]}))
  verdict = run.s3_reassess(old.host)
  assert verdict["verdict"] == "would-pass" and verdict["recorded_state"] == "failed" and verdict["state_changed"] is False

print("PASS: upstream-model classifier flags real PM errors only, S3 may be repeated, and reassess is read-only")



# The session lock: exact runuser argv, OMARCHY_PATH validation, and a refused cycle is retryable with the same number.
with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-lock-") as temporary:
  base = Path(temporary)
  omarchy = base / "omarchy"
  (omarchy / "bin").mkdir(parents=True)
  (omarchy / "shell").mkdir()
  (omarchy / "bin/omarchy-system-sleep-lock").write_text("#!/bin/bash\n")
  (omarchy / "shell/shell.qml").write_text("")
  calls = []

  def fake(arguments, timeout=None):
    calls.append((tuple(str(item) for item in arguments), timeout))
    if tuple(arguments)[-3:] == ("systemctl", "--user", "show-environment"):
      return subprocess.CompletedProcess(arguments, 0, "A=b\nOMARCHY_PATH=" + str(omarchy) + "\n", "")
    return subprocess.CompletedProcess(arguments, 0, "", "")

  def lock_host(environ):
    host = run.Host(base, environ=environ)
    host._subprocess = fake
    return host

  sudo = {"SUDO_UID": "1000", "SUDO_USER": "jjc"}
  expected = ("runuser", "-u", "jjc", "--", "env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
              "OMARCHY_PATH=" + str(omarchy), "PATH=" + str(omarchy) + "/bin:/usr/local/bin:/usr/bin", str(omarchy) + "/bin/omarchy-system-sleep-lock")
  lock_host({**sudo, "OMARCHY_PATH": str(omarchy)}).lock()
  assert calls == [(expected, 30)], calls
  # Fallback: the user's systemd manager environment.
  calls.clear()
  lock_host(sudo).lock()
  assert calls[0][0] == ("runuser", "-u", "jjc", "--", "env", "XDG_RUNTIME_DIR=/run/user/1000", "systemctl", "--user", "show-environment")
  assert calls[1] == (expected, 30)
  # Refusals.
  empty = lock_host(sudo)
  empty._subprocess = lambda arguments, timeout=None: subprocess.CompletedProcess(arguments, 0, "A=b\n", "")
  rejects(empty.lock, "OMARCHY_PATH is not set")
  for bad in ("relative/path", str(omarchy) + "/../omarchy", str(base / "nope"), str(base)):
    rejects(lock_host({**sudo, "OMARCHY_PATH": bad}).lock, "not an Omarchy checkout")
  (omarchy / "shell/shell.qml").unlink()
  rejects(lock_host({**sudo, "OMARCHY_PATH": str(omarchy)}).lock, "not an Omarchy checkout")
  (omarchy / "shell/shell.qml").write_text("")
  (omarchy / "bin/omarchy-system-sleep-lock").unlink()
  rejects(lock_host({**sudo, "OMARCHY_PATH": str(omarchy)}).lock, "not an Omarchy checkout")
  (omarchy / "bin/omarchy-system-sleep-lock").write_text("#!/bin/bash\n")
  rejects(lock_host({}).lock, "run the runner through sudo")
  failing = lock_host({**sudo, "OMARCHY_PATH": str(omarchy)})
  failing._subprocess = lambda arguments, timeout=None: subprocess.CompletedProcess(arguments, 1, "", "omarchy-system-sleep-lock: suspending without a secure lock")
  rejects(failing.lock, "Desktop lock was not secured: omarchy-system-sleep-lock: suspending without a secure lock")

  # A cycle refused at the lock (no guard, hibernate not attempted) is re-run with the same number; the old attempt is archived.
  case = Env(base / "lock-retry")
  case.to_s3_passed()
  case.lock_hook = lambda: (_ for _ in ()).throw(ValueError("Desktop lock was not secured: the shell did not secure the session"))
  rejects(lambda: run.s4_cycle(case.host, 1), "Desktop lock was not secured")
  refused = case.attempt(1)
  assert refused["state"] == "refused-before-guard" and refused["hibernate_attempted"] is False and not case.guard(1).exists() and not case.terminal()
  cycle_dir = case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1"
  case.lock_hook = None
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  prior = list(cycle_dir.glob("prior-*/attempt.json"))
  assert len(prior) == 1 and json.loads(prior[0].read_text())["state"] == "refused-before-guard"
  assert (prior[0].parent / "pre.json").exists() and case.guard(1).exists()

print("PASS: upstream-model session lock passes OMARCHY_PATH and PATH explicitly and a lock refusal is retryable")


# Settle, cat, and the inhibit-delay race. Pre-start idle is not "settled".
assert run.hibernate_transaction("ExecStart={ path=/usr/lib/systemd/systemd-sleep ; argv[]=/usr/lib/systemd/systemd-sleep hibernate ; }\n") == "missing"
assert run.hibernate_transaction("ActiveState=activating\nSubState=start\nJob=12\n") == "busy"
assert run.hibernate_transaction("ActiveState=active\nSubState=running\nJob=\n") == "busy"
assert run.hibernate_transaction("ActiveState=failed\nSubState=failed\nJob=\n") == "failed"
assert run.hibernate_transaction("ActiveState=inactive\nSubState=dead\nJob=0\n") == "idle"
assert run.hibernate_transaction("ActiveState=inactive\nSubState=dead\nJob=\n") == "idle"
assert run.last_execstart("ExecStart=\nExecStart=/usr/bin/python3 -B /x/sleep_entry.py\nExecStart=\nExecStart=/usr/lib/systemd/systemd-sleep hibernate\n") == "/usr/lib/systemd/systemd-sleep hibernate"
assert run.last_execstart("ExecStart=/usr/bin/python3 -B /x/sleep_entry.py\n").endswith("sleep_entry.py")

with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-race-") as temporary:
  base = Path(temporary)

  # rc 0: inactive (inhibit delay), then activating, then failed. Drop-in stays through the idle polls.
  case = Env(base / "early-return")
  case.to_s3_passed()
  case.consume_transition = False
  polls = {"n": 0, "idle": 0}

  def active(polls=polls, case=case):
    polls["n"] += 1
    assert case.dropin_present(), "drop-in removed before systemd-hibernate.service left the transaction"
    if polls["n"] <= 2:
      polls["idle"] += 1
      return "inactive"
    return "activating" if polls["n"] < 5 else "failed"

  case.hibernate_active = active
  rejects(lambda: run.s4_cycle(case.host, 1), "returned 0 with LoaderEntryOneShot still armed")
  assert polls["idle"] >= 2 and polls["n"] >= 5
  record = case.attempt(1)
  assert record["state"] == "refused-before-transition" and record["hibernate_returncode"] == 0 and record["real_s4_attempted"] is False
  assert not case.terminal() and not case.guard(1).exists() and not case.dropin_present() and not (case.root / stage.ONESHOT).exists()
  assert len(sorted((case.root / C.GUARDS / case.receipt["image_sha256"]).glob("cycle-1.refused-*"))) == 1
  assert ("systemctl", "reset-failed", "systemd-hibernate.service") in case.calls
  # The same cycle can proceed once the unit settles and the transition is consumed.
  case.consume_transition = True
  case.hibernate_active = None
  case.hibernate_invoked = False
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  assert case.guard(1).exists() and not case.terminal()

  # Evidence of a freeze with the one-shot still armed stays terminal.
  case = Env(base / "early-but-freezing")
  case.to_s3_passed()
  case.consume_transition = False
  case.hibernate_hook = lambda: setattr(case, "dmesg", case.dmesg + "[   60.0] PM: Freezing user space processes\n")
  rejects(lambda: run.s4_cycle(case.host, 1), "one-shot")
  assert case.terminal() and case.guard(1).exists() and case.attempt(1)["state"] == "failed-terminal"

  # A unit that stays activating is left untouched and the image is terminal.
  case = Env(base / "settle-timeout")
  case.to_s3_passed()
  case.consume_transition = False
  case.hibernate_active = "activating"
  rejects(lambda: run.s4_cycle(case.host, 1), "did not settle")
  assert case.terminal() and case.dropin_present() and (case.root / stage.ONESHOT).exists() and case.guard(1).exists()
  assert case.attempt(1)["unwound"] is False and case.attempt(1)["state"] == "failed-terminal"

  # rc 0 and the unit never leaves inactive: the inhibit deadline fires, and nothing is unwound.
  case = Env(base / "never-started")
  case.to_s3_passed()
  case.consume_transition = False
  case.hibernate_active = "inactive"
  rejects(lambda: run.s4_cycle(case.host, 1), "did not settle")
  assert case.terminal() and case.dropin_present() and (case.root / stage.ONESHOT).exists() and case.guard(1).exists()
  assert case.attempt(1)["unwound"] is False and case.attempt(1)["state"] == "failed-terminal"
  assert "45s" in case.attempt(1)["error"]

  # The activating window was missed, but the one-shot is gone and the entry line is present.
  case = Env(base / "missed-poll")
  case.to_s3_passed()
  case.consume_transition = False
  polls = {"n": 0}

  def missed(polls=polls, case=case):
    polls["n"] += 1
    assert case.dropin_present(), "drop-in removed while the unit was still idle"
    if polls["n"] < 3:
      return "inactive"
    (case.root / stage.ONESHOT).unlink()
    case.header(b"SWAPSPACE2", 5)
    case.journal += case.hibernate_lines
    return "inactive"

  case.hibernate_active = missed
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  assert polls["n"] >= 3 and case.guard(1).exists() and not case.terminal() and not case.dropin_present()

  # A nonzero return with the unit still idle is logind refusing, not the inhibit-delay race.
  case = Env(base / "rc-idle")
  case.to_s3_passed()
  case.hibernate_rc = 1
  polls = {"n": 0}

  def stay_idle(polls=polls):
    polls["n"] += 1
    return "inactive"

  case.hibernate_active = stay_idle
  rejects(lambda: run.s4_cycle(case.host, 1), "returned 1")
  assert polls["n"] == 1
  assert case.attempt(1)["state"] == "refused-before-transition" and not case.terminal()
  assert not case.dropin_present() and not (case.root / stage.ONESHOT).exists()

  # A stale failed unit is refused before the guard, so it cannot be read as this attempt.
  case = Env(base / "stale-failed")
  case.to_s3_passed()
  case.pre_guard_state = "failed"
  rejects(lambda: run.s4_cycle(case.host, 1), "not idle before the guard")
  assert case.attempt(1)["state"] == "refused-before-guard" and not case.guard(1).exists() and not case.terminal()
  assert not case.dropin_present() and not (case.root / stage.ONESHOT).exists() and not case.called("systemctl", "hibernate")

  # systemd 261: reset-failed says the unit is not loaded when it was never started. That is not a failed unit.
  case = Env(base / "reset-not-loaded")
  case.to_s3_passed()
  case.reset_failed_error = "Failed to reset failed state of unit systemd-hibernate.service: Unit systemd-hibernate.service not loaded."
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  assert case.guard(1).exists() and not case.terminal() and case.called("systemctl", "hibernate")

  # Any other reset-failed failure is still before the guard.
  case = Env(base / "reset-denied")
  case.to_s3_passed()
  case.reset_failed_error = "Failed to reset failed state of unit systemd-hibernate.service: Access denied"
  rejects(lambda: run.s4_cycle(case.host, 1), "Could not clear systemd-hibernate.service")
  assert case.attempt(1)["state"] == "refused-before-guard" and not case.guard(1).exists() and not case.terminal()
  assert not case.called("systemctl", "hibernate")

  # cat's last ExecStart is the product hook: refuse before the guard and remove the drop-in.
  case = Env(base / "cat-product")
  case.to_s3_passed()
  case.cat_override = "ExecStart=/usr/bin/python3 -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/sleep_entry.py\n"
  rejects(lambda: run.s4_cycle(case.host, 1), "last ExecStart is not stock")
  assert not case.guard(1).exists() and not case.dropin_present() and not case.terminal() and not case.called("systemctl", "hibernate")

  # The unit is right at install time and wrong again just before the guard.
  case = Env(base / "cat-recheck")
  case.to_s3_passed()
  real_arm = run.STAGE.arm_s4

  def flip(root, cycle, runner=None, sync=None, case=case):
    real_arm(root, cycle, runner=runner, sync=sync)
    case.cat_override = "ExecStart=/usr/bin/python3 -B /x/sleep_entry.py\n"

  run.STAGE.arm_s4 = flip
  try:
    rejects(lambda: run.s4_cycle(case.host, 1), "last ExecStart is not stock")
  finally:
    run.STAGE.arm_s4 = real_arm
  assert not case.guard(1).exists() and not case.terminal() and not (case.root / stage.ONESHOT).exists() and not case.dropin_present()

print("PASS: upstream-model runner waits for hibernate to settle and treats an armed one-shot as no transition")


def plant_terminal(case, *, journal_extra="", post_journal=None, efi=None, problems=None):
  """A failed-terminal cycle shaped like the 2026-10-06 userspace misclassification."""
  sha = case.receipt["image_sha256"]
  directory = case.root / C.ATTEMPTS / sha / "cycle-1"
  directory.mkdir(parents=True)
  if problems is None:
    problems = ["Journal lacks the hibernation entry line"]
  attempt = {
    "state": "failed-terminal", "hibernate_attempted": True, "hibernate_returncode": 0, "real_s4_attempted": True,
    "pre_write_monotonic": "22722.96", "boot_id": BOOT_B, "cycle": 1, "image_sha256": sha, "post_problems": problems,
    "error": "Post-return checks failed: Journal lacks the hibernation entry line",
  }
  (directory / "attempt.json").write_text(json.dumps(attempt) + "\n")
  if post_journal is None:
    # The span has to cover the refusal. The live post capture runs from the cursor through the
    # settle, so the maintenance line sits inside it even though the filter did not keep that line.
    post_journal = ["[22712.359805] host NetworkManager[1]: dhcp4 activation beginning",
                    "[22804.014243] host NetworkManager[1]: dhcp4 activation beginning"]
  if efi is None:
    efi = ["LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"]
  post = {"journal": post_journal, "efi_variables": efi,
          "swap_header_after": {"marker": "normal-swap-signature", "signature_hex": b"SWAPSPACE2".hex(), "flags": 5}}
  (directory / "post.json").write_text(json.dumps(post) + "\n")
  run.create_guard(case.host, case.receipt, 1, {"cycle": 1, "boot_id": BOOT_B})
  run.STAGE.mark_terminal(case.root, sha, "test misclassification")
  case.journal += "[22713.245020] host python3[9]: ValueError: " + run.MAINTENANCE_REFUSAL + "\n" + journal_extra


with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-reclassify-") as temporary:
  base = Path(temporary)

  case = Env(base / "reclassify-ok")
  case.to_s3_passed()
  # A later S3-style freeze is outside the post-capture window and must not block.
  plant_terminal(case, journal_extra="[90000.000000] host kernel: Freezing user space processes\n")
  result = run.reclassify_userspace_refusal(case.host, 1)
  sha = case.receipt["image_sha256"]
  assert result["state"] == "refused-before-transition" and not case.terminal()
  assert case.attempt(1)["reclassified_from"] == "failed-terminal" and case.attempt(1)["real_s4_attempted"] is False
  names = sorted(path.name for path in (case.root / C.TERMINAL).iterdir())
  assert len(names) == 1 and names[0].startswith(sha + ".reclassified-") and names[0].endswith(".json")
  assert names[0].removesuffix(".json") != sha
  assert not case.guard(1).exists()
  archived = sorted((case.root / C.GUARDS / sha).glob("cycle-1.refused-*"))
  assert len(archived) == 1 and archived[0].is_file()
  # The archived marker still holds the original reason.
  assert "misclassification" in (case.root / C.TERMINAL / names[0]).read_text()
  assert run.s4_cycle(case.host, 1)["state"] == "returned-and-cleaned"
  assert case.guard(1).exists() and not case.terminal()
  prior = list((case.root / C.ATTEMPTS / sha / "cycle-1").glob("prior-*/attempt.json"))
  assert len(prior) == 1 and json.loads(prior[0].read_text())["state"] == "refused-before-transition"
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "not failed-terminal")

  case = Env(base / "window-freeze")
  case.to_s3_passed()
  plant_terminal(case, journal_extra="[22713.500000] host kernel: PM: Freezing user space processes\n")
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "Journal window shows a hibernation transition")
  assert case.terminal() and case.guard(1).exists() and case.attempt(1)["state"] == "failed-terminal"

  case = Env(base / "no-refusal-text")
  case.to_s3_passed()
  plant_terminal(case)
  case.journal = case.journal.replace(run.MAINTENANCE_REFUSAL, "some other error")
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "lacks the package-maintenance refusal")
  assert case.terminal() and case.guard(1).exists()

  case = Env(base / "dirty-header")
  case.to_s3_passed()
  plant_terminal(case)
  case.header(b"S1SUSPEND")
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "SWAPSPACE2")
  assert case.terminal() and case.guard(1).exists()

  case = Env(base / "no-oneshot")
  case.to_s3_passed()
  plant_terminal(case, efi=["LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"])
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "did not record LoaderEntryOneShot")
  assert case.terminal() and case.guard(1).exists()

  case = Env(base / "captured-entry")
  case.to_s3_passed()
  plant_terminal(case, post_journal=["[22712.359805] host kernel: PM: hibernation: hibernation entry"])
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "Captured journal shows a hibernation transition")
  assert case.terminal() and case.guard(1).exists()

  case = Env(base / "hibernate-location")
  case.to_s3_passed()
  plant_terminal(case, efi=["LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", "HibernateLocation-8cf2644b-4b0b-428f-9387-6d876050dc67"])
  rejects(lambda: run.reclassify_userspace_refusal(case.host, 1), "HibernateLocation was set")
  assert case.terminal() and case.guard(1).exists()

print("PASS: upstream-model reclassify archives a userspace refusal and leaves a real transition terminal")


# Autonomous mode records a waiver. It does not read the tty and it does not hash a phrase nobody typed.
silent = run.Host(Path("/"), autonomous=True, ask=lambda prompt: (_ for _ in ()).throw(AssertionError("tty read: " + prompt)))
assert run.confirm(silent, "not typed") == C.sha256(run.WAIVER_TOKEN)
assert C.sha256(run.WAIVER_TOKEN) != C.sha256(C.attendance_phrase("a" * 64, BOOT_B, 1, "AC").encode())

with tempfile.TemporaryDirectory(prefix="t2-upstream-runner-autonomous-") as temporary:
  base = Path(temporary)
  case = Env(base / "auto-s4")
  case.to_s3_passed()
  asked = len([call for call in case.calls if isinstance(call, tuple) and call[0] == "ask"])
  case.host.autonomous = True
  attempt = run.s4_cycle(case.host, 1)
  assert len([call for call in case.calls if isinstance(call, tuple) and call[0] == "ask"]) == asked
  assert attempt["state"] == "returned-and-cleaned" and attempt["physical_confirmation"] == "waived-by-owner"
  assert attempt["waiver_sha256"] == C.sha256(run.WAIVER_TOKEN) and "physical_confirmation_sha256" not in attempt
  acceptance = json.loads((case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1" / "acceptance.json").read_text())
  assert acceptance["kind"] == run.AUTONOMOUS_KIND and acceptance["attendance"] == "owner-authorized-without-typed-phrase"
  assert acceptance["waiver_sha256"] == C.sha256(run.WAIVER_TOKEN) and "phrase_sha256" not in acceptance
  assert acceptance["waiver_sha256"] != C.sha256(C.attendance_phrase(case.receipt["image_sha256"], BOOT_B, 1, "AC").encode())
  # An attended host must not accept the waiver file.
  case.host.autonomous = False
  rejects(lambda: run.require_acceptance(case.host, case.receipt, 1, BOOT_B, "AC", case.root / C.ATTEMPTS / case.receipt["image_sha256"] / "cycle-1"), "differs")

print("PASS: upstream-model autonomous mode waives typed phrases without forging one")
