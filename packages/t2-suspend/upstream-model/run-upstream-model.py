#!/usr/bin/python3
"""Attended upstream-model hibernation test runner (gates G0-G4).

Phases, all run as root from the stager's receipt:
  preflight    G0 preconditions, read-only.
  verify-boot  G1 ordinary boot of the staged image: entry, cmdline, t2bce srcversions,
               Wi-Fi not loaded from the initramfs, health, typed physical-input confirmation.
  s3           G2 plain `systemctl suspend` with pre/post health and typed confirmation.
  s4           G3/G4 one S4 cycle (1, 2 or 3): attendance phrase, O_EXCL guard before the power
               write, one-shot armed, /run drop-in routing `systemctl hibernate` to stock
               systemd-sleep, evidence, post-return cleanup and confirmation.
  recover      On the test boot after a dead runner: remove the drop-in, disarm, settle attempts, continue.
  pre-reactivate-check  Refuse while any drop-in, /run helper, one-shot, receipt or unsettled attempt remains.
  cleanup      Remove the /run drop-in and helpers and disarm an owned one-shot.
  recovery     Print the recovery checklist.
Any failure after a guard is consumed makes the image hash terminal. Typed phrases come from
/dev/tty. The runner never writes boot entries itself; it arms only through the stager.
"""

import argparse
from contextlib import contextmanager
import fcntl
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("upstream_model_common", HERE / "common.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)
STAGE = C.import_path("upstream_model_stager", HERE / "stage-upstream-model.py")
HEADER = C.import_path("upstream_model_swap_header", C.EXPERIMENTS / "audit-hibernation-swap-header.py")

PREPARE = HERE / "prepare.py"
WIFI_HELPER = C.EXPERIMENTS / "0008-wifi-hibernate-isolation/omarchy-t2-hibernate-wifi"
PRODUCT_RUNTIME = "/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate"
GUARD_SCRIPT = PRODUCT_RUNTIME + "/update_guard.py"
NATIVE_SCRIPT = PRODUCT_RUNTIME + "/boot_policy_native.py"
MODEL = "MacBookAir9,1"
ACCEPTANCE_SECONDS = 30 * 60
SETTLE_SECONDS = 90
BATTERY_MINIMUM = 70
CYCLE_POWER = {1: "AC", 2: "AC", 3: "battery"}
HIBERNATE_LOCATION = "sys/firmware/efi/efivars/HibernateLocation-8cf2644b-4b0b-428f-9387-6d876050dc67"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
JOURNAL_FILTER = re.compile(
  r"PM:|Waking up from|t2bce|\bbce\b|vhci|HC died|timeout|brcmfmac|hci_bcm4377|thunderbolt|i915|nvme|btrfs|Call Trace",
  re.I,
)
BAD_PM = re.compile(r"HC died|Call Trace|t2bce\S*.*(?:error|failed|timed out|-5\b)|BUG:|Oops", re.I)
EVIDENCE_COMMANDS = {
  "lspci-k": ("lspci", "-k"),
  "lsmod": ("lsmod",),
  "bluetooth": ("timeout", "5s", "bluetoothctl", "show"),
  "wifi-link": ("iw", "dev"),
  "audio-wpctl": ("wpctl", "status"),
  "audio-aplay": ("aplay", "-l"),
  "bolt": ("boltctl", "list"),
  "failed-units": ("systemctl", "--failed", "--no-legend", "--plain"),
  "btrfs-device-stats": ("btrfs", "device", "stats", "/"),
  "inhibitors": ("systemd-inhibit", "--list", "--no-pager", "--no-legend"),
}
STALE_WARNING = ("The power call did not return cleanly: the drop-in and any one-shot were left in place. NEXT BOOT: use the noresume "
                 "edit (Limine menu, E on the stock entry, append noresume, F10) and read the swap header before any normal boot; "
                 "then run recover (test boot) or cleanup (stock boot).")
CHECKLIST = """\
Recovery checklist (nothing here repeats a hibernation attempt):
 1. Write down what the screen showed, how long it took, and whether the machine powered down by itself.
 2. Hold the power button until off, then power on. LoaderEntryOneShot was consumed, so Limine boots stock Omarchy.linux-t2.
    STALE-IMAGE MITIGATION: if the failed S4 may have left the image intact, the stock resume hook could restore it with an
    unpatched BCE. At the Limine menu highlight the stock entry (Omarchy), press E, move to the cmdline line, press End,
    type a space and noresume, then press F10 to boot once. Read the swap header from that boot (step 4) before any normal boot.
 3. On the stock boot run: journalctl -b | head -200 | grep -iE 'Image not found|resume|hibernat'
    'Image not found' means the image was consumed and the session is lost (filesystem consistent).
    If stock resumed the image instead, record it as an unplanned vector and stop.
 4. Read the swap header: SWAPSPACE2 means no image remains. S1SUSPEND after a normal stock boot should be impossible.
 5. The image SHA-256 is now terminal: do not re-arm it; the next attempt needs a new image hash and a design review.
 6. Roll back the staged entry from the stock boot: stage-upstream-model.py rollback, then clear.
 7. Run assess; reactivate the product only if assess reports unchanged. Otherwise hibernation stays off.
"""


class Host:
  """Everything the runner touches outside its own state: commands, the terminal, clocks and the root."""

  def __init__(self, root=Path("/"), run=None, ask=None, now=time.time, sleep=time.sleep, euid=os.geteuid,
               sync=os.sync, stager_runner=subprocess.run, owner=None, lock=None, environ=None):
    self.root = Path(root)
    self.now, self.sleep, self.euid, self.sync = now, sleep, euid, sync
    self.stager_runner = stager_runner
    self.environ = os.environ if environ is None else environ
    self._run = run or self._subprocess
    self._ask = ask or self._tty
    self._lock = lock or self._session_lock
    self.owner = 0 if self.root.resolve() == Path("/") else os.geteuid() if owner is None else owner

  @staticmethod
  def _subprocess(arguments, timeout=None):
    try:
      return subprocess.run([str(item) for item in arguments], text=True, capture_output=True, check=False, env=ENV, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
      return subprocess.CompletedProcess(arguments, 127, "", str(error))

  @staticmethod
  def _tty(prompt):
    try:
      with open("/dev/tty", "r+") as terminal:
        terminal.write(prompt)
        terminal.flush()
        return terminal.readline().rstrip("\n")
    except OSError as error:
      raise ValueError("A controlling terminal (/dev/tty) is required for typed confirmation") from error

  def _session_lock(self):
    uid = self.environ.get("SUDO_UID")
    user = self.environ.get("SUDO_USER")
    if not uid or not user:
      raise ValueError("Cannot lock the desktop session: run the runner through sudo from the desktop user")
    runtime = "/run/user/" + uid
    result = self._subprocess(("runuser", "-u", user, "--", "env", "XDG_RUNTIME_DIR=" + runtime,
                               "DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus", "omarchy-system-sleep-lock"), timeout=30)
    if result.returncode != 0:
      raise ValueError("Desktop lock was not secured: " + result.stderr.strip()[:200])

  def run(self, arguments, timeout=None):
    return self._run(tuple(arguments), timeout) if timeout else self._run(tuple(arguments))

  def output(self, arguments, timeout=None):
    result = self.run(arguments, timeout)
    if result.returncode != 0:
      raise ValueError("Command failed: " + " ".join(str(item) for item in arguments) + ": " + result.stderr.strip()[:200])
    return result.stdout

  def ask(self, prompt):
    return self._ask(prompt)

  def lock(self):
    self._lock()

  def read(self, relative):
    return (self.root / relative).read_text()

  def exists(self, relative):
    return os.path.lexists(self.root / relative)


def ignore_signals():
  """SIG_IGN for the terminating signals; returns the previous handlers (empty if not the main thread)."""
  previous = {}
  for name in ("SIGHUP", "SIGTERM", "SIGINT"):
    try:
      previous[getattr(signal, name)] = signal.signal(getattr(signal, name), signal.SIG_IGN)
    except ValueError:
      break
  return previous


def restore_signals(previous):
  for number, handler in previous.items():
    signal.signal(number, handler)


@contextmanager
def runner_lock(host):
  """Non-blocking exclusive flock so two runner invocations never mutate state concurrently."""
  path = host.root / C.STATE / "runner.lock"
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  try:
    try:
      fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      raise ValueError("Another upstream-model runner holds the runner lock") from None
    yield
  finally:
    os.close(descriptor)


def locked(function):
  @functools.wraps(function)
  def wrapper(host, *arguments, **options):
    with runner_lock(host):
      return function(host, *arguments, **options)
  return wrapper


def selected_value(text):
  match = re.search(r"\[([^\]]+)\]", text)
  return match.group(1) if match else None


def cmdline_value(text, key):
  for token in text.split():
    if token.split("=", 1)[0] == key:
      return token.split("=", 1)[1] if "=" in token else True
  return None


def save(host, path, data):
  STAGE.atomic_write(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def private_dir(path):
  path.mkdir(parents=True, exist_ok=True, mode=0o700)
  path.chmod(0o700)
  return path


def phase_dir(host, receipt, *names):
  directory = STAGE.rooted(host.root, C.ATTEMPTS / receipt["image_sha256"])
  for name in names:
    directory = directory / name
  return private_dir(directory)


# ---- Facts -------------------------------------------------------------------------

def power_source(host):
  ac, battery = None, None
  base = host.root / "sys/class/power_supply"
  for device in sorted(base.iterdir()) if base.is_dir() else []:
    kind = (device / "type").read_text().strip() if (device / "type").exists() else ""
    if kind == "Mains":
      ac = (device / "online").read_text().strip() == "1"
    elif kind == "Battery" and battery is None:
      battery = {"status": (device / "status").read_text().strip(), "percent": int((device / "capacity").read_text().strip())}
  if ac is None or battery is None:
    raise ValueError("AC and battery state are unavailable")
  return {"ac_online": ac, "label": "AC" if ac else "battery", "battery_status": battery["status"], "battery_percent": battery["percent"]}


def require_power(power, cycle):
  expected = CYCLE_POWER[cycle]
  if power["label"] != expected:
    raise ValueError("Cycle " + str(cycle) + " requires " + expected + " power (plug or unplug the charger)")
  if expected == "battery" and (power["battery_status"] != "Discharging" or power["battery_percent"] < BATTERY_MINIMUM):
    raise ValueError("Battery cycle requires Discharging at or above " + str(BATTERY_MINIMUM) + "% (now " + power["battery_status"] + " " + str(power["battery_percent"]) + "%)")


def swap_target(host):
  """Exact swapfile target agrees with the kernel, the cmdline and Btrfs; refuse any mismatch."""
  cmdline = host.read("proc/cmdline").strip()
  if cmdline_value(cmdline, "resume") != "/dev/mapper/root":
    raise ValueError("cmdline resume= is not /dev/mapper/root")
  offset = cmdline_value(cmdline, "resume_offset")
  if not isinstance(offset, str) or not offset.isdigit() or host.read("sys/power/resume_offset").strip() != offset:
    raise ValueError("Kernel resume_offset differs from the cmdline")
  devnum = host.read("sys/power/resume").strip()
  if re.fullmatch(r"[0-9]+:[0-9]+", devnum) is None or devnum == "0:0":
    raise ValueError("Kernel resume device is not set")
  entries = [line.split() for line in host.read("proc/swaps").splitlines()[1:] if line.strip()]
  candidates = [entry[0] for entry in entries if "zram" not in entry[0]]
  if candidates != ["/swap/swapfile"]:
    raise ValueError("Swap candidates are not exactly /swap/swapfile: " + repr(candidates))
  if host.output(("/usr/bin/btrfs", "inspect-internal", "map-swapfile", "-r", "/swap/swapfile")).strip() != offset:
    raise ValueError("Btrfs swapfile mapping differs from resume_offset")
  return {"device": "/dev/mapper/root", "devnum": devnum, "offset": int(offset)}


def swap_header(host, target):
  header = HEADER.read_header(host.root / "dev/mapper/root", target["offset"])
  return header


def require_clean_header(host, target):
  header = swap_header(host, target)
  if header["marker"] != "normal-swap-signature" or header["signature_hex"] != b"SWAPSPACE2".hex():
    raise ValueError("Swap header does not hold SWAPSPACE2: " + header["marker"])
  return header


def inhibitors(host):
  result = host.run(EVIDENCE_COMMANDS["inhibitors"])
  if result.returncode != 0:
    raise ValueError("Cannot list inhibitors")
  for line in result.stdout.splitlines():
    if line.strip() and line.split()[-1] != "delay":
      raise ValueError("A blocking inhibitor is active: " + line.strip()[:120])
  return result.stdout


def cursor(host):
  text = host.output(("journalctl", "-b", "-n", "0", "--show-cursor", "--no-pager"))
  match = re.search(r"-- cursor: (\S+)", text)
  if match is None:
    raise ValueError("Cannot read a journal cursor")
  return match.group(1)


def journal_slice(host, after=None):
  command = ["journalctl", "-b", "-o", "short-monotonic", "--no-pager"]
  if after:
    command.append("--after-cursor=" + after)
  text = host.output(command)
  return [line for line in text.splitlines() if JOURNAL_FILTER.search(line)], text


def production_cmdline(host):
  data = STAGE.rooted(host.root, Path("boot/EFI/Linux") / C.PRODUCTION_IMAGE).read_bytes()
  return STAGE.pe_sections(data)[".cmdline"][2].rstrip(b"\0").decode().strip()


def monotonic(line):
  match = re.match(r"\[\s*([0-9.]+)\]", line)
  return float(match.group(1)) if match else None


def check_wifi_not_in_initramfs(host):
  """First brcmfmac kernel message must come after PID 1 (systemd) starts on the real root."""
  _filtered, text = journal_slice(host)
  lines = [line for line in text.splitlines() if "kernel" in line or "systemd[1]" in line]
  root_start = next((monotonic(line) for line in lines if "systemd[1]:" in line), None)
  first = next((monotonic(line) for line in lines if "brcmfmac" in line and "kernel" in line), None)
  if root_start is None:
    raise ValueError("Cannot locate the switch to the real root in the kernel log")
  if first is not None and first < root_start:
    raise ValueError("brcmfmac was loaded before switch_root; the initramfs blacklist is ineffective")
  return {"switch_root_monotonic": root_start, "first_brcmfmac_monotonic": first}


def health(host, receipt):
  """(facts, problems). Hard problems stop the test; facts are recorded as evidence."""
  facts, problems = {}, []
  for name in C.T2BCE_MODULES:
    path = "sys/module/" + name + "/srcversion"
    actual = host.read(path).strip() if host.exists(path) else None
    facts["srcversion_" + name] = actual
    if actual != receipt["modules"][name]["srcversion"]:
      problems.append(name + " srcversion differs from the candidate pin")
  required = {**C.T2_DRIVERS, C.WIFI_FUNCTION: "brcmfmac", C.BLUETOOTH_FUNCTION: "hci_bcm4377"}
  for function in C.T2_FUNCTIONS + (C.WIFI_FUNCTION, C.BLUETOOTH_FUNCTION):
    device = host.root / "sys/bus/pci/devices" / function
    link = device / "driver"
    driver = os.path.basename(os.readlink(link)) if link.is_symlink() else None
    facts["driver_" + function] = driver
    if function == C.T2_ENCLAVE:
      # Secure Enclave: present is required, unbound is expected and recorded.
      facts["enclave_present"] = device.is_dir()
      if not device.is_dir():
        problems.append(function + " (T2 Secure Enclave) is not present")
    elif driver is None:
      problems.append(function + " has no bound driver (expected " + required[function] + ")")
    elif driver != required[function]:
      problems.append(function + " is bound to " + driver + ", expected " + required[function])
  nets = sorted((host.root / "sys/bus/pci/devices" / C.WIFI_FUNCTION / "net").glob("*")) if (host.root / "sys/bus/pci/devices" / C.WIFI_FUNCTION / "net").is_dir() else []
  facts["wifi_netdev"] = [net.name for net in nets]
  states = [(net / "operstate").read_text().strip() for net in nets]
  facts["wifi_operstate"] = states
  if not nets or states[0] != "up":
    problems.append("Wi-Fi interface is absent or not up")
  devices = host.read("proc/bus/input/devices") if host.exists("proc/bus/input/devices") else ""
  names = re.findall(r'^N: Name="([^"]*)"', devices, re.M)
  facts["input_devices"] = names
  if not any("Internal Keyboard" in name for name in names) or not any("Trackpad" in name for name in names):
    problems.append("Internal keyboard or trackpad is not registered")
  failed = host.run(EVIDENCE_COMMANDS["failed-units"])
  facts["failed_units"] = failed.stdout.strip()
  if failed.returncode != 0 or failed.stdout.strip():
    problems.append("Failed systemd units: " + failed.stdout.strip()[:200])
  if host.exists(HIBERNATE_LOCATION):
    problems.append("HibernateLocation EFI variable remains set")
  facts["tainted"] = host.read("proc/sys/kernel/tainted").strip() if host.exists("proc/sys/kernel/tainted") else None
  facts["power"] = power_source(host)
  return facts, problems


def settled_health(host, receipt, seconds):
  """Health with a bounded settle window: Wi-Fi association and input re-enumeration take a moment."""
  deadline = host.now() + seconds
  while True:
    facts, problems = health(host, receipt)
    if not problems or host.now() >= deadline:
      return facts, problems
    host.sleep(2)


def capture(host, receipt, directory, label, target=None, after=None, extra=None, settle=0):
  """Write raw evidence for one moment to the phase directory (0600, root)."""
  record = {"label": label, "time": host.now(), "boot_id": STAGE.current_boot_id(host.root)}
  for name, command in EVIDENCE_COMMANDS.items():
    result = host.run(command)
    STAGE.atomic_write(directory / (label + "-" + name + ".txt"),
                       ("rc=" + str(result.returncode) + "\n" + result.stdout + "\n--stderr--\n" + result.stderr).encode(), 0o600)
  if target is not None:
    record["swap_header"] = swap_header(host, target)
  record["efi_variables"] = sorted(item.name for item in (host.root / "sys/firmware/efi/efivars").iterdir()) if (host.root / "sys/firmware/efi/efivars").is_dir() else []
  record["health"], record["problems"] = settled_health(host, receipt, settle)
  if after is not None:
    record["journal"], _full = journal_slice(host, after)
  if extra:
    record.update(extra)
  save(host, directory / (label + ".json"), record)
  return record


# ---- Gates -------------------------------------------------------------------------

def preconditions(host, receipt, *, efi_clear=True):
  """G0. Raises ValueError naming the first failed condition."""
  if host.read("sys/class/dmi/id/product_name").strip() != MODEL:
    raise ValueError("Test is restricted to " + MODEL)
  if host.root.resolve() == Path("/") and host.euid() != 0:
    raise ValueError("Root required")
  STAGE.require_maintenance(host.root)
  guard = host.run(("/usr/bin/python3", "-I", "-B", GUARD_SCRIPT))
  if guard.returncode != 0:
    raise ValueError("Update guard does not admit: " + guard.stderr.strip()[:200])
  assess = host.run(("/usr/bin/python3", "-I", "-B", NATIVE_SCRIPT, "assess"))
  if assess.returncode != 0:
    raise ValueError("assess is not runnable: " + assess.stderr.strip()[:200])
  STAGE.verify_staged(host.root, receipt)
  image_reject_check(host, receipt)
  if host.exists(STAGE.DEFAULT) or (efi_clear and host.exists(STAGE.ONESHOT)):
    raise ValueError("An EFI default or one-shot is present")
  target = swap_target(host)
  require_clean_header(host, target)
  if selected_value(host.read("sys/power/disk")) != "platform":
    raise ValueError("Hibernation disk mode is not [platform]")
  if selected_value(host.read("sys/power/pm_test")) != "none":
    raise ValueError("pm_test is not none")
  inhibitors(host)
  return {"assess": assess.stdout.strip()[:2000], "swap_target": target}


def image_reject_check(host, receipt):
  if receipt["image_sha256"] in C.REJECTED_IMAGE_SHA256:
    raise ValueError("Image hash is on the rejected list")
  if STAGE.is_terminal(host.root, receipt["image_sha256"]):
    raise ValueError("Image hash is terminal after a failed or ambiguous attempt")


def confirm(host, phrase):
  answer = host.ask("Type exactly (Enter alone aborts):\n  " + phrase + "\n> ")
  if answer.strip() != phrase:
    raise ValueError("Typed phrase does not match; nothing was changed")
  return C.sha256(phrase.encode())


def load(host):
  receipt = STAGE.load_receipt(host.root)
  if receipt.get("kernel_policy") != "production-linux-unchanged":
    raise ValueError("Receipt lacks the production-kernel boot policy")
  return receipt


@locked
def verify_boot(host):
  """G1: ordinary boot of the staged image."""
  receipt = load(host)
  if receipt.get("state") not in ("armed", "booted"):
    raise ValueError("Image is not armed or verified (state " + str(receipt.get("state")) + ")")
  facts = preconditions(host, receipt, efi_clear=True)
  if STAGE.selected_entry(host.root) != receipt["entry_id"]:
    raise ValueError("Running boot is not the staged upstream-model entry")
  running = host.read("proc/cmdline").split()
  wanted = production_cmdline(host).split()
  extra = [token for token in running if token not in wanted and not token.startswith(("initrd=", "BOOT_IMAGE="))]
  if any(token not in running for token in wanted) or extra:
    raise ValueError("Running cmdline differs from the production cmdline")
  boot_id = STAGE.current_boot_id(host.root)
  if receipt["state"] == "booted" and receipt.get("test_boot_id") != boot_id:
    raise ValueError("Image was verified on another boot")
  initramfs = check_wifi_not_in_initramfs(host)
  directory = phase_dir(host, receipt, "g1-" + boot_id)
  record = capture(host, receipt, directory, "boot", facts["swap_target"], extra={"initramfs": initramfs})
  if record["problems"]:
    raise ValueError("Ordinary-boot health failed: " + "; ".join(record["problems"]))
  phrase_hash = confirm(host, C.confirmation_phrase("boot", receipt["image_sha256"], boot_id))
  if receipt["state"] == "armed":
    STAGE.mark_booted(host.root)
  save(host, directory / "g1.json", {"state": "passed", "boot_id": boot_id, "image_sha256": receipt["image_sha256"],
                                      "phrase_sha256": phrase_hash, "time": host.now()})
  return {"qualification": "upstream-model-ordinary-boot-verified", "boot_id": boot_id, "hibernate_attempted": False}


def require_g1(host, receipt):
  boot_id = STAGE.current_boot_id(host.root)
  record = STAGE.rooted(host.root, C.ATTEMPTS / receipt["image_sha256"] / ("g1-" + boot_id) / "g1.json")
  if not record.is_file() or json.loads(record.read_text()).get("state") != "passed":
    raise ValueError("Ordinary-boot verification (verify-boot) has not passed on this boot")
  if receipt.get("state") not in ("booted", "disarmed") or receipt.get("test_boot_id") != boot_id:
    raise ValueError("Image is not in the verified test boot")
  return boot_id


@locked
def s3(host):
  """G2: plain S3 suspend on the image."""
  receipt = load(host)
  boot_id = require_g1(host, receipt)
  facts = preconditions(host, receipt, efi_clear=True)
  directory = phase_dir(host, receipt, "s3-" + boot_id)
  if (directory / "s3.json").exists():
    raise ValueError("S3 was already run on this boot; its result is preserved")
  before = capture(host, receipt, directory, "before", facts["swap_target"])
  if before["problems"]:
    raise ValueError("Health before S3 failed: " + "; ".join(before["problems"]))
  host.ask("Press Enter to suspend (S3); wake the machine with a key press afterwards: ")
  mark = cursor(host)
  save(host, directory / "s3.json", {"state": "started", "boot_id": boot_id, "time": host.now()})
  result = host.run(("systemctl", "suspend"))
  after = capture(host, receipt, directory, "after", facts["swap_target"], after=mark, settle=SETTLE_SECONDS)
  lines = after["journal"]
  problems = list(after["problems"])
  if result.returncode != 0:
    problems.append("systemctl suspend failed: " + result.stderr.strip()[:200])
  joined = "\n".join(lines)
  if not re.search(r"suspend entry \(deep\)", joined) or not re.search(r"Waking up from system sleep state S3|PM: suspend exit", joined):
    problems.append("Journal lacks the S3 entry/exit lines")
  problems += [line for line in lines if BAD_PM.search(line)][:5]
  if STAGE.current_boot_id(host.root) != boot_id:
    problems.append("Boot ID changed across S3")
  if problems:
    save(host, directory / "s3.json", {"state": "failed", "boot_id": boot_id, "problems": problems})
    raise ValueError("S3 failed: " + "; ".join(problems))
  phrase_hash = confirm(host, C.confirmation_phrase("s3", receipt["image_sha256"], boot_id))
  save(host, directory / "s3.json", {"state": "passed", "boot_id": boot_id, "phrase_sha256": phrase_hash, "time": host.now()})
  return {"qualification": "upstream-model-s3-passed", "boot_id": boot_id}


# ---- S4 ----------------------------------------------------------------------------

def cycle_state(host, receipt, cycle):
  path = STAGE.rooted(host.root, C.ATTEMPTS / receipt["image_sha256"] / ("cycle-" + str(cycle)) / "attempt.json")
  return json.loads(path.read_text()) if path.is_file() else None


def require_sequence(host, receipt, cycle, boot_id):
  """N+1 requires N returned-and-cleaned on the same original boot; later cycles never pre-exist."""
  if cycle not in CYCLE_POWER:
    raise ValueError("Cycle must be 1, 2 or 3")
  existing = cycle_state(host, receipt, cycle)
  if host.exists(C.GUARDS / receipt["image_sha256"] / ("cycle-" + str(cycle))) or (existing is not None and existing.get("state") not in ("refused-before-guard", "refused-before-transition")):
    raise ValueError("Cycle " + str(cycle) + " already has an attempt or guard; it is never repeated")
  for later in range(cycle + 1, 4):
    if cycle_state(host, receipt, later) is not None:
      raise ValueError("A later cycle already exists")
  for earlier in range(1, cycle):
    record = cycle_state(host, receipt, earlier)
    if record is None or record.get("state") != "returned-and-cleaned" or record.get("boot_id") != boot_id:
      raise ValueError("Cycle " + str(earlier) + " is not returned-and-cleaned on this boot")


def require_s3(host, receipt, boot_id):
  path = STAGE.rooted(host.root, C.ATTEMPTS / receipt["image_sha256"] / ("s3-" + boot_id) / "s3.json")
  if not path.is_file() or json.loads(path.read_text()).get("state") != "passed":
    raise ValueError("S3 has not passed on this boot")


def vector(receipt, cycle, boot_id, power):
  return hashlib.sha256(":".join((receipt["image_sha256"], str(cycle), boot_id, power)).encode()).hexdigest()


def create_guard(host, receipt, cycle, record):
  """Durable O_EXCL guard, fsynced before the power write; never reset by this tool."""
  path = host.root / C.GUARDS / receipt["image_sha256"] / ("cycle-" + str(cycle))
  private_dir(path.parent)
  descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, "w") as stream:
    stream.write(json.dumps(record, sort_keys=True) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
  STAGE.fsync_directory(path.parent)
  return path


def issue_acceptance(host, receipt, cycle, boot_id, power, directory):
  phrase = C.attendance_phrase(receipt["image_sha256"], boot_id, cycle, power)
  phrase_hash = confirm(host, phrase)
  issued = host.now()
  record = {"kind": "upstream-model-attended-s4-v1", "image_sha256": receipt["image_sha256"], "boot_id": boot_id,
            "cycle": cycle, "power": power, "phrase_sha256": phrase_hash, "issued": issued,
            "expires": issued + ACCEPTANCE_SECONDS, "accepted": True}
  save(host, directory / "acceptance.json", record)
  return record


def require_acceptance(host, receipt, cycle, boot_id, power, directory):
  path = directory / "acceptance.json"
  if path.is_symlink() or not path.is_file():
    raise ValueError("Attendance acceptance is missing")
  metadata = path.stat()
  if metadata.st_uid != host.owner or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise ValueError("Attendance acceptance has an unsafe owner or mode")
  record = json.loads(path.read_text())
  phrase_hash = C.sha256(C.attendance_phrase(receipt["image_sha256"], boot_id, cycle, power).encode())
  expected = {"kind": "upstream-model-attended-s4-v1", "image_sha256": receipt["image_sha256"], "boot_id": boot_id,
              "cycle": cycle, "power": power, "phrase_sha256": phrase_hash, "accepted": True}
  if any(record.get(key) != value for key, value in expected.items()):
    raise ValueError("Attendance acceptance differs from this image, boot, cycle and power source")
  if not isinstance(record.get("expires"), (int, float)) or host.now() > record["expires"]:
    raise ValueError("Attendance acceptance expired; start the cycle again")


# -- /run drop-in --------------------------------------------------------------------

def runtime_paths(host):
  return host.root / C.RUNTIME_DIR, host.root / C.DROPIN


def expected_units(host):
  script = "/" + str(C.RUNTIME_DIR) + "/prepare.py"
  return {
    "ExecStart": [["/usr/lib/systemd/systemd-sleep", "hibernate"]],
    "ExecStartPre": [["/usr/bin/python3", "-I", "-B", script, "pre"]],
    "ExecStopPost": [["/usr/bin/python3", "-I", "-B", script, "post"]],
  }


def parse_exec(text, name):
  """argv lists from `systemctl show -p Exec...` (one line per property)."""
  result = []
  for line in text.splitlines():
    if line.startswith(name + "="):
      for match in re.finditer(r"argv\[\]=(.*?) ;", line):
        result.append(match.group(1).split(" "))
  return result


def show_units(host):
  text = host.output(("systemctl", "show", "systemd-hibernate.service", "-p", "ExecStart", "-p", "ExecStartPre", "-p", "ExecStopPost"))
  return {name: parse_exec(text, name) for name in ("ExecStart", "ExecStartPre", "ExecStopPost")}


def install_dropin(host):
  directory, dropin = runtime_paths(host)
  if directory.exists() or dropin.exists() or dropin.is_symlink():
    raise ValueError("Runtime drop-in or helpers already exist; run cleanup first")
  try:
    directory.mkdir(parents=True, mode=0o755)
    prepare_data, helper_data = PREPARE.read_bytes(), WIFI_HELPER.read_bytes()
    for name, data in (("prepare.py", prepare_data), ("omarchy-t2-hibernate-wifi", helper_data)):
      STAGE.atomic_write(directory / name, data, 0o755)
    pins = {"prepare_sha256": C.sha256(prepare_data), "wifi_helper_sha256": C.sha256(helper_data)}
    STAGE.atomic_write(directory / "pins.json", (json.dumps(pins, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    for name, pin in (("prepare.py", pins["prepare_sha256"]), ("omarchy-t2-hibernate-wifi", pins["wifi_helper_sha256"])):
      path = directory / name
      metadata = path.stat()
      if path.is_symlink() or metadata.st_uid != host.owner or metadata.st_mode & 0o022 or C.sha256(path.read_bytes()) != pin:
        raise ValueError("Runtime helper failed its ownership or hash check: " + name)
    dropin.parent.mkdir(parents=True, exist_ok=True)
    STAGE.atomic_write(dropin, C.dropin_text(C.RUNTIME_DIR, pins["prepare_sha256"]).encode(), 0o644)
    host.output(("systemctl", "daemon-reload"))
    if show_units(host) != expected_units(host):
      raise ValueError("systemd-hibernate.service does not show the expected stock ExecStart and prepare steps")
  except BaseException:
    ignore_signals()
    remove_dropin(host)
    raise
  return pins


def remove_dropin(host):
  """Remove drop-in and helpers, reload, and verify the product routing is back. Returns error strings."""
  directory, dropin = runtime_paths(host)
  errors = []
  try:
    if dropin.exists() or dropin.is_symlink():
      dropin.unlink()
    if directory.exists():
      if (directory / "prepare-state.json").exists():
        # The state names what still has to be restored (Wi-Fi, Bluetooth, bolt); keep it and its helpers.
        errors.append("prepare state still pending in " + str(directory) + "; run 'prepare.py post' from there, then cleanup")
      else:
        shutil.rmtree(directory)
    host.output(("systemctl", "daemon-reload"))
    units = show_units(host)
    shown = " ".join(" ".join(argv) for argvs in units.values() for argv in argvs)
    if "omarchy-t2-upstream-model" in shown:
      errors.append("systemd-hibernate.service still shows upstream-model overrides")
    if dropin.exists():
      errors.append("runtime drop-in remains")
  except Exception as error:
    errors.append(str(error))
  return errors


# -- cycle ---------------------------------------------------------------------------

def terminal(host, receipt, reason):
  STAGE.mark_terminal(host.root, receipt["image_sha256"], reason)


class RefusedBeforeTransition(RuntimeError):
  """hibernate failed with no evidence that any transition began."""


@contextmanager
def terminating_signals():
  """SIGHUP, SIGTERM and SIGINT become SystemExit so the cleanup in s4_cycle always runs."""
  previous = {}

  def terminate(signum, _frame):
    raise SystemExit(128 + signum)

  for name in ("SIGHUP", "SIGTERM", "SIGINT"):
    try:
      previous[getattr(signal, name)] = signal.signal(getattr(signal, name), terminate)
    except ValueError:
      break  # not the main thread
  try:
    yield
  finally:
    for number, handler in previous.items():
      signal.signal(number, handler)


TRANSITION_KERNEL = re.compile(r"hibernation entry|Freezing|Syncing filesystems|swsusp|Image|PM: Preparing")
TRANSITION_SLEEP = re.compile(r"Performing sleep operation|Entering sleep state|hibernat", re.I)


def no_transition_evidence(host, target, mark, dmesg_before=""):
  """True only if every source agrees that no transition began; any hit or unreadable source means False.

  Sources: SWAPSPACE2 header, no HibernateLocation variable, the kernel log since the cursor (journal -k
  and dmesg beyond the pre-write baseline) free of freeze/swsusp/entry lines, and the full journal since
  the cursor free of systemd-sleep's own sleep lines (systemd[1] failure text for our own pre step is fine).
  """
  try:
    host.output(("journalctl", "--sync"))
    require_clean_header(host, target)
    if host.exists(HIBERNATE_LOCATION):
      return False
    kernel = host.output(("journalctl", "-k", "-b", "-o", "short-monotonic", "--no-pager", "--after-cursor=" + mark))
    dmesg = host.output(("dmesg",))
    _filtered, full = journal_slice(host, mark)
  except (ValueError, OSError):
    return False
  new_dmesg = dmesg[len(dmesg_before):] if dmesg.startswith(dmesg_before) else dmesg
  if TRANSITION_KERNEL.search(kernel) or TRANSITION_KERNEL.search(new_dmesg):
    return False
  return not any("systemd-sleep" in line and TRANSITION_SLEEP.search(line) for line in full.splitlines())


def archive_prior_attempt(host, directory):
  """Move the files of a refused attempt into prior-<time>/ (evidence is kept, never deleted)."""
  archive = directory / ("prior-" + str(int(host.now())))
  n = 0
  while archive.exists():
    n += 1
    archive = directory / ("prior-" + str(int(host.now())) + "-" + str(n))
  archive.mkdir(mode=0o700)
  for item in sorted(directory.iterdir()):
    if item.is_file():
      item.rename(archive / item.name)


@locked
def s4_cycle(host, cycle):
  receipt = load(host)
  boot_id = require_g1(host, receipt)
  require_s3(host, receipt, boot_id)
  require_sequence(host, receipt, cycle, boot_id)
  facts = preconditions(host, receipt, efi_clear=True)
  power = power_source(host)
  require_power(power, cycle)
  directory = phase_dir(host, receipt, "cycle-" + str(cycle))
  attempt_path = directory / "attempt.json"
  if attempt_path.exists():
    archive_prior_attempt(host, directory)
  identity = {"image_sha256": receipt["image_sha256"], "entry_id": receipt["entry_id"], "boot_id": boot_id, "cycle": cycle,
              "power": power["label"], "transition_vector": vector(receipt, cycle, boot_id, power["label"]),
              "swap_target": facts["swap_target"]}
  attempt = {**identity, "state": "preparing", "hibernate_attempted": False}
  save(host, attempt_path, attempt)
  consumed, armed, installed, in_flight, saved = False, False, False, False, {}
  try:
    capture(host, receipt, directory, "pre", facts["swap_target"])
    issue_acceptance(host, receipt, cycle, boot_id, power["label"], directory)
    attempt["state"] = "accepted"
    save(host, attempt_path, attempt)
    host.lock()
    install_dropin(host)
    installed = True
    armed = True  # set first: a partial arm must always be disarmed on failure
    STAGE.arm_s4(host.root, cycle, runner=host.stager_runner, sync=host.sync)
    attempt["state"] = "armed"
    save(host, attempt_path, attempt)
    # Final re-read immediately before the irreversible steps.
    require_acceptance(host, receipt, cycle, boot_id, power["label"], directory)
    again = power_source(host)
    if again["label"] != power["label"]:
      raise ValueError("Power source changed after attendance was accepted")
    require_power(again, cycle)
    if swap_target(host) != facts["swap_target"]:
      raise ValueError("Swap target changed")
    require_clean_header(host, facts["swap_target"])
    inhibitors(host)
    STAGE.verify_staged(host.root, receipt)
    one_shot = host.root / STAGE.ONESHOT
    if not one_shot.is_file() or STAGE.SINGLE.read_efi_string(one_shot) != receipt["entry_id"] or host.exists(STAGE.DEFAULT):
      raise ValueError("LoaderEntryOneShot is not exactly the upstream-model entry")
    if host.exists(HIBERNATE_LOCATION):
      raise ValueError("HibernateLocation EFI variable is already set")
    mark = cursor(host)
    dmesg_before = host.output(("dmesg",))
    # From here a signal must not abort the cycle: once the guard exists the hibernate job can continue in
    # pid 1 even if this client dies, so nothing may be unwound while a transition could be in flight.
    saved = ignore_signals()
    create_guard(host, receipt, cycle, {**identity, "created": host.now()})
    consumed = True
    attempt["state"] = "guard-consumed"
    save(host, attempt_path, attempt)
    attempt.update(state="transition-started", hibernate_attempted=True, real_s4_attempted=True, pre_write_monotonic=host.read("proc/uptime").split()[0])
    save(host, attempt_path, attempt)
    host.sync()
    print("omarchy-t2-upstream-model: starting attended S4 cycle " + str(cycle) + " boot=" + boot_id + " image=" + receipt["image_sha256"][:12], flush=True)
    in_flight = True
    result = host.run(("systemctl", "hibernate"))
    in_flight = False
    attempt["hibernate_returncode"] = result.returncode
    if result.returncode != 0:
      message = "systemctl hibernate returned " + str(result.returncode) + ": " + result.stderr.strip()[:200]
      if no_transition_evidence(host, facts["swap_target"], mark, dmesg_before):
        raise RefusedBeforeTransition(message)
      raise RuntimeError(message)
    attempt["state"] = "returned"
    save(host, attempt_path, attempt)
    post_return(host, receipt, cycle, attempt, directory, mark, boot_id)
  except BaseException as error:
    ignore_signals()  # first statement: cleanup itself must not be interrupted
    attempt["error"] = str(error)
    cleanup_errors = []
    if in_flight:
      # The power call did not return: a transition may be running. Unwinding now (removing the drop-in,
      # daemon-reload, disarming) could break a live hibernate or its one-shot. Leave everything in place.
      attempt.update(state="failed-terminal", unwound=False, stale_image_warning=STALE_WARNING)
      terminal(host, receipt, "S4 cycle " + str(cycle) + " aborted during the power call: " + str(error))
      save(host, attempt_path, attempt)
      print(STALE_WARNING, file=sys.stderr)
      print(CHECKLIST, file=sys.stderr)
      raise
    if installed:
      cleanup_errors += remove_dropin(host)
    if armed and host.exists(STAGE.ONESHOT):
      try:
        STAGE.disarm(host.root, runner=host.stager_runner)
      except Exception as disarm_error:
        cleanup_errors.append("disarm: " + str(disarm_error))
    if cleanup_errors:
      attempt["cleanup_errors"] = cleanup_errors
    if consumed and isinstance(error, RefusedBeforeTransition):
      # No evidence of a transition: keep the guard as evidence under a per-attempt name and allow a retry.
      guard = host.root / C.GUARDS / receipt["image_sha256"] / ("cycle-" + str(cycle))
      archived = guard.with_name(guard.name + ".refused-" + str(int(host.now())))
      n = 0
      while archived.exists():
        n += 1
        archived = guard.with_name(guard.name + ".refused-" + str(int(host.now())) + "-" + str(n))
      guard.rename(archived)
      attempt["guard_archived_as"] = archived.name
      attempt.update(state="refused-before-transition", real_s4_attempted=False)
    elif consumed:
      attempt["state"] = "failed-terminal"
      terminal(host, receipt, "S4 cycle " + str(cycle) + ": " + str(error))
    else:
      attempt["state"] = "refused-before-guard"
    save(host, attempt_path, attempt)
    print(CHECKLIST, file=sys.stderr)
    raise
  finally:
    restore_signals(saved)
  return attempt


def post_return(host, receipt, cycle, attempt, directory, mark, boot_id):
  """G4: same process, after the image restored and this runner resumed."""
  problems = []
  if STAGE.current_boot_id(host.root) != boot_id:
    problems.append("Boot ID changed across S4")
  cleanup_errors = remove_dropin(host)
  problems += cleanup_errors
  if host.exists(STAGE.ONESHOT) or host.exists(STAGE.DEFAULT):
    problems.append("An EFI one-shot or default remains after the resume")
  if STAGE.selected_entry(host.root) != receipt["entry_id"]:
    problems.append("Resume boot did not select the upstream-model entry")
  header = None
  try:
    target = swap_target(host)
    if target != attempt["swap_target"]:
      problems.append("Swap target differs after the resume")
    header = require_clean_header(host, target)
  except ValueError as error:
    target = attempt["swap_target"]
    problems.append("Swap target or header after the resume: " + str(error))
  record = capture(host, receipt, directory, "post", target, after=mark, extra={"swap_header_after": header}, settle=SETTLE_SECONDS)
  problems += record["problems"]
  problems += [line for line in record["journal"] if BAD_PM.search(line)][:5]
  joined = "\n".join(record["journal"])
  if "hibernation entry" not in joined:
    problems.append("Journal lacks the hibernation entry line")
  attempt["post_problems"] = problems
  if problems:
    raise RuntimeError("Post-return checks failed: " + "; ".join(problems))
  STAGE.mark_booted(host.root)
  phrase_hash = confirm(host, C.confirmation_phrase("s4", receipt["image_sha256"], boot_id))
  attempt.update(state="returned-and-cleaned", physical_confirmation_sha256=phrase_hash, hardware_qualified=False)
  save(host, directory / "attempt.json", attempt)


def reconcile_attempts(host, receipt):
  """Settle attempts an interrupted runner left behind: no guard means retryable, a guard means terminal."""
  settled = {}
  base = host.root / C.ATTEMPTS / receipt["image_sha256"]
  for directory in sorted(base.glob("cycle-*")) if base.is_dir() else []:
    path = directory / "attempt.json"
    if not path.is_file():
      continue
    attempt = json.loads(path.read_text())
    state = attempt.get("state")
    if state in ("preparing", "accepted", "armed"):
      attempt["state"] = "refused-before-guard"
    elif state in ("guard-consumed", "transition-started", "returned"):
      attempt["state"] = "failed-terminal"
      terminal(host, receipt, directory.name + " interrupted in state " + state)
    else:
      continue
    save(host, path, attempt)
    settled[directory.name] = attempt["state"]
  return settled


@locked
def cleanup(host):
  """Standalone G4 cleanup: drop-in and helpers gone, owned one-shot disarmed; never touches guards."""
  errors = remove_dropin(host)
  receipt = load(host)
  if host.exists(STAGE.ONESHOT):
    try:
      STAGE.disarm(host.root, runner=host.stager_runner)
    except ValueError as error:
      errors.append("disarm: " + str(error))
  settled = reconcile_attempts(host, receipt)
  if errors:
    raise ValueError("Cleanup incomplete: " + "; ".join(errors))
  return {"state": "cleaned", "image_sha256": receipt["image_sha256"], "settled_attempts": settled}


@locked
def recover(host):
  """Repair after a runner died on the test boot: drop-in gone, one-shot disarmed, attempts settled.

  Runs only on the test-image boot. Leftover guards and evidence are never deleted; attempts with a guard
  become terminal, those without become retryable, and the receipt moves to "booted" (or "disarmed") so
  verify-boot and the later steps can continue. From the stock boot use cleanup instead.
  """
  receipt = load(host)
  if STAGE.selected_entry(host.root) != receipt["entry_id"]:
    raise ValueError("recover runs on the upstream-model test boot; from the stock boot use cleanup")
  errors = remove_dropin(host)
  if host.exists(STAGE.ONESHOT):
    try:
      STAGE.disarm(host.root, runner=host.stager_runner)
    except ValueError as error:
      errors.append("disarm: " + str(error))
  settled = reconcile_attempts(host, receipt)
  current = STAGE.load_receipt(host.root)
  if current.get("state") in ("armed", "s4-armed", "arming") and not host.exists(STAGE.ONESHOT):
    try:
      STAGE.adopt_boot(host.root)
    except ValueError as error:
      errors.append("adopt: " + str(error))
  if errors:
    raise ValueError("Recovery incomplete: " + "; ".join(errors))
  final = STAGE.load_receipt(host.root)
  return {"state": "recovered", "receipt_state": final["state"], "test_boot_id": final.get("test_boot_id"),
          "terminal": STAGE.is_terminal(host.root, receipt["image_sha256"]), "settled_attempts": settled,
          "next": "run verify-boot again on this boot" if final["state"] == "booted" else "see receipt state"}


def pre_reactivate_check(host):
  """Refuse while any test leftover exists; run before the product's reactivate (reads state only)."""
  directory, dropin = runtime_paths(host)
  problems = []
  if dropin.exists() or dropin.is_symlink():
    problems.append("the /run drop-in " + str(Path("/") / C.DROPIN) + " exists")
  if directory.exists():
    problems.append(str(Path("/") / C.RUNTIME_DIR) + " exists")
  if host.exists(STAGE.ONESHOT) or host.exists(STAGE.DEFAULT):
    problems.append("an EFI one-shot or default is present")
  if host.exists(C.RECEIPT):
    problems.append("the upstream-model receipt still exists; run the stager rollback and clear first")
  if host.exists(C.ATTEMPTS):
    for directory_ in sorted((host.root / C.ATTEMPTS).glob("*/cycle-*/attempt.json")):
      if json.loads(directory_.read_text()).get("state") in ("preparing", "accepted", "armed", "guard-consumed", "transition-started", "returned"):
        problems.append("an unsettled attempt remains: " + str(directory_.parent.name) + "; run cleanup")
  if problems:
    raise ValueError("Do not reactivate the product yet: " + "; ".join(problems))
  return {"state": "clear-to-reactivate-check-assess-first"}


def main():
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("phase", choices=("preflight", "verify-boot", "s3", "s4", "cleanup", "recover", "pre-reactivate-check", "recovery"))
  parser.add_argument("--cycle", type=int)
  args = parser.parse_args()
  if args.phase == "recovery":
    print(CHECKLIST)
    return
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  host = Host()
  try:
    with terminating_signals():
      if args.phase == "preflight":
        receipt = load(host)
        result = preconditions(host, receipt, efi_clear=receipt.get("state") not in ("armed", "s4-armed"))
      elif args.phase == "verify-boot":
        result = verify_boot(host)
      elif args.phase == "s3":
        result = s3(host)
      elif args.phase == "s4":
        if args.cycle is None:
          parser.error("s4 requires --cycle")
        result = s4_cycle(host, args.cycle)
      elif args.phase == "pre-reactivate-check":
        result = pre_reactivate_check(host)
      elif args.phase == "recover":
        result = recover(host)
      else:
        result = cleanup(host)
  except (OSError, RuntimeError, ValueError) as error:
    print(CHECKLIST, file=sys.stderr)
    raise SystemExit("Upstream-model runner refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
  main()
