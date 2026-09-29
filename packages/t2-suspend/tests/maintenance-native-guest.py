"""Dedicated networkless guest: REAL native update guard and maintenance entry, real pacman.

Runs as guest root (isolated Python, fixed path) and exercises the actual
installed-runtime entry points from the fixed deployed path:
  * update_guard.py (the reviewed pacman PreTransaction hook, exactly as
    installed at /etc/pacman.d/hooks) through real `pacman -U` transactions,
  * boot_policy_native.py `maintenance` re-entry via its real CLI (real
    systemd-inhibit re-exec, real logind, real systemctl show of the reviewed
    drop-in) reporting already_inactive.
The runtime is deployed with the real runtime_deployment.deploy_snapshot into
/var/lib/omarchy/t2-hibernate-product/runtime from an independently generated
reviewed inventory (0700/0600, root); the whole tree is authenticated by the
native code itself.

REAL: kernel/sysfs /sys/power/resume + resume_offset, virtio block device read
through the actual image_state page check, systemd/logind/inhibitors/busctl,
systemctl show with the reviewed drop-in, pacman transactions and db.lck, flock
on the physical lock, the deployed hook bytes, deploy_snapshot, transition core
(activation and maintenance publication) rooted at the guest '/'.

SIMULATED (each is a seam, not evidence of the host):
  S1 /sys/firmware is a tmpfs holding an empty efivars directory (no EFI in a
     direct-kernel QEMU boot); only the fixture's LoaderEntries file lives there.
  S2 /dev/mapper/root is a symlink to a mknod'ed node with the virtio scratch
     disk's device number; dm-crypt and Btrfs do not exist. The resume page is
     read from the raw scratch disk at resume_offset*4096 by the real reader.
  S3 /usr/bin/btrfs and /usr/bin/findmnt are guest stubs printing the recorded
     swapfile offset and a qualified encrypted-Btrfs source (real ones are absent).
  S4 The production UKI and the limine stock hash are synthetic byte strings; the
     "limine-mkinitcpio" step is a test PostTransaction hook that rewrites the fake
     UKI and its BLAKE2b in limine.conf (or, deliberately, only the UKI). A second
     PostTransaction hook stands in for limine-snapper-sync: after EVERY app or
     kernel transaction it adds a nested //Snapshots sub-entry and prunes old ones
     (alternating block order), so snapshot churn accompanies every transaction.
  S5 FIRST publication of package-maintenance.pending cannot use the native CLI:
     boot_policy_native._precheck needs the real qualified source/restore UKI pair
     (product.check, derive_artifacts). The marker is instead published by the real
     engine core _transition(ROOT, "maintenance", native capability, real
     _maintenance_gate) from the deployed runtime with a fixture precheck,
     _resume patched to the recorded tuple, and an owner-held real logind block
     instead of the systemd-inhibit re-exec. Re-entry/verification IS the real CLI.
  S6 Activation before it is a fixture activation through the same engine core.
  S7 The reviewed runtime inventory is authored by this guest (external review
     approval is not modeled).
  S8 The qualified generation the baseline pins is synthetic: config.json,
     qualification.json, source/restore candidate files, seven fixture module
     files and the Formosa firmware set are guest bytes, and /usr/bin/modinfo is
     a guest stub answering only the driver inventory's exact queries (the guest
     has no kmod). The baseline itself is captured by the REAL provider
     (boot_policy_native._baseline: real root_driver_inventory/root_control_inventory
     against guest '/') and `assess` runs through the REAL CLI.
  S9 `reactivate` is exercised through the real engine core (_reactivate) with the REAL assess core
     (N._assess_core), REAL retained gate, REAL locks/limine writes/guard/pacman, and an owner-held real
     logind block for the guard; only product-side seams are simulated: `inspect` returns the guest's
     config (with the real receipt digest; derive_artifacts needs the real qualified pair) and the W6
     postchecks reuse the fixture's `_verify_deployment` plus the real no-image and generation checks.
     The interrupted-run recovery, the kernel-update refusal and the class (c) refusal go through the
     REAL CLI (real inhibitor re-exec), because none of them reach derive_artifacts.
Kernel update is a test package plus the S4 hook; no real kernel/initramfs,
DKMS, EFI, PM or power operation exists. Not a host, hibernation or hardware claim.
"""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from unittest.mock import patch


SRC = Path("/opt/omarchy-src/packages/t2-suspend")
SOURCE_ROOT = Path("/opt/omarchy-src")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
RUNTIME = STATE / "runtime/packages/t2-suspend/hibernate"
NATIVE = RUNTIME / "boot_policy_native.py"
GUARD = RUNTIME / "update_guard.py"
INHIBITOR = RUNTIME / "maintenance_inhibitor.py"
SCRIPT = Path("/maintenance-native-test.py")
WORK = Path("/run/maintenance-native")
UKI = Path("/boot/EFI/Linux/omarchy_linux-t2.efi")
LIMINE = Path("/boot/limine.conf")
OFFSET = 16
PAGE = 4096
MACHINE = "0123456789abcdef0123456789abcdef"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
HOOKS = Path("/etc/pacman.d/hooks")
KERNEL_FILE = Path("/usr/lib/modules/t2fixture/version")
RELEASE = "t2fixture"
# Mirror the host: the qualified artifact tree lives in the operator's account (uid 1000, 0700/0600) under a
# 0755 user-owned ancestry, while the runtime and its state are root's.
OPERATOR_UID = 1000
ARTIFACTS = Path("/home/operator/.local/state/qualified-artifacts")
MODULES = ("brcmfmac", "brcmfmac-wcc", "brcmfmac-cyw", "brcmfmac-bca", "hci_bcm4377")
FORMOSA = "brcmfmac4377b3-pcie.apple,formosa"
MODINFO = """#!/usr/bin/python3
import sys
arguments = sys.argv[1:]
if arguments[:1] == ["-b"] and arguments[2:3] == ["-k"] and arguments[4:5] == ["-n"]:
  print("//lib/modules/" + arguments[3] + "/updates/dkms/" + arguments[5] + ".ko.zst")
elif arguments[:2] == ["-F", "srcversion"]: print("A1B2C3D4E5F60718293A4B5C")
elif arguments[:2] == ["-F", "vermagic"]: print("t2fixture SMP preempt mod_unload")
else: sys.exit(2)
"""


def require(value, message):
  if not value: raise RuntimeError(message)


def step(name, detail=""):
  print("MAINTENANCE_NATIVE_STEP PASS " + name + (" :: " + detail if detail else ""), flush=True)


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def blake2(raw): return hashlib.blake2b(raw).hexdigest()


def atomic(path, raw):
  mode = stat.S_IMODE(path.stat().st_mode)
  temporary = path.with_name(path.name + ".tmp")
  fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  os.replace(temporary, path)


def mkuki():
  """Test PostTransaction hook standing in for limine-mkinitcpio (S4)."""
  version = KERNEL_FILE.read_bytes().strip()
  image = b"fixture-production-uki kernel=" + version + b"\n"
  atomic(UKI, image)
  if not version.endswith(b"-nolimine"):
    text = LIMINE.read_text()
    updated, count = re.subn(r"(omarchy_linux-t2\.efi#)[0-9a-f]{128}", lambda match: match.group(1) + blake2(image), text)
    require(count == 1, "mkuki: production hash line missing")
    atomic(LIMINE, updated.encode())
  print("MKUKI kernel=" + version.decode() + " uki_blake2b=" + blake2(image)[:16] + " limine_updated=" + str(not version.endswith(b"-nolimine")), flush=True)
  return 0


SNAPSHOT_RE = re.compile(r"\n     //Snapshots\n.*?(?=\n# BEGIN omarchy T2 hibernation pair)", re.S)


def strip_snapshots(raw): return SNAPSHOT_RE.sub("", raw.decode()).encode()


def snapsync():
  """Test PostTransaction hook standing in for limine-snapper-sync: add one snapshot sub-entry, keep the last two."""
  text = LIMINE.read_text()
  numbers = [int(value) for value in re.findall(r"^     ///(\d+) ", text, re.M)]
  numbers = (numbers + [max(numbers, default=0) + 1])[-2:]
  if numbers[-1] % 2: numbers.reverse()  # the block order changes between runs
  lines = ["", "     //Snapshots", "     ### Auto-generated by limine-snapper-sync", "     comment: %d snapshots" % len(numbers)]
  for number in numbers:
    lines += ["     ///%d \u2502 2026-09-%02d 17:35:47" % (number, number), "     comment: 4.0.2-1", "     ////linux-t2",
              "     comment: kernel-id=linux-t2", "     protocol: efi",
              "     path: boot():/" + MACHINE + "/limine_history/omarchy_linux-t2.efi_sha256_%s#%s" % (("%02x" % number) * 32, ("%02x" % number) * 64),
              "     cmdline: root=/dev/mapper/root rootflags=subvol=/@/.snapshots/%d/snapshot rw" % number]
  base = SNAPSHOT_RE.sub("", text)
  marker = "# BEGIN omarchy T2 hibernation pair"
  require(base.count(marker) == 1, "snapsync: pair marker missing")
  index = base.index(marker)
  atomic(LIMINE, (base[:index].rstrip("\n") + "\n" + "\n".join(lines) + "\n" + base[index:]).encode())
  print("SNAPSYNC snapshots=" + json.dumps(numbers), flush=True)
  return 0


def package(name, version, files):
  path = WORK / (name + "-" + version + "-x86_64.pkg.tar.gz")
  size = sum(len(raw) for raw in files.values())
  metadata = ("pkgname = " + name + "\npkgbase = " + name + "\npkgver = " + version + "\npkgdesc = Disposable fixture only\nbuilddate = 1700000000\npackager = Disposable fixture\nsize = " +
    str(size) + "\narch = x86_64\nlicense = MIT\n").encode()
  with tarfile.open(path, "w:gz") as archive:
    for entry_name, raw in ((".PKGINFO", metadata), *files.items()):
      entry = tarfile.TarInfo(entry_name)
      entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(raw), 0o644, 0, 0, 1700000000
      archive.addfile(entry, io.BytesIO(raw))
  return path


def app(version): return package("t2fixture-app", version, {"opt/t2fixture/app": ("app " + version + "\n").encode()})
def kernel(version, tag=""): return package("t2fixture-kernel", version, {"usr/lib/modules/t2fixture/version": (version + tag + "\n").encode()})


def pacman(*arguments):
  process = subprocess.run(["/usr/bin/pacman", "--noconfirm", *arguments], env=ENV, capture_output=True, text=True, timeout=90)
  output = process.stdout + process.stderr
  for line in output.splitlines(): print("PACMAN| " + line, flush=True)
  return process.returncode, output


def installed(name):
  process = subprocess.run(["/usr/bin/pacman", "-Q", name], env=ENV, capture_output=True, text=True, timeout=30)
  return process.stdout.split()[1] if process.returncode == 0 else None


def snapshot():
  state = {"app": installed("t2fixture-app"), "kernel": installed("t2fixture-kernel"),
    "payload": Path("/opt/t2fixture/app").read_bytes() if Path("/opt/t2fixture/app").exists() else None,
    "uki": UKI.read_bytes(), "limine": LIMINE.read_bytes()}
  return state


def blocked(package_path, needle):
  """Real transaction MUST be aborted by the PreTransaction hook with no package change."""
  before = snapshot()
  code, output = pacman("-U", str(package_path))
  after = snapshot()
  require(code != 0, "Guard did not abort the transaction: " + package_path.name)
  require(needle in output, "Expected refusal text absent: " + needle)
  require(before == after, "Blocked transaction changed packages or boot bytes")
  require(not Path("/var/lib/pacman/db.lck").exists(), "db.lck remained after aborted pacman")
  return output


def admitted(package_path):
  code, output = pacman("-U", str(package_path))
  require(code == 0, "Guard/pacman refused an admissible transaction: " + package_path.name)
  require("Checking inactive T2 source boot policy before package changes" in output, "PreTransaction guard hook did not run")
  require(not Path("/var/lib/pacman/db.lck").exists(), "db.lck remained after pacman")
  return output


def busy(path):
  fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Physical exclusion was not held")
  finally: os.close(fd)


def write_file(path, raw, mode):
  path.parent.mkdir(parents=True, exist_ok=True)
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  os.chmod(path, mode)


def sysfs(name, value):
  Path("/sys/power/" + name).write_text(str(value))


def run_hook():
  """The exact command the installed pacman hook executes."""
  process = subprocess.run(["/usr/bin/python3", "-I", "-B", str(GUARD)], env=ENV, capture_output=True, text=True, timeout=60)
  return process.returncode, (process.stdout + process.stderr).strip()


def native_cli():
  process = subprocess.run(["/usr/bin/python3", "-I", "-B", str(NATIVE), "maintenance"], env=ENV, capture_output=True, text=True, timeout=90)
  return process.returncode, process.stdout.strip(), process.stderr.strip()


def reactivate_cli():
  """The real CLI (real systemd-inhibit re-exec, real logind, real locks): (returncode, stdout, stderr)."""
  process = subprocess.run(["/usr/bin/python3", "-I", "-B", str(NATIVE), "reactivate"], env=ENV, capture_output=True, text=True, timeout=120)
  return process.returncode, process.stdout.strip(), process.stderr.strip()


def assess_cli():
  """The real read-only CLI; parses the canonical JSON report."""
  process = subprocess.run(["/usr/bin/python3", "-I", "-B", str(NATIVE), "assess"], env=ENV, capture_output=True, text=True, timeout=90)
  require(process.returncode == 0, "Native assess failed: " + process.stdout + process.stderr)
  return json.loads(process.stdout.splitlines()[-1])


def evidence_tree():
  """Every byte, mode, size and timestamp that assess must leave untouched."""
  state = {}
  for base in (STATE, Path("/boot"), Path("/var/lib/omarchy/t2-hibernate-trial"), Path("/var/lib/pacman/local")):
    for path in [base, *sorted(base.rglob("*"))]:
      info = path.lstat()
      raw = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
      state[str(path)] = (info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, None if raw is None else hashlib.sha256(raw).hexdigest())
  return state


def assessed(expected, *, changed=None, limine_exact=None):
  """Run assess through the real CLI; it must write nothing and leave no lock."""
  before = evidence_tree()
  report = assess_cli()
  require(evidence_tree() == before, "assess changed evidence bytes, modes or timestamps")
  require(not Path("/var/lib/pacman/db.lck").exists(), "assess left db.lck")
  held = os.open("/var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock", os.O_RDONLY | os.O_CLOEXEC)
  try: fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # assess left no flock behind
  finally: os.close(held)
  require(report["class"] == expected and report["read_only"] is True, "Assessment class differs: " + json.dumps(report, sort_keys=True))
  if changed is not None: require(report["changed_items"] == changed, "Changed items differ: " + json.dumps(report, sort_keys=True))
  if expected != "unknown":
    require(report["limine"]["stock_projection_equal"] is True, "Snapshot churn must not change the stock projection")
    if limine_exact is not None: require(report["limine"]["exact_equal"] is limine_exact, "Limine exact-equality differs")
  return report


def setup_generation():
  """S8: a synthetic qualified generation for the baseline to pin."""
  write_file(Path("/usr/bin/modinfo"), MODINFO.encode(), 0o755)
  if not os.path.lexists("/lib"): os.symlink("usr/lib", "/lib")
  require(os.readlink("/lib") == "usr/lib", "Guest /lib must alias usr/lib for the driver inventory")
  for name in MODULES: write_file(Path("/usr/lib/modules/" + RELEASE + "/updates/dkms/" + name + ".ko.zst"), (name + " module bytes\n").encode(), 0o644)
  for suffix in (".bin", "-SPPR-m.txt", "-SPPR-u.txt", ".clm_blob", ".txcap_blob"):
    write_file(Path("/usr/lib/firmware/brcm/" + FORMOSA + suffix), ("firmware " + suffix + "\n").encode(), 0o644)
  for role in ("source", "restore"):
    directory = ARTIFACTS / role
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    for directory_parent in (ARTIFACTS, directory): directory_parent.chmod(0o700)
    write_file(directory / "provenance.json", json.dumps({"kernel_release": RELEASE, "modules": {"t2bce_core": {"sha256": role}}}).encode(), 0o600)
    write_file(directory / "mba-t2-hibernation-candidate.efi", (role + " candidate uki\n").encode(), 0o600)
    write_file(directory / "mba-t2-hibernation-candidate.initrd", (role + " candidate initrd\n").encode(), 0o600)
  for path in (Path("/home/operator"), Path("/home/operator/.local"), Path("/home/operator/.local/state"), ARTIFACTS):
    path.chmod(0o755 if path != ARTIFACTS else 0o700)
    os.chown(path, OPERATOR_UID, OPERATOR_UID)
  for role in ("source", "restore"):
    for path in (ARTIFACTS / role, *(ARTIFACTS / role).iterdir()): os.chown(path, OPERATOR_UID, OPERATOR_UID)
  pins = {role + "_sha256": hashlib.sha256((role + " candidate uki\n").encode()).hexdigest() for role in ("source", "restore")}
  require(all(os.lstat(path).st_uid == OPERATOR_UID for path in (ARTIFACTS, ARTIFACTS / "source" / "provenance.json")), "Guest artifacts must be operator-owned")
  write_file(STATE / "config.json", json.dumps({"source_directory": str(ARTIFACTS / "source"), "restore_directory": str(ARTIFACTS / "restore"),
    "production_uki": str(UKI), "audited_details_sha256": "a" * 64, "staged_receipt_sha256": "b" * 64,
    "manifest": {"protocol": "guest-fixture", "runtime_sha256": "c" * 64, **pins}}).encode(), 0o600)
  write_file(STATE / "qualification.json", b'{"approved":true}', 0o600)


def setup_topology():
  """S1, S2 and the real disk/sysfs resume topology."""
  subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/sys/firmware"], check=True, timeout=20)
  for directory in ("/sys/firmware/efi", "/sys/firmware/efi/efivars"): os.mkdir(directory, 0o755)
  device = Path("/sys/class/block/vda/dev").read_text().strip()
  major, minor = (int(part) for part in device.split(":"))
  Path("/dev/mapper").mkdir(mode=0o755)
  os.mknod("/dev/dm-0", stat.S_IFBLK | 0o600, os.makedev(major, minor))
  os.symlink("../dm-0", "/dev/mapper/root")
  write_header(b"SWAPSPACE2")
  sysfs("resume_offset", OFFSET)
  sysfs("resume", device)  # kernel checks the disk once; a normal swap header is not an image
  require(Path("/sys/power/resume").read_text().strip() == device and Path("/sys/power/resume_offset").read_text().strip() == str(OFFSET), "Kernel resume topology not accepted")
  return {"device": "/dev/mapper/root", "devnum": device, "offset": OFFSET}


def write_header(signature):
  page = bytearray(PAGE)
  page[1024:1028] = b"\x01\0\0\0"
  page[-10:] = signature.ljust(10, b"\0")
  fd = os.open("/dev/dm-0", os.O_WRONLY | os.O_SYNC)
  try: os.pwrite(fd, bytes(page), OFFSET * PAGE)
  finally: os.close(fd)


def copy_fixture(fixture):
  """Install the fixture's evidence bytes at guest '/' (never its fake runtime)."""
  skip = ("var/lib/omarchy/t2-hibernate-product/runtime", "etc/pacman.d/hooks")
  root = fixture.root
  for path in sorted(root.rglob("*")):
    relative = path.relative_to(root).as_posix()
    if any(relative == item or relative.startswith(item + "/") for item in skip): continue
    target = Path("/") / relative
    if relative.startswith("sys/"):
      if path.is_file(): write_file(target, path.read_bytes(), 0o600)  # S1: onto the tmpfs efivars
      continue
    if path.is_dir():
      if not target.exists(): target.mkdir(mode=0o700 if relative.startswith("var/lib/omarchy") else 0o755)
      if relative.startswith("var/lib/omarchy"): target.chmod(0o700)
      else: target.chmod(0o755) if relative in ("boot", "boot/EFI", "boot/EFI/Linux", "etc/omarchy", "var/lib/pacman") else None
    else:
      write_file(target, path.read_bytes(), stat.S_IMODE(path.lstat().st_mode))
  # the fixture's own stub runtime must not have been carried over
  require(not (STATE / "runtime").exists(), "Fixture runtime leaked into guest root")


def deploy_real_runtime(D):
  """Independent reviewed inventory + real deploy_snapshot (S7)."""
  inventory = D.inventory(SOURCE_ROOT)
  commit = Path("/etc/guest-sim/reviewed-commit").read_text().strip()
  review = {"protocol": D.SCHEMA, "approved": True, "reviewed_commit": commit, "files": inventory}
  write_file(STATE / "runtime-deployment-review.json", json.dumps(review).encode(), 0o600)
  completion = D.deploy_snapshot(SOURCE_ROOT, root=Path("/"))
  hook = (STATE / "runtime" / D.UPDATE_GUARD_HOOK).read_bytes()
  write_file(HOOKS / "00-omarchy-t2-hibernate-guard.hook", hook, 0o644)
  return len(inventory), hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(), completion


def owner():
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM only")
  WORK.mkdir(mode=0o700)
  HOOKS.mkdir(parents=True, mode=0o755)
  for name, when, target, command in (
      ("90-fixture-limine-mkinitcpio.hook", "PostTransaction", "t2fixture-kernel", "mkuki"),
      ("91-fixture-limine-snapper-sync.hook", "PostTransaction", "t2fixture-kernel\nTarget = t2fixture-app", "snapsync")):
    raw = ("[Trigger]\nOperation = Install\nOperation = Upgrade\nType = Package\nTarget = " + target + "\n[Action]\nWhen = " + when +
      "\nExec = /usr/bin/python3 -I -B " + str(SCRIPT) + " " + command + "\n").encode()
    write_file(HOOKS / name, raw, 0o644)
  resume = setup_topology()
  step("topology", "resume=" + json.dumps(resume, sort_keys=True))
  tests = SRC / "tests"
  F = load("transition_fixture", tests / "test-hibernate-boot-policy-transition.py")
  D = load("guest_deployment", SRC / "hibernate/runtime_deployment.py")
  original_temporary = tempfile.TemporaryDirectory
  fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
  with patch.object(tempfile, "TemporaryDirectory", side_effect=lambda: original_temporary(prefix="maintenance-native-", dir="/run")):
    fixture.setUp()
  copy_fixture(fixture)
  setup_generation()
  count, digest, completion = deploy_real_runtime(D)
  step("runtime-deploy", "files=" + str(count) + " inventory_sha256=" + digest + " reviewed_commit=" + completion["reviewed_commit"])
  N = load("native_installed", NATIVE)
  engine = N._installed()  # authenticates the ENTIRE installed tree (real code)
  I = load("owner_inhibitor", INHIBITOR)
  N.WHO, N.WHY = I.WHO, I.WHY

  def release(handle):
    handle.close()
    deadline = time.monotonic() + 3
    while N._bus("call", N.LOGIN, "ListInhibitors") != ["a(ssssuu)", "0"]:
      require(time.monotonic() < deadline, "Owner inhibitor remained after safe close")
      time.sleep(.02)
  require(N._bus("call", N.LOGIN, "ListInhibitors") == ["a(ssssuu)", "0"], "Guest must start with no inhibitors")
  block = I.acquire(N)
  T = engine

  def precheck(root, action, phase):
    require((root / T.DB_LOCK).is_file(), "db.lck missing during transition")
    busy(root / T.PHYSICAL_LOCK)
    source_default = (action == "activation" and phase == "after") or (action == "deactivation" and phase == "before")
    F.F.PRODUCT.TRIAL._verify_deployment(root, fixture.f.config, fixture.f.report, source_default=source_default)

  # --- control: active source default blocks a real pacman transaction ---
  engine._transition(Path("/"), "activation", precheck=precheck, guard=block.check)
  require((STATE / "boot-policy.json").exists() and not (STATE / "source-default-activation.pending").exists(), "Fixture activation incomplete")
  step("active-fixture", "S6 activation through engine core at '/'; boot-policy.json present")
  before = snapshot()
  code, output = run_hook()
  require(code == 1 and "remains active/incomplete" in output, "Hook did not refuse ACTIVE policy: " + output)
  code, output = pacman("-U", str(app("1.0-1")))
  require(code != 0 and installed("t2fixture-app") is None and snapshot() == before, "Active policy did not block a real transaction")
  step("control-active-blocks", "hook exit 1 and pacman transaction aborted, package absent")

  # --- publish maintenance marker (S5 seam) ---
  capture = {"resume": dict(resume)}
  N._resume = lambda engine_arg: dict(resume)
  gate = lambda root, phase: N._maintenance_gate(engine, root, phase, capture)
  result = engine._transition(N.ROOT, "maintenance", precheck=precheck, guard=block.check, maintenance_gate=gate,
                              native=engine._NATIVE_MAINTENANCE, maintenance_resume=lambda: capture["resume"],
                              maintenance_baseline=lambda: N._baseline(engine, N.ROOT))
  block.check()
  marker = (STATE / "package-maintenance.pending")
  require(marker.exists() and not (STATE / "source-default-deactivation.pending").exists() and not (STATE / "boot-policy.json").exists(), "Maintenance publication state wrong")
  release(block)
  step("publish-marker", "S5 seam; real _maintenance_gate (drop-in/ExecStart/vetoes/fallback/no-image) passed; intent_sha256=" + result["maintenance_intent_sha256"])
  del block

  baseline_file = STATE / "boot-policy-transitions" / result["transition_id"] / "generation-baseline.json"
  require(baseline_file.is_file() and stat.S_IMODE(baseline_file.stat().st_mode) == 0o600, "Baseline sidecar was not archived")
  document = json.loads(baseline_file.read_bytes())
  require(document["protocol"] == "omarchy-t2-generation-baseline-v1" and document["transition_id"] == result["transition_id"] and
          set(document["items"]) == {*engine.BASELINE_ITEMS, "limine"}, "Baseline sidecar shape differs")
  require(all("unavailable" not in item for item in document["items"].values()), "Real baseline provider left an item unavailable: " + json.dumps(document["items"], sort_keys=True)[:600])
  step("baseline-archived", "generation-baseline.json sha256=" + hashlib.sha256(baseline_file.read_bytes()).hexdigest() + " items=" + ",".join(sorted(document["items"])))
  report = assessed("unchanged", changed=[], limine_exact=True)
  require(all(item == {"state": "equal"} for item in report["items"].values()), "Fresh baseline items differ")
  step("assess-0-published", "class=unchanged, every item equal, read-only (evidence bytes/mtimes and locks unchanged)")

  # --- reactivation (S9): assess -> failed run -> real-CLI rollback -> reactivate -> ACTIVE -> guard blocks -> churn -> back to maintenance ---
  sleep_entry = N._load_reviewed("guest_reviewed_sleep_entry", N.SLEEP_ENTRY)
  receipt_digest = hashlib.sha256(Path("/var/lib/omarchy-t2-hibernation-pair/receipt.json").read_bytes()).hexdigest()
  qualified = json.loads((STATE / "config.json").read_bytes())

  def veto_holds():
    with_pending = (STATE / "source-default-activation.pending")
    require(with_pending.exists(), "Reactivation pending missing while a veto is expected")
    try: sleep_entry.reject_pending(Path("/"))
    except ValueError: pass
    else: raise RuntimeError("Reviewed sleep entry admitted sleep with a reactivation pending")
    code, text = run_hook()
    require(code == 1 and ("prevents maintenance evidence" in text or "remains active/incomplete" in text), "Update guard admitted an interrupted reactivation: " + text)
    blocked(app("0.9-1"), "T2 hibernation update guard")

  def reactivate(handle, failure=None):
    capture = {}
    def postchecks(root, baseline):
      if failure: raise ValueError(failure)
      F.F.PRODUCT.TRIAL._verify_deployment(root, fixture.f.config, fixture.f.report, source_default=True)
      engine.IMAGE_STATE.require_no_image(root, resume)
      items, errors = N.generation_items(engine, root)
      require(not errors and items == {name: baseline[name] for name in engine.BASELINE_ITEMS}, "Generation differs from the baseline after reactivation")
    return engine._reactivate(N.ROOT, guard=handle.check, gate=lambda root, phase: N._maintenance_gate(engine, root, phase, capture), native=engine._NATIVE_MAINTENANCE,
                              pinned=capture, assess=lambda evidence, raw: N._assess_core(engine, N.ROOT, evidence, raw),
                              inspect=lambda evidence: {"config": {**qualified, "staged_receipt_sha256": receipt_digest}, "manifest": qualified["manifest"]},
                              postchecks=postchecks)

  snapsync()  # one snapshot sync before anything: the region now exists in the inactive stock bytes
  assessed("unchanged", changed=[], limine_exact=False)
  stock_with_region = LIMINE.read_bytes()
  step("reactivate-0-assess-unchanged", "class=unchanged with a snapshot region present (exact_equal=False, stock projection equal)")

  before = evidence_tree()
  code, out, err = reactivate_cli()
  require(code != 0 and evidence_tree() == before and not Path("/var/lib/pacman/db.lck").exists(), "Real CLI reactivate must refuse without writing when derivation is unavailable: " + out + err)
  step("reactivate-1-cli-refuses-without-derivation", "real CLI passed the assessment then refused at derivation with zero writes: " + (err.splitlines()[-1] if err else out)[:160])

  handle = I.acquire(N)
  try: reactivate(handle, failure="injected W6 failure")
  except ValueError as error: require("injected W6 failure" in str(error), "Wrong failure: " + str(error))
  else: raise RuntimeError("Injected postcheck failure did not surface")
  handle.check()
  release(handle)
  require((STATE / "boot-policy.json").exists() and (Path("/etc/omarchy/t2-hibernate-product.enabled")).exists() and (STATE / "package-maintenance.pending").exists(), "Failed run must stop after W5 with the marker kept")
  require(b"default_entry: MBA-T2-hibernation-source-" in LIMINE.read_bytes(), "Boot-config line was not switched before the injected failure")
  veto_holds()
  code, out, err = native_cli()
  require(code != 0 and "reactivate" in err, "maintenance did not refuse naming reactivate: " + out + err)
  step("reactivate-2-injected-failure-vetoed", "W6 failure left pending+marker+policy+opt-in+switched line; reviewed sleep entry, update guard, real pacman and `maintenance` all refuse")

  code, out, err = reactivate_cli()  # recovery is a re-run of the real CLI: it rolls back, never forward
  require(code == 0, "Real CLI recovery failed: " + out + err)
  rolled = json.loads(out.splitlines()[-1])
  require(rolled["rolled_back"] is True and rolled["reactivated"] is False and rolled["live_execution"] is True and rolled["power_operation"] is False, "Recovery result differs: " + out)
  require(LIMINE.read_bytes() == stock_with_region and not (STATE / "boot-policy.json").exists() and not Path("/etc/omarchy/t2-hibernate-product.enabled").exists()
          and not (STATE / "source-default-activation.pending").exists() and marker.exists() and not Path("/var/lib/pacman/db.lck").exists(), "Rollback did not restore inactive maintenance")
  code, text = run_hook()
  require(code == 0, "Guard refused after rollback: " + text)
  assessed("unchanged", changed=[], limine_exact=False)
  step("reactivate-3-rollback-by-rerun", "real CLI rolled back: limine bytes restored exactly (snapshot region intact), marker kept, guard admits, assess unchanged; " + out[:120])

  handle = I.acquire(N)
  reply = reactivate(handle)
  handle.check()
  release(handle)
  require(reply["reactivated"] is True and reply["requalification_required"] is False, "Reactivation result differs: " + json.dumps(reply, sort_keys=True))
  activated = LIMINE.read_bytes()
  require(activated == stock_with_region.replace(b"default_entry: 2\n", b"default_entry: " + json.loads((STATE / "boot-policy.json").read_bytes())["source_entry_id"].encode() + b"\n", 1)
          and b"limine-snapper-sync" in activated, "Reactivated bytes are not exactly the one-line change of the current bytes")
  require(not marker.exists() and not (STATE / "source-default-activation.pending").exists() and (STATE / "boot-policy.json").exists()
          and Path("/etc/omarchy/t2-hibernate-product.enabled").exists() and not Path("/var/lib/pacman/db.lck").exists(), "ACTIVE state wrong after reactivation")
  sleep_entry.reject_pending(Path("/"))  # no pending or marker remains: the reviewed sleep entry's veto no longer applies
  code, text = run_hook()
  require(code == 1 and "remains active/incomplete" in text, "Blanket guard did not refuse the ACTIVE state: " + text)
  blocked(app("0.9-1"), "remains active/incomplete")
  step("reactivate-4-active-and-guard-blocks", "reactivated=True; exactly one default_entry line changed; hook exit 1 and real pacman aborted; " + json.dumps({key: reply[key] for key in ("transition_id", "requalification_required")}))

  snapsync()  # one more snapshot sync while ACTIVE
  require(engine.P.verify(Path("/"), receipt_digest) is True, "BOOT_POLICY.verify failed after further snapshot churn")
  F.F.PRODUCT.TRIAL._verify_deployment(Path("/"), fixture.f.config, fixture.f.report, source_default=True)
  step("reactivate-5-verify-survives-snapsync", "BOOT_POLICY.verify and the source-default deployment check pass after another snapshot sync: " + json.dumps(re.findall(r"^     ///(\d+) ", LIMINE.read_text(), re.M)))

  handle = I.acquire(N)
  capture = {"resume": dict(resume)}
  result = engine._transition(N.ROOT, "maintenance", precheck=precheck, guard=handle.check, maintenance_gate=lambda root, phase: N._maintenance_gate(engine, root, phase, capture),
                              native=engine._NATIVE_MAINTENANCE, maintenance_resume=lambda: capture["resume"], maintenance_baseline=lambda: N._baseline(engine, N.ROOT))
  handle.check()
  release(handle)
  baseline_file = STATE / "boot-policy-transitions" / result["transition_id"] / "generation-baseline.json"
  require(marker.exists() and not (STATE / "boot-policy.json").exists(), "Second maintenance publication state wrong")
  code, text = run_hook()
  require(code == 0, "Guard refused the republished maintenance: " + text)
  assessed("unchanged", changed=[], limine_exact=True)
  step("reactivate-6-back-to-maintenance", "deactivation after churn published a marker the real guard validates (from_sha256 = approved active hash); assess unchanged; intent_sha256=" + result["maintenance_intent_sha256"])

  # --- (b) real native CLI re-entry ---
  code, out, err = native_cli()
  require(code == 0, "Native maintenance re-entry failed: " + out + err)
  reply = json.loads(out.splitlines()[-1])
  require(reply["already_inactive"] is True and reply["qualification_issued"] is False and reply["power_operation"] is False and reply["maintenance_intent_sha256"] == result["maintenance_intent_sha256"], "Native re-entry result differs")
  step("native-cli-reentry-1", "already_inactive=True " + json.dumps(reply, sort_keys=True))

  # --- (c) first admitted transaction ---
  original_uki = UKI.read_bytes()
  code, text = run_hook()
  require(code == 0, "Direct hook run refused: " + text)
  guard = load("guest_guard", GUARD)
  admission = guard.native()
  require(admission["classification"] == "inactive-maintenance-update-admitted" and admission["resume"] == resume, "Native guard classification differs")
  step("guard-direct", json.dumps({key: admission[key] for key in ("classification", "image", "resume", "transition_id")}, sort_keys=True) + " production_blake2b=" + admission["fallback"]["production"]["blake2b"][:16])
  admitted(app("1.0-1"))
  require(installed("t2fixture-app") == "1.0-1" and Path("/opt/t2fixture/app").read_bytes() == b"app 1.0-1\n", "Admitted app transaction did not install")
  step("txn-1-app-admitted", "app 1.0-1 installed via real pacman -U; hook AbortOnFail passed")
  report = assessed("unchanged", changed=[], limine_exact=False)
  step("assess-1-after-userspace-txn", "class=unchanged; limine snapshot churn: exact_equal=False stock_projection_equal=True")

  # --- (d) kernel package update, coherent stock rewrite ---
  admitted(kernel("1.0-1"))
  uki1 = UKI.read_bytes()
  require(uki1 != original_uki and installed("t2fixture-kernel") == "1.0-1", "Kernel install did not rewrite UKI")
  admitted(kernel("2.0-1"))
  uki2 = UKI.read_bytes()
  require(uki2 != uki1 and installed("t2fixture-kernel") == "2.0-1" and blake2(uki2) in LIMINE.read_text(), "Kernel update did not coherently rewrite UKI + limine")
  report = assessed("requalification-required", changed=["production_uki"], limine_exact=False)
  step("assess-2-after-kernel-update", "class=requalification-required changed=" + json.dumps(report["changed_items"]) + " paths=" + json.dumps(report["items"]["production_uki"]["paths"]))
  before = evidence_tree()
  code, out, err = reactivate_cli()
  require(code != 0 and "requalification required: production_uki" in err and evidence_tree() == before and not Path("/var/lib/pacman/db.lck").exists(),
          "Kernel-update variant was not refused with zero writes: " + out + err)
  code, text = run_hook()
  require(code == 0, "Refused reactivation must leave updates allowed: " + text)
  step("reactivate-7-kernel-update-refused", "real CLI: requalification required: production_uki, zero writes, marker kept, guard still admits")
  step("txn-2-3-kernel-update-admitted", "kernel 1.0-1 then 2.0-1 admitted; uki blake2b " + blake2(original_uki)[:16] + " -> " + blake2(uki1)[:16] + " -> " + blake2(uki2)[:16])

  # --- (e) transaction after the kernel update still admitted, with the NEW stock bytes ---
  admitted(app("2.0-1"))
  require(installed("t2fixture-app") == "2.0-1", "Post-kernel-update transaction did not install")
  churned = LIMINE.read_text()
  require("limine-snapper-sync" in churned and len(re.findall(r"^     ///\d+ ", churned, re.M)) == 2 and re.findall(r"^default_entry:.*$", churned, re.M) == ["default_entry: 2"], "Snapshot churn did not accompany the transactions")
  report = assessed("requalification-required", changed=["production_uki"])
  step("assess-3-after-post-kernel-userspace-txn", "still requalification-required; nothing but the production UKI differs")
  step("txn-4-after-kernel-update-admitted", "app 2.0-1 upgraded against updated coherent stock bytes; snapshot sub-entries added/pruned by every transaction: " + json.dumps(re.findall(r"^     ///(\d+) ", churned, re.M)))

  # --- (f) native maintenance re-entry after the update ---
  code, out, err = native_cli()
  require(code == 0, "Native re-entry after update failed: " + out + err)
  reply2 = json.loads(out.splitlines()[-1])
  require(reply2["already_inactive"] is True and reply2["maintenance_intent_sha256"] == result["maintenance_intent_sha256"], "Post-update re-entry differs")
  step("native-cli-reentry-2", "already_inactive=True after kernel update; marker unchanged " + json.dumps(reply2, sort_keys=True))

  # --- (g) negatives: fail closed, no package change ---
  good_limine = LIMINE.read_bytes()
  sysfs("resume_offset", OFFSET + 1)
  blocked(app("3.0-1"), "Active kernel resume target differs")
  sysfs("resume_offset", OFFSET)
  step("neg-kernel-resume-topology", "resume_offset mismatch aborts pacman, packages/boot bytes unchanged")

  Path("/etc/guest-sim/btrfs-swap-offset").write_text("99\n")
  blocked(app("3.0-1"), "Actual Btrfs swapfile mapping differs")
  Path("/etc/guest-sim/btrfs-swap-offset").write_text(str(OFFSET) + "\n")
  step("neg-btrfs-mapping", "swapfile mapping mismatch aborts pacman")

  write_header(b"S1SUSPEND\0")
  blocked(app("3.0-1"), "Pending or unknown hibernation image header")
  write_header(b"SWAPSPACE2")
  step("neg-saved-image", "hibernation-image signature at the resume page aborts pacman")

  code, text = run_hook()
  require(code == 0, "Restored topology not admitted again: " + text)
  held = os.open("/var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock", os.O_RDONLY)
  try:
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    blocked(app("3.0-1"), "A hibernation cycle holds the physical lock")
  finally: os.close(held)
  step("neg-physical-lock-held", "held physical cycle lock aborts pacman")

  admitted(kernel("3.0-1", "-nolimine"))
  require(UKI.read_bytes() != uki2 and strip_snapshots(LIMINE.read_bytes()) == strip_snapshots(good_limine), "nolimine kernel fixture did not leave stale stock hash")
  blocked(app("3.0-1"), "Stock entry does not bind actual production UKI bytes")
  code, out, err = native_cli()
  require(code != 0, "Native CLI accepted incoherent stock bytes")
  print("NATIVE_CLI_REFUSAL rc=" + str(code) + " stderr_tail=" + (err.splitlines()[-1] if err else out[-200:]), flush=True)
  report = assessed("unknown")
  require("Stock entry does not bind actual production UKI bytes" in report["reason"], "Incoherent stock bytes must make the evidence unknown, not assessable: " + report["reason"])
  atomic(LIMINE, re.sub(r"(omarchy_linux-t2\.efi#)[0-9a-f]{128}", lambda match: match.group(1) + blake2(UKI.read_bytes()), LIMINE.read_text()).encode())
  admitted(app("3.0-1"))
  step("neg-incoherent-kernel-update", "UKI changed without limine hash: pacman + native CLI refuse; repaired coherent bytes admit again")

  archive = STATE / "boot-policy-transitions" / result["transition_id"]
  resume_file = archive / "maintenance-resume.json"
  saved = resume_file.read_bytes()
  resume_file.unlink()
  blocked(app("4.0-1"), "maintenance-resume.json")
  write_file(resume_file, saved, 0o600)
  code, text = run_hook()
  require(code == 0, "Restored resume evidence not admitted: " + text)
  step("neg-missing-resume-evidence", "removed archived resume file aborts pacman; exact restore admits again")

  saved_baseline = baseline_file.read_bytes()
  baseline_file.unlink()
  report = assessed("unknown")
  require(report["baseline"] == "missing", "Missing baseline must be reported")
  write_file(baseline_file, saved_baseline.replace(b'"transition_id":"', b'"transition_id":"0', 1), 0o600)
  report = assessed("unknown")
  require(report["baseline"] == "invalid", "Forged baseline binding must be refused")
  before = evidence_tree()
  code, out, err = reactivate_cli()
  require(code != 0 and "compatibility unknown: Generation baseline is invalid" in err and evidence_tree() == before, "Class (c) was not refused with zero writes: " + out + err)
  write_file(baseline_file, saved_baseline, 0o600)
  assessed("requalification-required", changed=["production_uki"])
  step("neg-baseline-missing-and-forged", "removed and mis-bound baseline sidecars are unknown (compatibility unknown); exact restore assesses again")

  marker_bytes = marker.read_bytes()
  admitted(app("4.0-1"))
  require(installed("t2fixture-app") == "4.0-1" and marker.read_bytes() == marker_bytes, "Final transaction/marker state wrong")
  step("final-admitted", "marker retained byte-identical; app 4.0-1 installed")
  print("MAINTENANCE_NATIVE_VM_PASS", flush=True)


def main():
  if len(sys.argv) == 2 and sys.argv[1] == "mkuki": return mkuki()
  if len(sys.argv) == 2 and sys.argv[1] == "snapsync": return snapsync()
  require(Path(__file__).absolute() == SCRIPT and os.getresuid() == (0,) * 3 and sys.flags.isolated, "Fixed isolated guest root script only")
  require(len(sys.argv) == 1, "No arguments")
  owner()
  return 0


if __name__ == "__main__": raise SystemExit(main())
