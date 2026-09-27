"""Fixed host operations, with no CLI and no implicit live root.

Construction requires an explicit root and audited cycle/artifact/marker pins.
Live root '/' requires euid 0 and forbids injected command/sysfs implementations.
Fixture roots require an explicit command runner. No reset or generic power API
exists. Power and two-slot retirement require active scoped ledger capabilities.
The dispatcher must additionally serialize hardware globally; efivarfs has no
atomic compare-and-delete primitive. Slot removal assumes that serialization and
absent marker writers, rechecking bytes and open-file identity before deletion.
Artifact consistency is not product qualification or authority for a trial.
"""

import array
import copy
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HOST = _module("backend_host_observation", "host_observation.py")
CT = HOST.CT
TX = CT.TX
RETIRE = _module("backend_slot_retirement", "slot_retirement.py")
POWER_POLICY = _module("backend_power_policy", "power_policy.py")
MARKER = HOST.MARKER
WIFI = "0000:73:00.0"
MAX_BYTES = 2 * 1024 * 1024
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x10


def _native_command(argv):
  # Fixed executable directory and locale; never inherit a user's shell PATH.
  return subprocess.run(("/usr/bin/" + argv[0], *argv[1:]), check=False, capture_output=True, text=True, timeout=20,
                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})


def verify_readiness(root, report, *, command_runner=None):
  """Read-only pre-consumption service/PCI/resume baseline, without a cycle."""
  root = Path(root)
  if not root.is_absolute() or not root.is_dir() or any(path.is_symlink() for path in (root, *root.parents)):
    raise ValueError("Explicit nonsymlink readiness root required")
  if root.resolve() == Path("/") and command_runner is not None:
    raise ValueError("No injected live readiness commands")
  if root.resolve() != Path("/") and command_runner is None:
    raise ValueError("Fixture readiness requires explicit command runner")
  def text(relative):
    path = root / relative
    path.resolve().relative_to(root.resolve())
    return HOST._raw(path).decode().strip()
  def query(argv):
    result = _native_command(argv) if command_runner is None else command_runner(tuple(argv))
    if result.returncode != 0 or type(result.stdout) is not str or len(result.stdout.encode()) > MAX_BYTES:
      raise ValueError("Unavailable bounded readiness query")
    return result.stdout.strip()
  CT.exact(text("sys/class/dmi/id/product_name"), "MacBookAir9,1", "Readiness model")
  CT.exact(text("proc/sys/kernel/osrelease"), report["audited_details"]["kernel_release"], "Readiness source kernel")
  for address, (vendor, device, driver) in HOST.PCI.items():
    relative = "sys/bus/pci/devices/" + address
    CT.exact((text(relative + "/vendor"), text(relative + "/device")), (vendor, device), "Readiness PCI identity")
    link = root / relative / "driver"
    if driver is None:
      if link.exists() or link.is_symlink(): raise ValueError("Readiness unexpected PCI driver")
    elif not link.is_symlink() or link.resolve(strict=True) != (root / "sys/bus/pci/drivers" / driver).resolve(strict=True):
      raise ValueError("Readiness exact PCI driver differs")
  for name in ("NetworkManager.service", "bluetooth.service", "sddm.service"):
    CT.exact(query(("systemctl", "is-active", name)), "active", "Readiness active service")
  CT.exact(query(("systemctl", "--failed", "--no-legend", "--plain", "--no-pager")), "", "Readiness no failed units")
  resume = report["audited_details"]["restore_protocol"]["resume"]
  CT.exact(text("sys/power/resume"), resume["devnum"], "Readiness resume device")
  CT.exact(text("sys/power/resume_offset"), str(resume["offset"]), "Readiness resume offset")
  CT.exact(query(("lsblk", "--nodeps", "--noheadings", "--output", "MAJ:MIN", resume["device"])), resume["devnum"], "Readiness actual resume block device")
  for name, expected in (("pm_test", "none"), ("disk", "platform")):
    selected = [item[1:-1] for item in text("sys/power/" + name).split() if item.startswith("[") and item.endswith("]")]
    CT.exact(selected, [expected], "Readiness qualified PM baseline")
  CT.exact(text("sys/power/pm_trace"), "0", "Readiness trace baseline")
  CT.exact(text("sys/power/pm_async"), "0", "Readiness T2 async baseline")
  if "disk" not in text("sys/power/state").split(): raise ValueError("Kernel disk power state not advertised")
  disk_modes = [item.strip("[]") for item in text("sys/power/disk").split()]
  if "platform" not in disk_modes: raise ValueError("Platform hibernation not advertised")
  swaps = [line.split() for line in text("proc/swaps").splitlines()[1:] if line.strip()]
  if any(len(row) != 5 for row in swaps): raise ValueError("Malformed active swap inventory")
  file_swaps = [row for row in swaps if row[1] == "file"]
  if len(file_swaps) != 1 or file_swaps[0][0] != "/swap/swapfile":
    raise ValueError("Exactly one active swapfile required")
  CT.exact(resume["device"], "/dev/mapper/root", "Pinned primary encrypted resume device")
  CT.exact(query(("btrfs", "inspect-internal", "map-swapfile", "-r", "/swap/swapfile")), str(resume["offset"]), "Actual swapfile resume extent")
  backing = query(("findmnt", "-n", "-o", "SOURCE,FSTYPE", "--target", "/swap/swapfile")).split()
  if len(backing) != 2 or backing[1] != "btrfs" or not re.fullmatch(r"/dev/mapper/root(?:\[/[^\]\r\n]*\])?", backing[0]):
    raise ValueError("Swapfile is not on the primary encrypted Btrfs root")
  pending = root / "run/omarchy-t2-hibernate-wifi/rebind-device"
  if pending.exists() or pending.is_symlink(): raise ValueError("Historical Wi-Fi cleanup is pending")


def validate_static_inputs(report, manifest, marker_file, marker_pin):
  """Pure constructor admission shared with the pre-consumption dispatcher.

  This creates no cycle and performs no filesystem, query or host mutation.
  Actual artifact/marker bytes and metadata remain independently checked.
  """
  manifest = TX.manifest_value(manifest)
  CT.exact(report["manifest"], manifest, "Backend artifact pins")
  CT.exact(TX.digest(report["audited_details"]), report["audited_details_sha256"], "Backend computed details digest")
  CT.exact(report["audited_details"]["manifest_sha256"], TX.digest(manifest), "Backend details manifest")
  CT.exact(report["hardware_qualified"], False, "No artifact hardware qualification")
  CT.exact(report["usable_hibernation_qualified"], False, "No artifact usability qualification")
  modules = report["audited_details"]["runtime_modules"]
  if type(modules) is not dict or not modules:
    raise ValueError("Missing audited runtime module pins")
  for metadata in modules.values():
    CT.srcversion_value(metadata["srcversion"])
  if not Path(marker_file).is_absolute():
    raise ValueError("Explicit absolute marker file required")
  CT.fields(marker_pin, ("sha256", "srcversion", "vermagic", "variable_version"), "Backend marker pin")
  TX.hash_value(marker_pin["sha256"])
  # This target's modpost passes sizeof(srcversion[25]) - 1 to snprintf,
  # whose terminating NUL leaves 23 uppercase hex characters. Other module
  # toolchains emit 24. Format admission does not relax exact modinfo/pin
  # comparison or the independently pinned module byte hash.
  CT.srcversion_value(marker_pin["srcversion"])
  if (type(marker_pin["vermagic"]) is not str or not marker_pin["vermagic"].split() or
      marker_pin["vermagic"].split()[0] != report["audited_details"]["kernel_release"]):
    raise ValueError("Marker static production ABI differs")
  CT.exact(marker_pin["variable_version"], "v3", "Backend marker protocol")


class HostBackend:
  def __init__(self, root, report, reserved_cycle, marker_file, marker_pin, *, command_runner=None, sysfs_writer=None):
    self.root = Path(root)
    if not self.root.is_absolute() or not self.root.is_dir() or self.root.is_symlink() or any(path.is_symlink() for path in self.root.parents):
      raise ValueError("Explicit absolute nonsymlink root required")
    self.live = self.root.resolve() == Path("/")
    if self.live and (os.geteuid() != 0 or command_runner is not None or sysfs_writer is not None):
      raise ValueError("Live root requires root identity and fixed native backends")
    if not self.live and command_runner is None:
      raise ValueError("Fixture root requires explicit command runner")
    self._runner = command_runner
    self._writer = sysfs_writer
    self.report = copy.deepcopy(report)
    self.cycle = copy.deepcopy(TX.cycle_value(reserved_cycle))
    self.marker_file = Path(marker_file)
    validate_static_inputs(self.report, self.cycle["manifest"], self.marker_file, marker_pin)
    self.marker_pin = copy.deepcopy(marker_pin)

  def _path(self, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
      raise ValueError("Fixed backend path must remain relative")
    path = self.root / relative
    path.resolve().relative_to(self.root.resolve())
    return path

  def _raw(self, relative, optional=False):
    path = self._path(relative)
    if optional and not path.exists() and not path.is_symlink():
      return None
    return HOST._raw(path)

  def _text(self, relative):
    return self._raw(relative).decode().strip()

  def _run(self, argv):
    argv = tuple(argv)
    if self._runner is None:
      result = _native_command(argv)
    else:
      result = self._runner(argv)
    if type(result.returncode) is not int or type(result.stdout) is not str or len(result.stdout.encode()) > MAX_BYTES:
      raise ValueError("Invalid bounded command result")
    return result

  def query(self, argv):
    """Allowlisted read-only query backend for the host sampler."""
    argv = tuple(str(item) for item in argv)
    module = len(argv) == 4 and argv[:2] == ("modinfo", "-F") and argv[2] in ("srcversion", "vermagic", "mba_postwrite_variable") and Path(argv[3]).is_absolute()
    service = len(argv) == 3 and argv[:2] == ("systemctl", "is-active") and argv[2] in ("bolt.service", "NetworkManager.service", "bluetooth.service", "sddm.service", "systemd-logind.service", "display-manager.service")
    failed = argv == ("systemctl", "--failed", "--no-legend", "--plain", "--no-pager")
    resume = self.report["audited_details"]["restore_protocol"]["resume"]["device"]
    block = argv == ("lsblk", "--nodeps", "--noheadings", "--output", "MAJ:MIN", resume)
    bluetooth = argv == ("timeout", "5s", "bluetoothctl", "show")
    if not (module or service or failed or block or bluetooth):
      raise ValueError("Command is outside fixed read-only backend")
    result = self._run(argv)
    if result.returncode != 0 and not service:
      raise ValueError("Read-only backend command failed")
    return result.stdout.strip()

  def _loader(self, name, multiple=False, optional=False):
    raw = self._raw(HOST.EFI / (name + "-" + HOST.LOADER_GUID), optional=optional)
    if raw is None:
      return None
    attributes = b"\x07\0\0\0" if name in ("LoaderEntryOneShot", "LoaderEntryDefault") else b"\x06\0\0\0"
    if len(raw) < 6 or raw[:4] != attributes or len(raw[4:]) % 2:
      raise ValueError("Loader EFI attributes or framing differs")
    text = raw[4:].decode("utf-16-le")
    if not text.endswith("\0"):
      raise ValueError("Loader EFI string lacks terminator")
    values = text.rstrip("\0").split("\0")
    if not values or any(not item for item in values) or len(set(values)) != len(values):
      raise ValueError("Loader EFI entries are empty or duplicate")
    if not multiple and len(values) != 1:
      raise ValueError("Loader EFI single entry differs")
    return values if multiple else values[0]

  def _marker_identity(self, loaded=False):
    if self.live:
      HOST.ARTIFACTS._regular_path(self.marker_file)
      info = self.marker_file.stat()
      if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Live marker must be root-owned private file")
    CT.exact(HOST.ARTIFACTS._file_digest(self.marker_file), self.marker_pin["sha256"], "Actual private marker hash")
    actual = {"sha256": self.marker_pin["sha256"], "srcversion": self.query(("modinfo", "-F", "srcversion", self.marker_file)),
              "vermagic": self.query(("modinfo", "-F", "vermagic", self.marker_file)),
              "variable_version": self.query(("modinfo", "-F", "mba_postwrite_variable", self.marker_file))}
    CT.exact(actual, self.marker_pin, "Actual private marker metadata")
    if not actual["vermagic"].split() or actual["vermagic"].split()[0] != self.read("kernel_release"):
      raise ValueError("Marker production ABI differs")
    if loaded:
      CT.exact(self._text("sys/module/" + MARKER + "/srcversion"), actual["srcversion"], "Loaded marker srcversion")
    return actual

  def read(self, key):
    paths = {"model": "sys/class/dmi/id/product_name", "boot_id": "proc/sys/kernel/random/boot_id", "kernel_release": "proc/sys/kernel/osrelease", "pm_trace": "sys/power/pm_trace"}
    if key in paths:
      value = self._text(paths[key])
      return TX.uuid_value(value) if key == "boot_id" else value
    if key in ("pm_test", "disk"):
      choices = [word[1:-1] for word in self._text("sys/power/" + key).split() if word.startswith("[") and word.endswith("]")]
      if len(choices) != 1: raise ValueError("Ambiguous PM selection")
      return choices[0]
    loaders = {"selected_entry": "LoaderEntrySelected", "oneshot": "LoaderEntryOneShot", "default": "LoaderEntryDefault", "loader_entries": "LoaderEntries"}
    if key in loaders:
      return self._loader(loaders[key], multiple=key == "loader_entries", optional=key in ("oneshot", "default"))
    stages = {"source_stage": CT.SOURCE_VARIABLE, "restore_stage": CT.RESTORE_VARIABLE,
              "restore_hook_entered": "OmarchyT2RestoreHookEntered" + self.cycle["prefix"] + "-" + CT.GUID,
              "restore_hook_armed": "OmarchyT2RestoreHookArmed" + self.cycle["prefix"] + "-" + CT.GUID}
    if key in stages: return self._raw(HOST.EFI / stages[key], optional=True)
    if key == "wifi_identity":
      return {name: self._text("sys/bus/pci/devices/" + WIFI + "/" + name) for name in ("vendor", "device")}
    if key == "wifi_driver":
      link = self._path("sys/bus/pci/devices/" + WIFI + "/driver")
      if not link.exists() and not link.is_symlink(): return None
      if not link.is_symlink(): raise ValueError("Wi-Fi driver is not a sysfs link")
      expected = self._path("sys/bus/pci/drivers/brcmfmac")
      if link.resolve(strict=True) != expected.resolve(strict=True): raise ValueError("Wi-Fi driver is foreign")
      return "brcmfmac"
    if key == "bolt_active":
      result = self._run(("systemctl", "is-active", "bolt.service"))
      if result.returncode == 0 and result.stdout.strip() == "active": return True
      if result.returncode in (0, 3) and result.stdout.strip() == "inactive": return False
      raise ValueError("Unavailable bolt service state")
    if key == "bluetooth_powered":
      text = self.query(("timeout", "5s", "bluetoothctl", "show"))
      values = re.findall(r"^\s*Powered:\s+(yes|no)\s*$", text, re.M)
      if len(values) != 1: raise ValueError("Unavailable Bluetooth power state")
      return values[0] == "yes"
    if key == "source_marker_loaded": return self._path("sys/module/" + MARKER).exists()
    if key in ("marker_file_identity", "source_marker_identity"): return self._marker_identity(loaded=key == "source_marker_identity")
    if key == "source_marker_parameters":
      return {name: self._text("sys/module/" + MARKER + "/parameters/" + name) for name in ("arm_vector", "stage", "last_efi_status")}
    raise ValueError("Unknown fixed backend read key")

  def command(self, argv):
    argv = tuple(argv)
    ordinary = argv in (("systemctl", "stop", "bolt.service"), ("systemctl", "start", "bolt.service"),
                        ("timeout", "5s", "bluetoothctl", "power", "on"), ("timeout", "5s", "bluetoothctl", "power", "off"))
    load = argv == ("insmod", str(self.marker_file))
    unload = argv == ("rmmod", MARKER)
    restore = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
    oneshot = argv in (("bootctl", "set-oneshot", restore), ("bootctl", "set-oneshot", ""))
    if not (ordinary or load or unload or oneshot): raise ValueError("Command is outside fixed preparation backend")
    if load: self._marker_identity()
    if unload: self._marker_identity(loaded=True)
    if oneshot:
      CT.exact(self.read("default"), None, "No persistent EFI override")
      CT.exact(self.read("oneshot"), None if argv[-1] else restore, "Exact owned one-shot operation")
    result = self._run(argv)
    if result.returncode != 0: raise ValueError("Fixed preparation command failed")

  def _write_bytes(self, relative, value, *, exclusive=False):
    path = self._path(relative)
    if self._writer is not None and not exclusive:
      self._writer(path, value)
      return
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_CREAT | os.O_EXCL if exclusive else 0
    fd = os.open(path, flags, 0o600)
    try:
      if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError("Fixed target is not regular sysfs/EFI file")
      if os.write(fd, value) != len(value): raise OSError("Short fixed backend write")
      if exclusive and not self.live: os.fsync(fd)
    finally:
      os.close(fd)
    if exclusive:
      if self.live:
        os.sync()
        CT.exact(self._raw(relative), value, "Actual EFI stage readback")
        return
      parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
      try: os.fsync(parent)
      finally: os.close(parent)

  def write(self, key, value):
    targets = {"pm_test": "none", "disk": "platform", "pm_trace": "0"}
    if key in targets:
      CT.exact(value, targets[key], "Fixed supported PM value")
      self._write_bytes("sys/power/" + key, value.encode())
      return
    if key in ("wifi_unbind", "wifi_bind"):
      CT.exact(value, WIFI, "Exact Wi-Fi function")
      CT.exact(self.read("wifi_identity"), {"vendor": "0x14e4", "device": "0x4488"}, "Owned Wi-Fi identity")
      CT.exact(self.read("wifi_driver"), "brcmfmac" if key == "wifi_unbind" else None, "Wi-Fi binding before operation")
      self._write_bytes("sys/bus/pci/drivers/brcmfmac/" + ("unbind" if key == "wifi_unbind" else "bind"), value.encode())
      return
    if key == "arm_vector":
      CT.exact(value, self.cycle["vector"], "Exact active cycle arm")
      self._marker_identity(loaded=True)
      CT.exact(self.read("source_marker_parameters"), {"arm_vector": "0", "stage": "0", "last_efi_status": "0"}, "Pristine marker arm")
      self._write_bytes("sys/module/" + MARKER + "/parameters/arm_vector", value.encode())
      return
    slots = {"source_stage": (CT.SOURCE_VARIABLE, b"MBPW"), "restore_stage": (CT.RESTORE_VARIABLE, b"MBRS")}
    if key in slots:
      name, magic = slots[key]
      CT.exact(value, b"\x07\0\0\0" + magic + bytes.fromhex(self.cycle["prefix"]) + b"\0", "Exact product stage-zero bytes")
      self._write_bytes(HOST.EFI / name, value, exclusive=True)
      return
    raise ValueError("Unknown or prohibited fixed write key")

  def power_writer(self, ledger, prepared_cycle, receipt, *, power_policy=None):
    return _PowerWrite(self, ledger, prepared_cycle, receipt, power_policy=power_policy)

  def read_slot(self, name):
    if name not in RETIRE.SLOTS.values(): raise ValueError("Only two fixed reusable slots can be read")
    return self._raw(HOST.EFI / name, optional=True)

  def retirement_callbacks(self, ledger, cycle, archive_directory):
    return self.read_slot, _SlotDelete(self, ledger, cycle, archive_directory)

  @staticmethod
  def retirement_health(sampler, original_binding):
    """Adapt the same retained sampler's cleanup checks; not caller success flags."""
    original = copy.deepcopy(original_binding)
    def observe(binding):
      for key in CT.BINDING_KEYS:
        CT.exact(binding[key], original[key], "Retirement original sampler binding")
      witness = sampler.health(copy.deepcopy(original))
      CT.exact(witness["binding"], original, "Retained health binding")
      CT.exact(witness.pop("after_cleanup"), True, "Post-cleanup sampler health")
      return {**witness, "schema": RETIRE.HEALTH_SCHEMA, "binding": copy.deepcopy(binding), "after_slot_retirement": True}
    return observe

  def archived_retirement_health(self, cycle, archive_directory):
    """Fresh host health for verified archival retirement, NOT source continuity.

    No retained Sampler, before-write state or Collector is reconstructed. The
    archived witness proves the earlier return; this callback observes NOW.
    """
    cycle = copy.deepcopy(TX.cycle_value(cycle))
    if cycle["state"] not in ("archived", "released"):
      raise ValueError("Fresh retirement health requires archived cycle")
    CT.exact(cycle["manifest"], self.report["manifest"], "Fresh health artifact pins")
    for key in CT.BINDING_KEYS:
      CT.exact(cycle[key], self.cycle[key], "Fresh health backend cycle")
    def pm():
      resume = self.report["audited_details"]["restore_protocol"]["resume"]
      devnum = self.query(("lsblk", "--nodeps", "--noheadings", "--output", "MAJ:MIN", resume["device"]))
      CT.exact(devnum, resume["devnum"], "Fresh health resume identity")
      CT.exact(self._text("sys/power/resume"), devnum, "Fresh health active resume device")
      offset = int(self._text("sys/power/resume_offset"))
      CT.exact(offset, resume["offset"], "Fresh health resume offset")
      return CT.pm_value({**{name: self.read(name) for name in ("pm_test", "disk", "pm_trace")},
                          "resume_device": resume["device"], "resume_offset": offset})
    def observe(binding):
      expected, markers, baseline = RETIRE._archived_evidence(archive_directory, cycle)
      CT.exact(binding, expected, "Fresh health verified archive binding")
      CT.exact(self.read("boot_id"), cycle["original_boot_id"], "Fresh health original boot")
      data = HOST.observe_current_health(self.root, self.query, pm, require_source_marker_absent=True)
      CT.exact(data["boot_id"], cycle["original_boot_id"], "Fresh health sampled original boot")
      CT.exact(data["pm"], baseline, "Fresh health archived PM baseline")
      result = {**data, "schema": RETIRE.HEALTH_SCHEMA, "binding": copy.deepcopy(binding), "after_slot_retirement": True}
      devices = CT.healthy_devices_value(result["devices"])
      CT.exact(result, RETIRE._health_expected(expected, baseline, ac_online=devices["ac_online"]), "Fresh retirement health")
      RETIRE._archived_evidence(archive_directory, cycle)
      return result
    return observe


class _PowerWrite:
  def __init__(self, backend, ledger, cycle, receipt, *, power_policy=None):
    self.backend, self.ledger = backend, ledger
    self.cycle = copy.deepcopy(TX.cycle_value(cycle))
    CT.exact(self.cycle["state"], "prepared", "Power callback prepared cycle")
    CT.exact({key: self.cycle[key] for key in CT.BINDING_KEYS}, {key: backend.cycle[key] for key in CT.BINDING_KEYS}, "Power callback backend binding")
    self.receipt = copy.deepcopy(receipt)
    self.power_policy = POWER_POLICY.validate(power_policy)
    self._advance = None
    self._used = False

  def bind_locked(self, advance):
    if self._advance is not None or self._used: raise ValueError("Power capability already consumed")
    CT.exact(advance.check_current(), self.cycle, "Scoped prepared power authority")
    self._advance = advance

  def __call__(self, path, value):
    if self._used: raise ValueError("Power write is one-use")
    self._used = True
    CT.exact(path, "/sys/power/state", "Fixed power path")
    CT.exact(value, "disk", "Fixed power value")
    if self._advance is None: raise ValueError("Missing locked workflow power capability")
    CT.exact(self._advance.check_current(), self.cycle, "Current locked prepared cycle")
    stem = "preparation-" + self.cycle["cycle_id"]
    CT.exact(self.ledger._read(stem + "-complete.json"), self.receipt, "Durable power preparation receipt")
    CT.exact(TX.digest(self.receipt), self.cycle["prepared_evidence_sha256"], "Prepared receipt hash")
    guard = HOST._raw(self.ledger.directory / (stem + "-guard.json"), private=True)
    attempt = HOST._raw(self.ledger.directory / (stem + "-attempt.json"), private=True)
    CT.consumed_records(self.cycle, guard, attempt)
    CT.exact(CT.raw_digest(guard), self.receipt["guard_sha256"], "Guard before power")
    CT.exact(CT.raw_digest(attempt), self.receipt["attempt_sha256"], "Attempt before power")
    before = self.ledger._read("workflow-before-" + self.cycle["cycle_id"] + ".json")
    CT.exact(before["phase"], "before-write", "Durable original workflow intent")
    retained = before["retained"]
    CT.exact(retained["write_used"], False, "Original collector before write")
    for key in CT.BINDING_KEYS: CT.exact(retained["binding"][key], self.cycle[key], "Workflow power cycle binding")
    backend = self.backend
    CT.exact(backend.read("model"), "MacBookAir9,1", "Exact power model")
    CT.exact(backend.read("boot_id"), self.cycle["original_boot_id"], "Original power boot")
    resume = backend.report["audited_details"]["restore_protocol"]["resume"]
    CT.exact(backend._text("sys/power/resume"), resume["devnum"], "Resume device before power")
    CT.exact(backend._text("sys/power/resume_offset"), str(resume["offset"]), "Resume offset before power")
    CT.exact(backend._text("sys/power/pm_async"), "0", "T2 async baseline before power")
    restore = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
    CT.exact(backend.read("oneshot"), restore, "Exact restore one-shot before power")
    CT.exact(backend.read("default"), None, "No persistent override before power")
    for key, expected in (("pm_test", "none"), ("disk", "platform"), ("pm_trace", "0"), ("wifi_driver", None), ("bluetooth_powered", False), ("bolt_active", False)):
      CT.exact(backend.read(key), expected, "Isolated power state " + key)
    backend._marker_identity(loaded=True)
    CT.exact(backend.read("source_marker_parameters"), {"arm_vector": "1", "stage": "0", "last_efi_status": "0"}, "Armed source before power")
    for key, magic in (("source_stage", b"MBPW"), ("restore_stage", b"MBRS")):
      CT.exact(backend.read(key), b"\x07\0\0\0" + magic + bytes.fromhex(self.cycle["prefix"]) + b"\0", "Exact staged power prefix")
    os.sync() if backend.live else None
    POWER_POLICY.check(backend.root, self.power_policy)
    backend._write_bytes("sys/power/state", b"disk")


class _SlotDelete:
  def __init__(self, backend, ledger, cycle, archive_directory):
    self.backend, self.ledger, self.directory = backend, ledger, archive_directory
    self.cycle = copy.deepcopy(TX.cycle_value(cycle))
    if self.cycle["state"] not in ("archived", "released"): raise ValueError("Archived retirement cycle required")
    CT.exact({key: self.cycle[key] for key in CT.BINDING_KEYS}, {key: backend.cycle[key] for key in CT.BINDING_KEYS}, "Retirement backend binding")
    self._advance = None
    self._used = set()

  def bind_locked(self, advance):
    if self._advance is not None: raise ValueError("Retirement capability already bound")
    CT.exact(advance.check_current(), self.cycle, "Scoped archived retirement authority")
    self._advance = advance

  def __call__(self, name, expected):
    if name not in RETIRE.SLOTS.values() or name in self._used: raise ValueError("Unknown or consumed reusable slot")
    self._used.add(name)
    if self._advance is None: raise ValueError("Missing locked retirement capability")
    CT.exact(self._advance.check_current(), self.cycle, "Current locked archived cycle")
    _binding, originals, _pm = RETIRE._archived_evidence(self.directory, self.cycle)
    role = next(role for role, fixed in RETIRE.SLOTS.items() if fixed == name)
    CT.exact(expected, originals[role + "-stage.bin"], "Verified private archive slot authorization")
    loaded = {line.split()[0] for line in self.backend._text("proc/modules").splitlines() if line.split()}
    loaded |= {path.name for path in self.backend._path("sys/module").iterdir()}
    if any(item.startswith("mba_hibernate_cold_") or "abort" in item.lower() or item in (MARKER, "mba_hibernate_efi_restore_marker") for item in loaded):
      raise ValueError("Marker or cold module writer still present")
    path = self.backend._path(HOST.EFI / name)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    reopened = None
    original_flags = None
    removed = False
    try:
      fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
      info = os.fstat(fd)
      if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES: raise ValueError("Owned slot is not a bounded regular file")
      CT.exact(os.read(fd, MAX_BYTES + 1), expected, "Owned raw slot immediately before retirement")
      current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
      if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino): raise ValueError("Owned slot path changed")
      if self.backend.live: original_flags = _clear_immutable(fd)
      # Native efivarfs descriptors need not be seekable. Reopen at offset zero
      # while retaining the original inode descriptor for protection recovery.
      reopened = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
      repeated = os.fstat(reopened)
      if (not stat.S_ISREG(repeated.st_mode) or repeated.st_size > MAX_BYTES or
          (repeated.st_dev, repeated.st_ino) != (info.st_dev, info.st_ino)):
        raise ValueError("Owned slot changed while reopening")
      CT.exact(os.read(reopened, MAX_BYTES + 1), expected, "Owned slot after immutable handling")
      current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
      if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino): raise ValueError("Owned slot path changed before unlink")
      os.unlink(path.name, dir_fd=parent)
      removed = True
      if self.backend.live: os.sync()
      else: os.fsync(parent)
      return True
    finally:
      try:
        if fd is not None and not removed and original_flags is not None and original_flags & FS_IMMUTABLE_FL:
          # Preserve the original open inode's protection on failed comparison.
          flags = array.array("L", [original_flags])
          fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags, True)
      finally:
        if reopened is not None: os.close(reopened)
        if fd is not None: os.close(fd)
        os.close(parent)


def _clear_immutable(fd):
  flags = array.array("L", [0])
  fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
  original = flags[0]
  if original & FS_IMMUTABLE_FL:
    flags[0] = original & ~FS_IMMUTABLE_FL
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, flags, True)
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
    if flags[0] != original & ~FS_IMMUTABLE_FL: raise ValueError("Exact owned immutable flag clear failed")
  return original
