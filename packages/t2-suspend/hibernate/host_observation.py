"""Read-only sampling through explicitly supplied roots, files and query backend.

No CLI, default host root/query, module load, power or EFI write exists. Artifact
report digests provide consistency, not authentication of a report's producer:
actual source files/provenance and the retained cycle are independently compared.
The caller still supplies previously audited restore/production artifact details
and an independently reviewed external source-marker pin. No qualification is
created. Runtime cmdline hashes frame /proc bytes; UKI section hashes frame PE
bytes and therefore intentionally differ. Complete module names plus selected
file hashes/srcversions do not authenticate arbitrary loaded memory bytes.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


CT = _module("observation_continuity", "continuity.py")
ARTIFACTS = _module("observation_artifacts", "artifacts.py")
TX = CT.TX
RETIREMENT = _module("observation_retirement", "slot_retirement.py")
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
EFI = Path("sys/firmware/efi/efivars")
MARKER = "mba_hibernate_efi_postwrite_marker"
MAX_BYTES = 2 * 1024 * 1024
PCI = {"0000:73:00.0": ("0x14e4", "0x4488", "brcmfmac"),
       "0000:73:00.1": ("0x14e4", "0x5fa0", "hci_bcm4377"),
       "0000:74:00.0": ("0x106b", "0x2005", "nvme"),
       "0000:74:00.1": ("0x106b", "0x1801", "t2bce_core"),
       "0000:74:00.2": ("0x106b", "0x1802", None),
       "0000:74:00.3": ("0x106b", "0x1803", "t2bce_audio")}


def _raw(path, private=False):
  path = Path(path)
  if path.is_symlink() or not path.is_file():
    raise ValueError("Missing, nonregular or symlinked observation file")
  if private and any(parent.is_symlink() for parent in path.parents):
    raise ValueError("Consumed evidence has a symlinked ancestor")
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  with os.fdopen(fd, "rb") as stream:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
      raise ValueError("Observation file exceeds bounded read")
    if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
      raise ValueError("Consumed evidence owner/mode/link count differs")
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
      raise ValueError("Observation file exceeds bounded read")
    return raw


def _digest(raw):
  return hashlib.sha256(raw).hexdigest()


def validate_source_selection(ledger, cycle, selected_entry, archive_directory=None, *, locked_advance=None):
  """Accept source, or proven same-boot immediate product return, never fresh restore.

  The optional locked capability is supplied only by Ledger.compare_and_run's
  trusted callback, avoiding nested locks during preparation. No predecessor
  JSON is accepted. Archive validation verifies byte integrity and the retained
  witness, conditional on the private trusted runner; it is not qualification.
  """
  cycle = TX.cycle_value(cycle)
  source = "MBA-T2-hibernation-source-" + cycle["manifest"]["source_sha256"][:16]
  if selected_entry == source:
    return
  restore = "MBA-T2-hibernation-restore-" + cycle["manifest"]["restore_sha256"][:16]
  CT.exact(selected_entry, restore, "Selected source or validated returned entry")
  if ledger is None or archive_directory is None:
    raise ValueError("Restore selection requires private predecessor ledger and byte archive")
  previous = ledger.predecessor(cycle) if locked_advance is None else locked_advance.predecessor()
  if previous is None or previous["state"] != "reconciled":
    raise ValueError("No immediate successful product predecessor")
  for key in ("original_boot_id", "manifest", "qualification_sha256", "qualification_vector"):
    CT.exact(previous[key], cycle[key], "Same-session predecessor " + key)
  # Abstract release/reconcile attestations are insufficient: require the
  # adapter's actual terminal chain (already checked by predecessor()).
  ledger._read("slot-retirement-" + previous["cycle_id"] + "-intent.json")
  RETIREMENT._archived_evidence(archive_directory, previous)


class Sampler:
  def __init__(self, root, report, cycle, qualification, source_directory, source_tree,
               marker_file, marker_pin, guard_file, attempt_file, *, query):
    self.root = Path(root)
    if not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir():
      raise ValueError("Explicit absolute observation root required")
    self.source_directory = Path(source_directory)
    self.source_tree = Path(source_tree)
    self.marker_file = Path(marker_file)
    self.guard_file = Path(guard_file)
    self.attempt_file = Path(attempt_file)
    self.query = query
    self.report = copy.deepcopy(report)
    self.cycle = copy.deepcopy(TX.cycle_value(cycle))
    CT.exact(self.cycle["state"], "prepared", "Prepared observation cycle")
    receipt = TX.authority_value(qualification, self.cycle["manifest"])
    CT.exact(TX.digest(receipt), self.cycle["qualification_sha256"], "Retained qualification binding")
    CT.fields(marker_pin, ("sha256", "srcversion", "vermagic", "variable_version"), "External marker pin")
    TX.hash_value(marker_pin["sha256"])
    CT.exact(marker_pin["variable_version"], "v3", "External marker variable version")
    self.marker_pin = copy.deepcopy(marker_pin)
    self._before_runtime = None
    self._before_pm = None
    self.last_raw_capture = None
    self._audit_source()
    self.guard = _raw(self.guard_file, private=True)
    self.attempt = _raw(self.attempt_file, private=True)
    CT.consumed_records(self.cycle, self.guard, self.attempt)

  def _path(self, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
      raise ValueError("Observation path must be confined and relative")
    path = self.root / relative
    path.resolve().relative_to(self.root.resolve())
    return path

  def _text(self, relative):
    return _raw(self._path(relative)).decode().strip()

  def _query(self, arguments):
    result = self.query(tuple(str(item) for item in arguments))
    if type(result) is not str or len(result.encode()) > MAX_BYTES:
      raise ValueError("Read-only query returned invalid text")
    return result.strip()

  def _audit_source(self):
    report = self.report
    CT.fields(report, ("manifest", "audited_details", "audited_details_sha256", "classification", "hardware_qualified", "usable_hibernation_qualified"), "Artifact report")
    CT.exact(report["classification"], "structurally-audited-artifacts-not-product-qualified", "Structural classification")
    CT.exact(report["hardware_qualified"], False, "Hardware qualification")
    CT.exact(report["usable_hibernation_qualified"], False, "Usability qualification")
    CT.exact(report["manifest"], self.cycle["manifest"], "Cycle artifact manifest")
    details = report["audited_details"]
    CT.exact(TX.digest(details), report["audited_details_sha256"], "Computed artifact details digest")
    CT.fields(details, ("protocol", "manifest_sha256", "production_uki_sha256", "sections", "provenance_sha256", "kernel_release", "cmdline_text", "runtime_modules", "source_initrd_module_selection", "restore_marker", "restore_protocol", "external_source_marker_pin_required"), "Audited artifact details")
    CT.exact(details["protocol"], ARTIFACTS.DETAILS_PROTOCOL, "Artifact details protocol")
    CT.exact(details["manifest_sha256"], TX.digest(report["manifest"]), "Details manifest binding")
    CT.exact(details["external_source_marker_pin_required"], True, "External marker requirement")
    raw = ARTIFACTS._raw(self.source_directory / "provenance.json")
    provenance = json.loads(raw, object_pairs_hook=TX.no_duplicates,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite source provenance")))
    CT.exact(_digest(raw), details["provenance_sha256"]["source"], "Actual source provenance digest")
    CT.exact(provenance["candidate"], "mba-t2-hibernation-early-source", "Source boot architecture")
    CT.exact(provenance["pre_restore_module_policy"], "early-t2-radio", "Source module policy")
    if provenance.get("modified_sections_sha256") is not None or provenance.get("kernel_override") is not None:
      raise ValueError("Replacement kernel source rejected")
    CT.exact(ARTIFACTS._file_digest(self.source_directory / "mba-t2-hibernation-candidate.efi"), self.cycle["manifest"]["source_sha256"], "Actual source image")
    CT.exact(provenance["candidate_uki_sha256"], self.cycle["manifest"]["source_sha256"], "Source provenance image")
    CT.exact(ARTIFACTS._file_digest(self.source_directory / "mba-t2-hibernation-candidate.initrd"), provenance["candidate_initrd_sha256"], "Actual source initramfs")
    CT.exact(details["sections"][".initrd"]["source"], provenance["candidate_initrd_sha256"], "Details source initramfs")
    for name, key in (("kernel_release", "kernel_release"), ("cmdline", "cmdline_text"), ("modules", "runtime_modules"), ("initrd_module_selection", "source_initrd_module_selection")):
      CT.exact(provenance[name], details[key], "Actual source " + name)
    CT.exact(provenance["production_uki_sha256"], details["production_uki_sha256"], "Production pin")
    CT.exact(ARTIFACTS.AUDIT.S4.runtime_stack_identity(provenance), self.cycle["manifest"]["runtime_sha256"], "Recomputed source runtime stack")
    for section, identity in provenance["unchanged_production_sections_sha256"].items():
      CT.exact(details["sections"][section], {"source": identity, "restore": identity, "production": identity}, "Preserved section " + section)
    for section, key in ((".linux", "linux_sha256"), (".cmdline", "cmdline_sha256")):
      CT.exact(provenance["unchanged_production_sections_sha256"][section], self.cycle["manifest"][key], "Manifest section " + section)
    CT.exact(details["restore_protocol"]["version"], ARTIFACTS.FULLRESTORE, "Restore protocol")
    for name, expected in (("resume", details["restore_protocol"]["resume"]["device"]), ("resume_offset", str(details["restore_protocol"]["resume"]["offset"]))):
      values = [token.split("=", 1)[1] for token in details["cmdline_text"].split() if token.startswith(name + "=")]
      CT.exact(values, [expected], "Audited resume command line")
    self.details = copy.deepcopy(details)

  def _boot(self):
    CT.exact(self._text("sys/class/dmi/id/product_name"), "MacBookAir9,1", "Observed model")
    return TX.uuid_value(self._text("proc/sys/kernel/random/boot_id"))

  def runtime(self):
    self._audit_source()
    names = [line.split()[0] for line in self._text("proc/modules").splitlines() if line.split()]
    if not names or len(names) != len(set(names)):
      raise ValueError("Duplicate or empty loaded module inventory")
    sys_names = {item.name for item in self._path("sys/module").iterdir()}
    forbidden = lambda name: name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name in ("mba_hibernate_efi_restore_marker", "t2bce_ave")
    if any(forbidden(name) for name in sys_names | set(names)):
      raise ValueError("Restore-only, abort or AVE module in source")
    release = self._text("proc/sys/kernel/osrelease")
    cmdline = _raw(self._path("proc/cmdline"))
    CT.exact(release, self.details["kernel_release"], "Running kernel")
    CT.exact(cmdline.decode().strip(), self.details["cmdline_text"], "Running command line text")
    pins = {name.replace("-", "_"): metadata for name, metadata in self.details["runtime_modules"].items()}
    selection = {name.replace("-", "_"): relative for name, relative in self.details["source_initrd_module_selection"].items()}
    result = {}
    for name in names:
      if name == MARKER:
        selected = self.marker_file
        expected = self.marker_pin
      elif name in pins:
        relative = selection.get(name)
        if not isinstance(relative, str) or not relative.startswith("usr/lib/modules/") or ".." in Path(relative).parts:
          raise ValueError("Missing source initramfs selection")
        embedded = self.source_tree / relative
        embedded.resolve().relative_to(self.source_tree.resolve())
        expected = pins[name]
        CT.exact(ARTIFACTS._file_digest(embedded), expected["sha256"], "Embedded source module " + name)
        selected = self._path("run/omarchy-t2-hibernation-candidate/hci_bcm4377.ko") if name == "hci_bcm4377" else embedded
      else:
        continue
      CT.exact(ARTIFACTS._file_digest(selected), expected["sha256"], "Selected source module " + name)
      loaded = self._text(Path("sys/module") / name / "srcversion")
      for field in ("srcversion", "vermagic"):
        CT.exact(self._query(("modinfo", "-F", field, selected)), expected[field], "Selected module " + field)
      CT.exact(loaded, expected["srcversion"], "Loaded source module " + name)
      if not expected["vermagic"].split() or expected["vermagic"].split()[0] != release:
        raise ValueError("Selected module ABI differs")
      if name == MARKER:
        CT.exact(self._query(("modinfo", "-F", "mba_postwrite_variable", selected)), "v3", "Source marker ABI")
      result[name] = {"sha256": expected["sha256"], "srcversion": loaded}
    return CT.runtime_value({"kernel_release": release, "cmdline_sha256": _digest(cmdline), "modules": result, "loaded_modules": sorted(names)})

  def pm(self):
    def selected(name):
      values = [word[1:-1] for word in self._text("sys/power/" + name).split() if word.startswith("[") and word.endswith("]")]
      if len(values) != 1:
        raise ValueError("Power selection is ambiguous")
      return values[0]
    resume = self.details["restore_protocol"]["resume"]
    devnum = self._query(("lsblk", "--nodeps", "--noheadings", "--output", "MAJ:MIN", resume["device"]))
    CT.exact(devnum, resume["devnum"], "Audited resume device identity")
    CT.exact(self._text("sys/power/resume"), devnum, "Active resume device")
    offset = int(self._text("sys/power/resume_offset"))
    CT.exact(offset, resume["offset"], "Active resume offset")
    return CT.pm_value({"pm_test": selected("pm_test"), "disk": selected("disk"), "pm_trace": self._text("sys/power/pm_trace"), "resume_device": resume["device"], "resume_offset": offset})

  def _overrides(self):
    return {name: _raw(self._path(EFI / (name + "-" + LOADER_GUID))) if self._path(EFI / (name + "-" + LOADER_GUID)).exists() or self._path(EFI / (name + "-" + LOADER_GUID)).is_symlink() else None for name in ("LoaderEntryOneShot", "LoaderEntryDefault")}

  def _preparation_receipt(self, receipt):
    CT.fields(receipt, ("schema", "cycle_binding", "baseline", "actions", "owned_one_shot", "guard_sha256", "attempt_sha256"),
              "Completed preparation receipt")
    CT.exact(receipt["schema"], "omarchy-t2-product-preparation-v1", "Preparation protocol")
    CT.exact(TX.digest(receipt), self.cycle["prepared_evidence_sha256"], "Ledger preparation digest")
    CT.exact(receipt["cycle_binding"], {key: self.cycle[key] for key in CT.BINDING_KEYS}, "Prepared cycle binding")
    baseline = receipt["baseline"]
    CT.fields(baseline, ("bolt_active", "bluetooth_powered", "wifi_driver", "pm"), "Pre-isolation baseline")
    if type(baseline["bolt_active"]) is not bool or type(baseline["bluetooth_powered"]) is not bool or baseline["wifi_driver"] not in (None, "brcmfmac"):
      raise ValueError("Invalid pre-isolation service/radio baseline")
    CT.exact(baseline["pm"], {"pm_test": "none", "disk": "platform", "pm_trace": "0"}, "Original supported PM baseline")
    actions = receipt["actions"]
    if type(actions) is not list or not actions:
      raise ValueError("Preparation receipt lacks completed actions")
    names = []
    for action in actions:
      CT.fields(action, ("name", "intent_sha256", "completion_sha256"), "Prepared action")
      if type(action["name"]) is not str or not action["name"]:
        raise ValueError("Invalid prepared action name")
      TX.hash_value(action["intent_sha256"])
      TX.hash_value(action["completion_sha256"])
      names.append(action["name"])
    if len(names) != len(set(names)):
      raise ValueError("Duplicate prepared action")
    entry = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
    CT.exact(receipt["owned_one_shot"], {"entry_id": entry, "boot_id": self.cycle["original_boot_id"]}, "Owned restore one-shot")
    CT.exact(receipt["guard_sha256"], _digest(self.guard), "Preparation guard bytes")
    CT.exact(receipt["attempt_sha256"], _digest(self.attempt), "Preparation transition-armed attempt bytes")
    return {"LoaderEntryOneShot": b"\x07\0\0\0" + (entry + "\0").encode("utf-16-le"), "LoaderEntryDefault": None}

  def before(self, preparation_receipt=None, *, predecessor_ledger=None, predecessor_archive_directory=None):
    """Original-source pre-write snapshot with exact optional preparation.

    The ordinary path requires absent overrides. After preparation, only the
    ledger-bound receipt's exact owned restore one-shot may be present. Its
    pre-isolation PM baseline must already match the supported none/platform/0
    policy; a changed post-isolation state cannot masquerade as the baseline.
    Restore-selected repeated cycles require the immediate private reconciled
    predecessor, actual byte archive and identical original boot/artifacts.
    """
    CT.exact(self._boot(), self.cycle["original_boot_id"], "Original source boot")
    selected_raw = _raw(self._path(EFI / ("LoaderEntrySelected-" + LOADER_GUID)))
    if selected_raw[:4] != b"\x06\0\0\0":
      raise ValueError("Selected entry attributes differ")
    selected = selected_raw[4:].decode("utf-16-le")
    if not selected.endswith("\0") or "\0" in selected[:-1]:
      raise ValueError("Selected entry framing differs")
    validate_source_selection(predecessor_ledger, self.cycle, selected[:-1], predecessor_archive_directory)
    overrides = {"LoaderEntryOneShot": None, "LoaderEntryDefault": None}
    if preparation_receipt is not None:
      overrides = self._preparation_receipt(preparation_receipt)
    CT.exact(self._overrides(), overrides, "Before-write EFI overrides")
    self._before_runtime = self.runtime()
    self._before_pm = self.pm()
    if preparation_receipt is not None:
      CT.exact({key: self._before_pm[key] for key in ("pm_test", "disk", "pm_trace")}, preparation_receipt["baseline"]["pm"],
                "Current preparation policy matches original PM baseline")
    return {"boot_id": self.cycle["original_boot_id"], "source_runtime": copy.deepcopy(self._before_runtime), "baseline_pm": copy.deepcopy(self._before_pm), "audited_details_sha256": TX.digest(self.details)}

  def _binding(self, binding):
    if self._before_runtime is None:
      raise ValueError("Missing source-only before-write sample")
    for key in CT.BINDING_KEYS:
      CT.exact(binding[key], self.cycle[key], "Retained cycle " + key)
    CT.exact(binding["schema"], CT.SCHEMA, "Retained continuity schema")
    TX.hash_value(binding["return_nonce"])
    CT.exact(binding["source_runtime_sha256"], TX.digest(self._before_runtime), "Pre-write runtime binding")
    CT.exact(binding["baseline_pm_sha256"], TX.digest(self._before_pm), "Pre-write PM binding")
    CT.exact(binding["consumed_guard_sha256"], _digest(self.guard), "Consumed guard binding")
    CT.exact(binding["consumed_attempt_sha256"], _digest(self.attempt), "Consumed attempt binding")

  def capture(self, binding):
    """Capture raw return first; retained Collector alone judges restore selection.

    Different boots, overrides or marker bytes are returned intact so a rejected
    continuity capture can still preserve them. No ordinary verifier is relaxed.
    ``last_raw_capture`` retains early bytes if later runtime sampling fails.
    """
    self._binding(binding)
    prefix = self.cycle["prefix"]
    names = (CT.SOURCE_VARIABLE, CT.RESTORE_VARIABLE, "OmarchyT2RestoreHookEntered" + prefix + "-" + CT.GUID, "OmarchyT2RestoreHookArmed" + prefix + "-" + CT.GUID)
    raw = {"efi_overrides": {}, "markers": {}}
    errors = []
    self.last_raw_capture = raw
    def sample(label, reader):
      try:
        return reader()
      except (OSError, ValueError, UnicodeError) as error:
        errors.append({"field": label, "error_type": type(error).__name__})
        return None
    raw["boot_id"] = sample("boot_id", self._boot)
    raw["LoaderEntrySelected"] = sample("LoaderEntrySelected", lambda: _raw(self._path(EFI / ("LoaderEntrySelected-" + LOADER_GUID))))
    for name in ("LoaderEntryOneShot", "LoaderEntryDefault"):
      def read_override():
        path = self._path(EFI / (name + "-" + LOADER_GUID))
        return _raw(path) if path.exists() or path.is_symlink() else None
      raw["efi_overrides"][name] = sample(name, read_override)
    for name in names:
      raw["markers"][name] = sample(name, lambda: _raw(self._path(EFI / name)))
    raw["consumed_guard"] = sample("consumed_guard", lambda: _raw(self.guard_file, private=True))
    raw["consumed_attempt"] = sample("consumed_attempt", lambda: _raw(self.attempt_file, private=True))
    runtime = sample("source_runtime", self.runtime)
    abort_witnesses = sample("abort_witnesses", lambda: sorted(path.name for path in self._path(EFI).iterdir() if "OmarchyT2Cold" in path.name and "Returned" in path.name and prefix in path.name))
    result = {**raw, "schema": CT.SCHEMA, "binding": copy.deepcopy(binding), "manifest": copy.deepcopy(self.cycle["manifest"]),
            "runtime_stack_sha256": self.cycle["manifest"]["runtime_sha256"], "source_runtime": runtime,
            "restore_only_modules": [], "abort_modules": [],
            "abort_witnesses": abort_witnesses}
    if errors:
      # Extra read_errors deliberately violates the strict success schema. The
      # retained Collector stores this incomplete observation before rejecting it.
      result["read_errors"] = errors
    self.last_raw_capture = copy.deepcopy(result)
    return result

  def health(self, binding):
    """Post-cleanup callback: enumeration only, with no source marker required."""
    self._binding(binding)
    loaded = {line.split()[0] for line in self._text("proc/modules").splitlines() if line.split()}
    sys_names = {item.name for item in self._path("sys/module").iterdir()}
    if any(name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name == "mba_hibernate_efi_restore_marker" for name in loaded | sys_names):
      raise ValueError("Restore-only or abort module after cleanup")
    for address, expected in PCI.items():
      device = self._path(Path("sys/bus/pci/devices") / address)
      link = device / "driver"
      actual = (_raw(device / "vendor").decode().strip(), _raw(device / "device").decode().strip(), Path(os.readlink(link)).name if link.is_symlink() else None)
      CT.exact(actual, expected, "Post-cleanup PCI binding")
    mounts = [line.split() for line in self._text("proc/self/mounts").splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
    primary = len(mounts) == 1 and mounts[0][0] == "/dev/mapper/root" and mounts[0][2] == "btrfs" and "subvol=/@" in mounts[0][3].split(",")
    inputs = self._text("proc/bus/input/devices")
    internal = inputs.count('N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"') >= 2 and inputs.count("Phys=usb-t2bce_vhci-") >= 2
    wifi = [path for path in self._path("sys/bus/pci/devices/0000:73:00.0/net").iterdir() if path.is_dir()]
    if "Apple T2 Audio" not in self._text("proc/asound/cards"):
      raise ValueError("T2 audio enumeration missing")
    ac = any(_raw(path / "type").decode().strip() == "Mains" and _raw(path / "online").decode().strip() == "1" for path in self._path("sys/class/power_supply").iterdir() if (path / "type").is_file() and (path / "online").is_file())
    services = {name: self._query(("systemctl", "is-active", name)) for name in ("NetworkManager.service", "bluetooth.service", "sddm.service")}
    return {"schema": CT.SCHEMA, "binding": copy.deepcopy(binding), "boot_id": self._boot(), "after_cleanup": True,
            "devices": {"primary_encrypted_root": primary, "internal_keyboard": internal, "internal_trackpad": internal,
                        "wifi": len(wifi) == 1, "bluetooth": self._path("sys/class/bluetooth/hci0").exists(), "ac_online": ac},
            "services": services, "failed_units": self._query(("systemctl", "--failed", "--no-legend", "--plain", "--no-pager")).splitlines(), "pm": self.pm()}
