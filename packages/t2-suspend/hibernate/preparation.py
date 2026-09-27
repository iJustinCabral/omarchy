"""Injected preparation and owned cleanup derived from the successful pair runner.

There is no CLI or default command, sysfs, EFI or sleep backend. The adapter never
enters hibernation. Callers must supply reviewed preflight/artifact qualification
and a serialized backend. Historical guards and EFI witnesses are not imported,
cleared or migrated. Cleanup unloads only its source marker, preserving stage EFI
and durable product guards. The separate retirement adapter owns slot release.

Order follows run-hibernation-uki-pair-s4.py: bolt, Bluetooth, owned Wi-Fi detach,
PM, consumed guard, source marker plus V3/V2 stage zero, restore one-shot, durable
transition intent. Cleanup follows its one-shot, PM, Wi-Fi, Bluetooth, bolt, marker
order. Completed preparation is not a power transition or hardware qualification.
"""

import copy
import hashlib
import importlib.util
import re
from pathlib import Path


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


CT = _module("preparation_continuity", "continuity.py")
TX = CT.TX
SCHEMA = "omarchy-t2-product-preparation-v1"
MARKER = "mba_hibernate_efi_postwrite_marker"
WIFI = "0000:73:00.0"


class Preparation:
  """Backend read(key), write(key,value), command(tuple) and injected sleeper.

  Read keys are fixed logical readbacks, including parsed LoaderEntry values,
  marker parameters and identities. Commands are explicit historical argv; the
  injected backend must verify model/file/module/EFI identities without defaults.
  source_stage/restore_stage writes must create exclusively, never replace an
  existing EFI value. arm_vector must address only the pinned source marker.
  ``cleanup`` is a workflow callback, run while that workflow owns the ledger
  lock. It never acquires a second lock or advances the ledger on its own.
  """
  def __init__(self, ledger, reserved_cycle, backend, marker_file, marker_pin, *, sleeper, predecessor_archive_directory=None):
    self.ledger = ledger
    self.cycle = copy.deepcopy(TX.cycle_value(reserved_cycle))
    CT.exact(self.cycle["state"], "reserved", "Reserved preparation cycle")
    CT.fields(marker_pin, ("sha256", "srcversion", "vermagic", "variable_version"), "Source marker pin")
    TX.hash_value(marker_pin["sha256"])
    if type(marker_pin["srcversion"]) is not str or not re.fullmatch(r"[0-9A-F]{24}", marker_pin["srcversion"]):
      raise ValueError("Invalid source marker srcversion")
    if type(marker_pin["vermagic"]) is not str or not marker_pin["vermagic"].split():
      raise ValueError("Invalid source marker vermagic")
    CT.exact(marker_pin["variable_version"], "v3", "Source marker protocol")
    self.backend = backend
    self.marker_file = str(Path(marker_file))
    if not Path(marker_file).is_absolute():
      raise ValueError("Explicit absolute private marker file required")
    self.marker_pin = copy.deepcopy(marker_pin)
    self.sleeper = sleeper
    self.predecessor_archive_directory = predecessor_archive_directory
    self.stem = "preparation-" + self.cycle["cycle_id"]
    self.baseline = None
    self.actions = []
    self.started = set()
    self._used = False
    self._cleaned = False
    self._receipt = None
    self.guard_file = ledger.directory / (self.stem + "-guard.json")
    self.attempt_file = ledger.directory / (self.stem + "-attempt.json")

  def _read(self, key):
    return copy.deepcopy(self.backend.read(key))

  def _binding(self):
    return {key: copy.deepcopy(self.cycle[key]) for key in CT.BINDING_KEYS}

  def _journal(self, suffix, value):
    self.ledger._write(self.stem + "-" + suffix + ".json", value, exclusive=True)
    return TX.digest(value)

  def _action(self, name, target, operation, verify):
    intent = {"schema": SCHEMA, "cycle_binding": self._binding(), "name": name,
              "state": "intent", "target": target, "baseline": copy.deepcopy(self.baseline)}
    identity = self._journal(name + "-intent", intent)
    self.started.add(name)
    operation()
    verify()
    complete = {"schema": SCHEMA, "cycle_binding": self._binding(), "name": name,
                "state": "complete", "intent_sha256": identity}
    completion = self._journal(name + "-complete", complete)
    self.actions.append({"name": name, "intent_sha256": identity, "completion_sha256": completion})

  def _bluetooth(self, powered):
    for attempt in range(3 if powered else 1):
      try:
        self.backend.command(("timeout", "5s", "bluetoothctl", "power", "on" if powered else "off"))
        CT.exact(self._read("bluetooth_powered"), powered, "Bluetooth power readback")
        return
      except Exception:
        if not powered or attempt == 2:
          raise
        self.sleeper(1)

  def _source_selection(self, advance):
    # Shared read-only verifier admits a restore-selected source session only
    # through its authoritative immediate reconciled predecessor, never a flag.
    host = _module("preparation_source_selection", "host_observation.py")
    host.validate_source_selection(self.ledger, self.cycle, self._read("selected_entry"), self.predecessor_archive_directory, locked_advance=advance)

  def _preflight(self, advance):
    CT.exact(self._read("model"), "MacBookAir9,1", "Preparation model")
    CT.exact(self._read("boot_id"), self.cycle["original_boot_id"], "Preparation source boot")
    source = "MBA-T2-hibernation-source-" + self.cycle["manifest"]["source_sha256"][:16]
    restore = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
    self._source_selection(advance)
    for key in ("oneshot", "default", "source_stage", "restore_stage", "restore_hook_entered", "restore_hook_armed"):
      CT.exact(self._read(key), None, "Unoccupied preparation " + key)
    entries = self._read("loader_entries")
    if type(entries) is not list or source not in entries or restore not in entries:
      raise ValueError("Exact source/restore entries not advertised")
    CT.exact(self._read("source_marker_loaded"), False, "Unloaded source marker")
    CT.exact(self._read("marker_file_identity"), self.marker_pin, "Audited source marker file")
    CT.exact(self._read("kernel_release"), self.marker_pin["vermagic"].split()[0], "Source marker kernel ABI")
    CT.exact(self._read("wifi_identity"), {"vendor": "0x14e4", "device": "0x4488"}, "Wi-Fi identity")
    wifi = self._read("wifi_driver")
    if wifi not in (None, "brcmfmac"):
      raise ValueError("Unexpected Wi-Fi driver")
    bolt, bluetooth = self._read("bolt_active"), self._read("bluetooth_powered")
    if type(bolt) is not bool or type(bluetooth) is not bool:
      raise ValueError("Unavailable bolt or Bluetooth baseline")
    pm = {name: self._read(name) for name in ("pm_test", "disk", "pm_trace")}
    CT.exact(pm, {"pm_test": "none", "disk": "platform", "pm_trace": "0"}, "Qualified baseline PM")
    self.baseline = {"bolt_active": bolt, "bluetooth_powered": bluetooth, "wifi_driver": wifi, "pm": pm}
    self._journal("baseline", {"schema": SCHEMA, "cycle_binding": self._binding(), "baseline": self.baseline})
    return restore

  def prepare(self):
    if self._used:
      raise ValueError("Preparation object already consumed")
    self._used = True
    def execute(advance):
      try:
        restore = self._preflight(advance)
        if self.baseline["bolt_active"]:
          self._action("bolt-stop", False, lambda: self.backend.command(("systemctl", "stop", "bolt.service")), lambda: CT.exact(self._read("bolt_active"), False, "Stopped bolt"))
        if self.baseline["bluetooth_powered"]:
          self._action("bluetooth-off", False, lambda: self._bluetooth(False), lambda: CT.exact(self._read("bluetooth_powered"), False, "Isolated Bluetooth"))
        if self.baseline["wifi_driver"] == "brcmfmac":
          self._action("wifi-detach", WIFI, lambda: self.backend.write("wifi_unbind", WIFI), lambda: CT.exact(self._read("wifi_driver"), None, "Detached owned Wi-Fi"))
        for name, target in (("pm_test", "none"), ("disk", "platform"), ("pm_trace", "0")):
          self._action("pm-" + name, target, lambda name=name, target=target: self.backend.write(name, target), lambda name=name, target=target: CT.exact(self._read(name), target, "Selected PM " + name))
        guard = {"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": self._binding()}
        self.ledger._write(self.guard_file.name, guard, exclusive=True)
        self._action("marker-load", self.marker_pin, lambda: self.backend.command(("insmod", self.marker_file)), self._verify_disarmed)
        source_zero = b"\x07\0\0\0MBPW" + bytes.fromhex(self.cycle["prefix"]) + b"\0"
        restore_zero = b"\x07\0\0\0MBRS" + bytes.fromhex(self.cycle["prefix"]) + b"\0"
        self._action("source-stage", source_zero.hex(), lambda: self.backend.write("source_stage", source_zero), lambda: CT.exact(self._read("source_stage"), source_zero, "Source stage zero"))
        self._action("marker-arm", self.cycle["vector"], lambda: self.backend.write("arm_vector", self.cycle["vector"]), self._verify_armed)
        self._action("restore-stage", restore_zero.hex(), lambda: self.backend.write("restore_stage", restore_zero), lambda: CT.exact(self._read("restore_stage"), restore_zero, "Restore stage zero"))
        self._action("restore-oneshot", restore, lambda: self._arm_restore(restore, advance), lambda: CT.exact(self._read("oneshot"), restore, "Owned restore one-shot"))
        attempt = {"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": self._binding(), "state": "transition-armed",
                   "real_s4_attempted": True, "requested_disk_mode": "platform", "consumed_guard_sha256": self._raw_hash(self.guard_file)}
        # This is the existing continuity contract's durable pre-write intent,
        # not a claim that preparation itself executed the physical transition.
        self.ledger._write(self.attempt_file.name, attempt, exclusive=True)
        self._receipt = {"schema": SCHEMA, "cycle_binding": self._binding(), "baseline": copy.deepcopy(self.baseline), "actions": copy.deepcopy(self.actions),
                         "owned_one_shot": {"entry_id": restore, "boot_id": self.cycle["original_boot_id"]},
                         "guard_sha256": self._raw_hash(self.guard_file), "attempt_sha256": self._raw_hash(self.attempt_file)}
        self._journal("complete", self._receipt)
        prepared = advance("prepared", TX.digest(self._receipt))
        self.cycle = prepared
        return {"cycle": copy.deepcopy(prepared), "receipt": self.receipt(), "guard_file": self.guard_file, "attempt_file": self.attempt_file}
      except BaseException as error:
        cleanup_errors = self.cleanup()
        failed = {"schema": SCHEMA, "cycle_binding": self._binding(), "error_type": type(error).__name__, "cleanup_errors": cleanup_errors}
        try:
          self._journal("failure", failed)
        except BaseException as persistence_error:
          error.add_note("Preparation failure journal could not persist: " + type(persistence_error).__name__)
        try:
          advance("failed", TX.digest(failed))
        except BaseException as latch_error:
          error.add_note("Preparation failure latch could not persist; incomplete cycle remains blocked: " + type(latch_error).__name__)
        raise
    return self.ledger.compare_and_run(self.cycle, execute)

  def _raw_hash(self, path):
    self.ledger._private(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()

  def _arm_restore(self, restore, advance):
    for name in ("oneshot", "default"):
      CT.exact(self._read(name), None, "No conflicting EFI " + name)
    CT.exact(self._read("boot_id"), self.cycle["original_boot_id"], "Restore arm source boot")
    self._source_selection(advance)
    self._verify_armed()
    CT.exact(self._read("restore_stage"), b"\x07\0\0\0MBRS" + bytes.fromhex(self.cycle["prefix"]) + b"\0", "Restore prefix immediately before arm")
    self.backend.command(("bootctl", "set-oneshot", restore))

  def _verify_disarmed(self):
    CT.exact(self._read("source_marker_loaded"), True, "Loaded owned source marker")
    CT.exact(self._read("source_marker_identity"), self.marker_pin, "Loaded marker pin")
    CT.exact(self._read("source_marker_parameters"), {"arm_vector": "0", "stage": "0", "last_efi_status": "0"}, "Disarmed source marker")

  def _verify_armed(self):
    CT.exact(self._read("source_marker_parameters"), {"arm_vector": "1", "stage": "0", "last_efi_status": "0"}, "Armed source marker")
    CT.exact(self._read("source_stage"), b"\x07\0\0\0MBPW" + bytes.fromhex(self.cycle["prefix"]) + b"\0", "Armed source prefix")

  def receipt(self):
    if self._receipt is None:
      raise ValueError("Preparation is incomplete")
    stored = self.ledger._read(self.stem + "-complete.json")
    CT.exact(stored, self._receipt, "Durable completed preparation")
    return copy.deepcopy(stored)

  def cleanup(self):
    """Restore only journal-owned actions; preserves guards and all stage EFI.

    Successful cleanup is one-use. Failed cleanup has no automatic retry; durable
    intents retain the ownership evidence for independent external recovery.
    """
    if self._cleaned:
      return ["preparation cleanup already consumed"]
    self._cleaned = True
    errors = []
    if self.baseline is None:
      return errors
    def recover(name, operation):
      intent_persisted = False
      try:
        self._journal(name + "-cleanup-intent", {"schema": SCHEMA, "cycle_binding": self._binding(), "name": name})
        intent_persisted = True
      except BaseException as error:
        errors.append(name + " cleanup journal: " + type(error).__name__)
      try:
        # Original action ownership was durable before mutation. Failure to
        # journal cleanup must not suppress its owned recovery operation.
        operation()
      except BaseException as error:
        errors.append(name + ": " + type(error).__name__)
        return
      try:
        self._journal(name + "-cleanup-complete", {"schema": SCHEMA, "cycle_binding": self._binding(), "name": name,
                                                  "cleanup_intent_persisted": intent_persisted})
      except BaseException as error:
        errors.append(name + " cleanup completion: " + type(error).__name__)
    def oneshot():
      current = self._read("oneshot")
      if current is None:
        return
      restore = "MBA-T2-hibernation-restore-" + self.cycle["manifest"]["restore_sha256"][:16]
      CT.exact(current, restore, "Still-owned restore one-shot")
      CT.exact(self._read("boot_id"), self.cycle["original_boot_id"], "Owned one-shot boot")
      self.backend.command(("bootctl", "set-oneshot", ""))
      CT.exact(self._read("oneshot"), None, "Cleared owned one-shot")
    if "restore-oneshot" in self.started:
      recover("restore-oneshot", oneshot)
    for name in ("pm_test", "disk", "pm_trace"):
      if "pm-" + name in self.started:
        def restore_pm(name=name):
          self.backend.write(name, self.baseline["pm"][name])
          CT.exact(self._read(name), self.baseline["pm"][name], "Restored PM " + name)
        recover("pm-" + name, restore_pm)
    if "wifi-detach" in self.started:
      def wifi():
        current = self._read("wifi_driver")
        if current is None:
          self.backend.write("wifi_bind", WIFI)
        CT.exact(self._read("wifi_driver"), "brcmfmac", "Rebound owned Wi-Fi")
      recover("wifi-detach", wifi)
    if "bluetooth-off" in self.started:
      recover("bluetooth-off", lambda: self._bluetooth(True))
    if "bolt-stop" in self.started:
      def bolt():
        self.backend.command(("systemctl", "start", "bolt.service"))
        CT.exact(self._read("bolt_active"), True, "Restored bolt")
      recover("bolt-stop", bolt)
    if "marker-load" in self.started:
      def marker():
        if self._read("source_marker_loaded"):
          CT.exact(self._read("source_marker_identity"), self.marker_pin, "Owned marker unload identity")
          self.backend.command(("rmmod", MARKER))
        CT.exact(self._read("source_marker_loaded"), False, "Unloaded source marker")
      recover("marker-load", marker)
    return errors
