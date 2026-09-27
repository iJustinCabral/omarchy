"""Conditional original-process product-cycle continuity, with injected inputs.

No CLI, host sampling, EFI/module writes or built-in power operation exists.
The collector retains context across its one injected write and samples the
return before cleanup. A JSON record cannot recreate that retained context.
This is not cryptographic process authentication: a dishonest original caller,
fake callbacks or arbitrary Python object manipulation can fabricate evidence.
Module identities describe verified files/srcversions, not arbitrary RAM bytes.
The future audited adapter must derive manifest, runtime and baseline pins from
actual provenance and independently verify their files; this API cannot derive
the existing runtime-stack hash from a caller's inventory or authenticate pins.
Neither this contract nor healthy enumeration qualifies physical input or usable
hibernation. Historical experiment proofs cannot qualify a product cycle.
"""

import copy
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import secrets


spec = importlib.util.spec_from_file_location("product_cycle_transaction", Path(__file__).with_name("transaction.py"))
TX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TX)
SCHEMA = "omarchy-t2-product-source-continuity-v1"
SOURCE_VARIABLE = "OmarchyT2PostwriteStageV3-47a2fceb-87bc-4e58-8d83-23f62ffb3393"
RESTORE_VARIABLE = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
GUID = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"
REQUIRED_MODULES = {"brcmfmac", "brcmfmac_wcc", "hci_bcm4377", "t2bce_dma", "t2bce_core",
                    "t2bce_vhci", "t2bce_audio", "mba_hibernate_efi_postwrite_marker"}
BINDING_KEYS = ("protocol", "cycle_id", "original_boot_id", "manifest", "qualification_sha256", "qualification_vector", "vector", "prefix")


def raw_digest(value):
  if type(value) is not bytes or not value or len(value) > 2 * 1024 * 1024:
    raise ValueError("Expected bounded nonempty raw evidence bytes")
  return hashlib.sha256(value).hexdigest()


def consumed_records(cycle, guard, attempt):
  """Synthetic product record contract, separate from historical boot-ID guards."""
  binding = {key: cycle[key] for key in BINDING_KEYS}
  raw_digest(guard)
  raw_digest(attempt)
  def decode(raw):
    try:
      return json.loads(raw, object_pairs_hook=TX.no_duplicates,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError) as error:
      raise ValueError("Malformed consumed record") from error
  exact(decode(guard), {"schema": "omarchy-t2-product-consumed-guard-v1", "cycle": binding}, "Consumed cycle guard")
  exact(decode(attempt), {"schema": "omarchy-t2-product-pretransition-attempt-v1", "cycle": binding,
                         "state": "transition-armed", "real_s4_attempted": True,
                         "requested_disk_mode": "platform", "consumed_guard_sha256": raw_digest(guard)}, "Pretransition attempt")


def json_evidence(value):
  """Lossless deterministic framing for raw bytes in the computed witness."""
  if type(value) is bytes:
    return {"raw_hex": value.hex()}
  if type(value) is dict:
    return {key: json_evidence(item) for key, item in value.items()}
  if type(value) is list:
    return [json_evidence(item) for item in value]
  return value


def fields(value, keys, label):
  if type(value) is not dict or set(value) != set(keys):
    raise ValueError(label + " fields differ")


def exact(actual, expected, label):
  if type(actual) is not type(expected):
    raise ValueError(label + " type differs")
  if type(expected) is dict:
    fields(actual, expected, label)
    for key in expected:
      exact(actual[key], expected[key], label + "." + key)
  elif type(expected) is list:
    if len(actual) != len(expected):
      raise ValueError(label + " length differs")
    for left, right in zip(actual, expected):
      exact(left, right, label)
  elif actual != expected:
    raise ValueError(label + " differs")


def runtime_value(value):
  fields(value, ("kernel_release", "cmdline_sha256", "modules", "loaded_modules"), "Runtime")
  if type(value["kernel_release"]) is not str or not value["kernel_release"]:
    raise ValueError("Missing runtime kernel release")
  TX.hash_value(value["cmdline_sha256"])
  loaded = value["loaded_modules"]
  if type(loaded) is not list or not loaded or any(type(name) is not str or not re.fullmatch(r"[a-zA-Z0-9_]+", name) for name in loaded):
    raise ValueError("Invalid full module inventory")
  if loaded != sorted(set(loaded)):
    raise ValueError("Module inventory must be unique and sorted")
  if any(name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name == "mba_hibernate_efi_restore_marker" for name in loaded):
    raise ValueError("Restore-only or abort module present")
  modules = value["modules"]
  if type(modules) is not dict or not REQUIRED_MODULES <= set(modules) <= set(loaded):
    raise ValueError("Mandatory audited source modules missing")
  for name, identity in modules.items():
    fields(identity, ("sha256", "srcversion"), "Module " + name)
    TX.hash_value(identity["sha256"])
    if type(identity["srcversion"]) is not str or not re.fullmatch(r"[0-9A-F]{23,24}", identity["srcversion"]):
      raise ValueError("Invalid module srcversion")
  return copy.deepcopy(value)


def pm_value(value):
  fields(value, ("pm_test", "disk", "pm_trace", "resume_device", "resume_offset"), "Baseline PM")
  for name, expected in (("pm_test", "none"), ("disk", "platform"), ("pm_trace", "0")):
    exact(value[name], expected, name)
  if type(value["resume_device"]) is not str or not value["resume_device"].startswith("/dev/"):
    raise ValueError("Invalid baseline resume device")
  if type(value["resume_offset"]) is not int or value["resume_offset"] < 0:
    raise ValueError("Invalid baseline resume offset")
  return copy.deepcopy(value)


class Collector:
  """Retain before-write context; only this object's original call may finish.

  ``power_write`` accepts literal (path, value), with no default implementation.
  ``capture`` receives a copy of the binding and must sample raw return evidence
  immediately. Cleanup runs outside this collector; finish then samples health.
  Construction accepts audited runtime and baseline PM pins supplied by caller.
  It validates qualification receipt binding, not its underlying hardware proof.
  """
  def __init__(self, cycle, qualification, source_runtime, baseline_pm, consumed_guard, consumed_attempt):
    cycle = copy.deepcopy(TX.cycle_value(cycle))
    exact(cycle["state"], "prepared", "Prepared cycle")
    receipt = TX.authority_value(qualification, cycle["manifest"])
    exact(TX.digest(receipt), cycle["qualification_sha256"], "Cycle qualification")
    consumed_records(cycle, consumed_guard, consumed_attempt)
    self._guard = consumed_guard
    self._attempt = consumed_attempt
    self._cycle = cycle
    self._runtime = runtime_value(source_runtime)
    self._pm = pm_value(baseline_pm)
    self._binding = {"schema": SCHEMA, **{key: copy.deepcopy(cycle[key]) for key in BINDING_KEYS},
                     "return_nonce": secrets.token_hex(32), "consumed_guard_sha256": raw_digest(consumed_guard),
                     "consumed_attempt_sha256": raw_digest(consumed_attempt),
                     "source_runtime_sha256": TX.digest(self._runtime), "baseline_pm_sha256": TX.digest(self._pm)}
    self._pid = os.getpid()
    self._used = False
    self._returned = False
    self._capture = None
    self._capture_valid = False
    self._finished = False
    self._workflow_started = False

  def __reduce__(self):
    raise TypeError("Original-process context cannot be serialized")

  @property
  def binding(self):
    """An evidence label, never a resumable context or proof of process continuity."""
    return copy.deepcopy(self._binding)

  def _original_process(self):
    if os.getpid() != self._pid:
      raise ValueError("Collector belongs to another process")

  def write_and_capture(self, power_write, capture):
    self._original_process()
    if self._used:
      raise ValueError("Original write is already consumed")
    self._used = True
    power_write("/sys/power/state", "disk")
    self._returned = True
    observed = copy.deepcopy(capture(self.binding))
    self._capture = observed
    self._validate_capture(observed)
    self._capture_valid = True

  def prepared_cycle(self):
    self._original_process()
    return copy.deepcopy(self._cycle)

  def claim_workflow(self):
    """Consume the adapter entry even if persistence fails before the write."""
    self._original_process()
    if self._workflow_started or self._used or self._finished:
      raise ValueError("Collector workflow is already consumed")
    self._workflow_started = True

  def retained_evidence(self):
    """Preserve raw inputs even after rejected capture; never a success receipt."""
    self._original_process()
    return {"binding": self.binding, "consumed_guard": self._guard, "consumed_attempt": self._attempt,
            "capture": copy.deepcopy(self._capture), "capture_valid": self._capture_valid,
            "write_used": self._used, "write_returned": self._returned}

  def _validate_capture(self, observed):
    fields(observed, ("schema", "binding", "boot_id", "manifest", "runtime_stack_sha256", "source_runtime",
                      "LoaderEntrySelected", "efi_overrides", "markers", "restore_only_modules",
                      "abort_modules", "abort_witnesses", "consumed_guard", "consumed_attempt"), "Immediate capture")
    exact(observed["schema"], SCHEMA, "Capture schema")
    exact(observed["binding"], self._binding, "Retained context")
    exact(observed["consumed_guard"], self._guard, "Retained consumed guard bytes")
    exact(observed["consumed_attempt"], self._attempt, "Retained pretransition attempt bytes")
    exact(observed["boot_id"], self._cycle["original_boot_id"], "Restored original boot")
    exact(observed["manifest"], self._cycle["manifest"], "Exact artifact pins")
    exact(observed["runtime_stack_sha256"], self._cycle["manifest"]["runtime_sha256"], "Runtime stack pin")
    runtime_value(observed["source_runtime"])
    exact(observed["source_runtime"], self._runtime, "Restored runtime inventory")
    entry = "MBA-T2-hibernation-restore-" + self._cycle["manifest"]["restore_sha256"][:16]
    exact(observed["LoaderEntrySelected"], b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le"), "Selected restore EFI entry")
    exact(observed["efi_overrides"], {"LoaderEntryOneShot": None, "LoaderEntryDefault": None}, "EFI overrides")
    for name in ("restore_only_modules", "abort_modules", "abort_witnesses"):
      exact(observed[name], [], name)
    prefix = self._cycle["prefix"]
    markers = {SOURCE_VARIABLE: b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04",
               RESTORE_VARIABLE: b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07",
               "OmarchyT2RestoreHookEntered" + prefix + "-" + GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x01",
               "OmarchyT2RestoreHookArmed" + prefix + "-" + GUID: b"\x07\0\0\0MBRH" + prefix.encode() + b"\x02"}
    exact(observed["markers"], markers, "Raw versioned cycle EFI markers")

  def finish(self, health, cleanup_errors):
    self._original_process()
    if not self._returned or not self._capture_valid or self._finished:
      raise ValueError("Missing original return or already finished")
    self._finished = True
    exact(cleanup_errors, [], "Cleanup errors")
    fields(health, ("schema", "binding", "boot_id", "after_cleanup", "devices", "services", "failed_units", "pm"), "Post-cleanup health")
    exact(health["schema"], SCHEMA, "Health schema")
    exact(health["binding"], self._binding, "Health retained context")
    exact(health["boot_id"], self._cycle["original_boot_id"], "Health original boot")
    exact(health["after_cleanup"], True, "Health sampling order")
    exact(health["devices"], {"primary_encrypted_root": True, "internal_keyboard": True,
                             "internal_trackpad": True, "wifi": True, "bluetooth": True, "ac_online": True}, "Healthy devices")
    exact(health["services"], {"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"}, "Healthy services")
    exact(health["failed_units"], [], "Failed units")
    exact(health["pm"], self._pm, "Restored PM baseline")
    proof = {"schema": SCHEMA, "classification": "conditional-original-process-cycle-return", "binding": self.binding,
            "post_cleanup_health_valid": True, "hardware_qualified": False, "physical_input_confirmed": False,
            "usable_hibernation_qualified": False, "trust": "trusted-original-process-and-injected-samplers"}
    self._witness = json_evidence({"proof": proof, "capture": self._capture, "cleanup_health": copy.deepcopy(health)})
    return {**proof, "witness_sha256": TX.digest(self._witness)}

  def returned_transition(self, health, cleanup_errors):
    """Propose a computed ledger receipt; no ledger mutation or PM authority.

    A future adapter must atomically compare prepared_cycle with the ledger's
    current record before recording returned using evidence_sha256. This object
    remains the trusted original producer; imported JSON is not continuity.
    """
    proof = self.finish(health, cleanup_errors)
    return {"prepared_cycle": copy.deepcopy(self._cycle), "action": "returned",
            "evidence_sha256": proof["witness_sha256"], "witness": copy.deepcopy(self._witness)}
