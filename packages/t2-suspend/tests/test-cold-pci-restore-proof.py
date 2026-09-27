#!/usr/bin/python3
"""Synthetic offline contracts only; no fixture represents physical success."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("restore_proof", Path(__file__).resolve().parents[1] /
                                           "experiments/cold-pci-restore-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


def fixture():
  boot = "11111111-1111-4111-8111-111111111111"
  expected = {"schema": PROOF.SCHEMA, "boot_id": boot, "attempt_id": boot,
              "return_nonce": "22222222-2222-4222-8222-222222222222",
              "source_uki_sha256": "a" * 64, "restore_uki_sha256": "b" * 64,
              "production_uki_sha256": "c" * 64, "runtime_stack_sha256": "d" * 64,
              "guard_module_sha256": "e" * 64, "candidate_protocol": "cold-pci-guard-fullrestore-v1",
              "restore_modules": {PROOF.GUARD_MODULE: "e" * 64, "mba_hibernate_restore_marker": "f" * 64},
              # Actual pinned production section and module identities. The
              # surrounding return evidence remains deliberately synthetic.
              "sections": {role: {"linux_sha256": "b6b9d3e9572089c973334fa5faa811328e5efe33e4c00e3d6a69d6c1cf9cc64c",
                                  "cmdline_sha256": "ecf3a0ff094525c9e0b88f34ac8defed18cf805f6bb6d00bff0853c08f5ea2e0"}
                           for role in ("source", "restore", "production")},
              "source_runtime": {"kernel_release": "7.2.6-arch2-Watanare-T2-2-t2",
                                 "cmdline_sha256": "6e8c7c97724360fcbeb6065c6d72c7a30c3c82cea0cf9ca58cef44d6329d9e08",
                                 "modules": {"t2bce_core": "ae507370dc0ee4e87cf5093340d1772cd48e2a14a878a5656ec5923952ac4db4",
                                             "brcmfmac-wcc": "0edfd9065acb349a9ed1662a34a943932fa6178bb2a30aedecd3d49d35637882"}}}
  expected["transition_vector"] = PROOF.digest(":".join(expected[key] for key in
                  ("source_uki_sha256", "restore_uki_sha256", "runtime_stack_sha256")).encode())
  for role in ("source", "restore"):
    expected[role + "_entry_id"] = "MBA-T2-hibernation-" + role + "-" + expected[role + "_uki_sha256"][:16]
  attempt = {key: expected[key] for key in ("boot_id", "transition_vector", "source_uki_sha256",
             "restore_uki_sha256", "runtime_stack_sha256", "source_entry_id", "restore_entry_id")}
  attempt.update(state="transition-armed", hibernate_attempted=True, real_s4_attempted=True,
                 hardware_qualified=False, requested_disk_mode="platform")
  attempt_raw = json.dumps(attempt, sort_keys=True).encode()
  guard = (boot + "\n").encode()
  expected.update(consumed_attempt_sha256=PROOF.digest(attempt_raw), consumed_guard_sha256=PROOF.digest(guard))
  context = {key: expected[key] for key in ("boot_id", "attempt_id", "return_nonce", "transition_vector",
             "source_uki_sha256", "restore_uki_sha256", "production_uki_sha256", "runtime_stack_sha256")}
  context.update(power_path="/sys/power/state", power_value="disk", power_write_returned=True)
  vector = expected["transition_vector"]
  marker_specs = {PROOF.SOURCE_VARIABLE: (b"MBPW", bytes.fromhex(vector[:24]), 4),
                  PROOF.RESTORE_VARIABLE: (b"MBRS", bytes.fromhex(vector[:24]), 7),
                  "OmarchyT2RestoreHookEntered" + vector[:24] + "-" + PROOF.GUID: (b"MBRH", vector[:24].encode(), 1),
                  "OmarchyT2RestoreHookArmed" + vector[:24] + "-" + PROOF.GUID: (b"MBRH", vector[:24].encode(), 2)}
  capture = {"state": "returned", "context": copy.deepcopy(context), "boot_id": boot,
             "LoaderEntrySelected_hex": (b"\x06\0\0\0" + (expected["restore_entry_id"] + "\0").encode("utf-16-le")).hex(),
             "efi_overrides": {"LoaderEntryOneShot": None, "LoaderEntryDefault": None},
             "pair_pins": {key: copy.deepcopy(expected[key]) for key in ("source_uki_sha256", "restore_uki_sha256",
               "production_uki_sha256", "runtime_stack_sha256", "guard_module_sha256", "sections",
               "candidate_protocol", "restore_modules")},
             "runtime_stack_sha256": expected["runtime_stack_sha256"],
             "source_runtime": copy.deepcopy(expected["source_runtime"]), "restore_only_modules": [],
             "abort_modules": [], "abort_witnesses": [],
             "markers": {name: (b"\x07\0\0\0" + magic + token + bytes((stage,))).hex()
                         for name, (magic, token, stage) in marker_specs.items()}}
  observation = {"schema": PROOF.SCHEMA, "state": "returned-and-cleaned", "return_capture": capture,
                 "consumed_guard_hex": guard.hex(), "consumed_attempt_hex": attempt_raw.hex(),
                 "cleanup_completed": True, "cleanup_errors": []}
  health = {key: expected[key] for key in ("boot_id", "transition_vector", "return_nonce")}
  health.update(after_cleanup=True, failed_units=[],
                devices={"primary_encrypted_root": True, "internal_keyboard": True, "internal_trackpad": True,
                         "wifi": True, "bluetooth": True, "ac_online": True},
                services={"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"},
                pm={"pm_test": "none", "disk": "platform", "pm_trace": "0",
                    "resume_device": "/dev/mapper/root", "resume_offset": 1923214})
  return expected, observation, context, health


def set_path(obj, path, value):
  for key in path[:-1]:
    obj = obj[key]
  obj[path[-1]] = value


class RestoreProofTests(unittest.TestCase):
  def test_actual_production_cmdline_framing_and_hyphenated_module(self):
    expected, observation, context, _ = fixture()
    self.assertNotEqual(expected["source_runtime"]["cmdline_sha256"],
                        expected["sections"]["production"]["cmdline_sha256"])
    self.assertIn("brcmfmac-wcc", expected["source_runtime"]["modules"])
    PROOF.validate_source_return(expected, observation, context)
    observation["return_capture"]["source_runtime"]["cmdline_sha256"] = expected["sections"]["production"]["cmdline_sha256"]
    with self.assertRaises(ValueError):
      PROOF.validate_source_return(expected, observation, context)

  def test_conditional_return_never_qualifies_usable_hibernation(self):
    expected, observation, context, health = fixture()
    original = copy.deepcopy((expected, observation, context, health))
    result = PROOF.validate_source_return(expected, observation, context)
    self.assertEqual(result["classification"], "source-return-evidence-valid")
    self.assertFalse(result["hardware_qualified"])
    self.assertFalse(result["physical_input_confirmed"])
    self.assertFalse(result["usable_hibernation_qualified"])
    self.assertNotIn("post_cleanup_health_valid", result)
    self.assertTrue(PROOF.validate_post_cleanup(expected, observation, context, health)["post_cleanup_health_valid"])
    self.assertEqual((expected, observation, context, health), original)

  def test_false_success_mutations(self):
    mutations = [
      (0, ["schema"], "cold-pci-pre-arch-v1"),
      (0, ["candidate_protocol"], "cold-pci-guard-pre-arch-abort-v1"),
      (0, ["transition_vector"], "0" * 64),
      (0, ["runtime_stack_sha256"], "D" * 64),
      (0, ["source_uki_sha256"], False),
      (0, ["attempt_id"], "33333333-3333-4333-8333-333333333333"),
      (0, ["sections", "restore", "linux_sha256"], "0" * 64),
      (0, ["sections", "source", "cmdline_sha256"], "0" * 64),
      (0, ["restore_modules"], {}),
      (0, ["restore_modules", PROOF.GUARD_MODULE], "0" * 64),
      (0, ["source_runtime", "modules", PROOF.GUARD_MODULE], "e" * 64),
      (0, ["restore_modules", "mba_hibernate_cold_pre_arch"], "e" * 64),
      (1, ["state"], "controlled-abort-return"),
      (1, ["state"], "transition-failed"),
      (1, ["cleanup_completed"], 1),
      (1, ["cleanup_errors"], ["wifi: failed"]),
      (1, ["consumed_guard_hex"], "00"),
      (1, ["consumed_attempt_hex"], "00"),
      (1, ["return_capture", "state"], "ordinary-boot"),
      (1, ["return_capture", "boot_id"], "33333333-3333-4333-8333-333333333333"),
      (1, ["return_capture", "efi_overrides", "LoaderEntryOneShot"], "restore"),
      (1, ["return_capture", "efi_overrides", "LoaderEntryDefault"], "source"),
      (1, ["return_capture", "pair_pins", "production_uki_sha256"], "0" * 64),
      (1, ["return_capture", "runtime_stack_sha256"], "0" * 64),
      (1, ["return_capture", "source_runtime", "modules", "t2bce_core"], "0" * 64),
      (1, ["return_capture", "restore_only_modules"], [PROOF.GUARD_MODULE]),
      (1, ["return_capture", "abort_modules"], ["mba_hibernate_cold_pre_cpu"]),
      (1, ["return_capture", "abort_witnesses"], ["MBPG"]),
      (1, ["return_capture", "context", "power_write_returned"], 1),
      (2, ["power_write_returned"], False),
      (2, ["power_write_returned"], 1),
      (2, ["power_path"], "/sys/power/pm_test"),
      (2, ["power_value"], "freeze"),
      (2, ["return_nonce"], "33333333-3333-4333-8333-333333333333"),
    ]
    for index, path, value in mutations:
      with self.subTest(index=index, path=path):
        values = fixture()
        set_path(values[index], path, value)
        with self.assertRaises(ValueError):
          PROOF.validate_source_return(*values[:3])

  def test_missing_fields_fail_closed(self):
    for index in range(3):
      for key in fixture()[index]:
        with self.subTest(index=index, missing=key):
          values = fixture()
          del values[index][key]
          with self.assertRaises(ValueError):
            PROOF.validate_source_return(*values[:3])

  def test_exact_raw_markers_and_selection(self):
    for name in fixture()[1]["return_capture"]["markers"]:
      for change in ("missing", "wrong-vector", "wrong-stage", "wrong-attributes", "truncated"):
        with self.subTest(marker=name, change=change):
          expected, observation, context, _ = fixture()
          markers = observation["return_capture"]["markers"]
          raw = bytearray.fromhex(markers[name])
          if change == "missing":
            del markers[name]
          else:
            if change == "wrong-vector":
              raw[8] ^= 1
            elif change == "wrong-stage":
              raw[-1] = 0
            elif change == "wrong-attributes":
              raw[0] = 6
            else:
              raw.pop()
            markers[name] = raw.hex()
          with self.assertRaises(ValueError):
            PROOF.validate_source_return(expected, observation, context)
    for entry in ("Omarchy.linux-t2", "MBA-T2-hibernation-source-" + "a" * 16):
      expected, observation, context, _ = fixture()
      observation["return_capture"]["LoaderEntrySelected_hex"] = (b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le")).hex()
      with self.assertRaises(ValueError):
        PROOF.validate_source_return(expected, observation, context)

  def test_consumed_attempt_fields_even_with_repinned_hash(self):
    for key, value in (("state", "returned"), ("state", "transition-failed"),
                       ("real_s4_attempted", 1), ("hibernate_attempted", False),
                       ("hardware_qualified", 0), ("requested_disk_mode", "shutdown"),
                       ("transition_vector", "0" * 64), ("boot_id", "3" * 36),
                       ("error", "source unwind"), ("cleanup_errors", ["failed"])):
      with self.subTest(key=key, value=value):
        expected, observation, context, _ = fixture()
        attempt = PROOF.decode_json(bytes.fromhex(observation["consumed_attempt_hex"]))
        attempt[key] = value
        raw = json.dumps(attempt).encode()
        observation["consumed_attempt_hex"] = raw.hex()
        expected["consumed_attempt_sha256"] = PROOF.digest(raw)
        with self.assertRaises(ValueError):
          PROOF.validate_source_return(expected, observation, context)

  def test_health_is_independent_and_exactly_typed(self):
    for path, value in ((["after_cleanup"], False), (["after_cleanup"], 1),
                         (["failed_units"], ["bolt.service"]), (["devices", "internal_keyboard"], False),
                         (["devices", "internal_trackpad"], 1), (["services", "sddm.service"], "failed"),
                         (["pm", "pm_test"], "devices"), (["pm", "pm_trace"], "1"),
                         (["pm", "resume_offset"], True), (["return_nonce"], "0" * 36)):
      with self.subTest(path=path):
        expected, observation, context, health = fixture()
        set_path(health, path, value)
        PROOF.validate_source_return(expected, observation, context)
        with self.assertRaises(ValueError):
          PROOF.validate_post_cleanup(expected, observation, context, health)

  def test_duplicate_json_and_historical_mbpg_are_rejected(self):
    with self.assertRaises(ValueError):
      PROOF.decode_json('{"state":"returned","state":"transition-armed"}')
    expected, observation, context, _ = fixture()
    observation["return_capture"]["markers"]["OmarchyT2ColdPciPreArchReturned-" + PROOF.GUID] = "00"
    with self.assertRaises(ValueError):
      PROOF.validate_source_return(expected, observation, context)


if __name__ == "__main__":
  unittest.main()
