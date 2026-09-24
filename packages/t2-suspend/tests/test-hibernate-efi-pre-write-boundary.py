#!/usr/bin/python3
"""Check the one-use EFI plus pre-write-abort boundary without host PM."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-pre-write-ftrace/run-efi-boundary.py"
spec = importlib.util.spec_from_file_location("t2_efi_pre_write_boundary", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

vector = "a" * 64
arm = {
  "kind": probe.KIND,
  "boot_id": "11111111-2222-3333-4444-555555555555",
  "vector": vector,
  "marker_module_sha256": probe.MARKER_SHA256,
  "abort_module_sha256": probe.ABORT_SHA256,
}
for stage in range(3):
  value = probe.MARKER.ATTRIBUTES + probe.MARKER.payload(vector, stage)
  arm[f"stage{stage}_sha256"] = hashlib.sha256(value).hexdigest()
  assert probe.expected(arm, stage) == value
  assert probe.MARKER.decode(value, vector) == stage


def refused(action, message):
  try:
    action()
  except (OSError, RuntimeError, ValueError) as error:
    assert message in str(error), str(error)
  else:
    raise AssertionError("Unsafe boundary operation was accepted")


refused(lambda: probe.execute_live(), "operator at the power button")
refused(lambda: probe.expected({**arm, "vector": "b" * 64}, 0), "stage digest differs")
refused(lambda: probe.expected({**arm, "marker_module_sha256": "0" * 64}, 0), "identity differs")
refused(lambda: probe.expected({**arm, "stage2_sha256": "0" * 64}, 2), "stage digest differs")

source = script.read_text()
armed_validation = source.split("def validate_armed_live():", 1)[1].split("\ndef execute_live(", 1)[0]
execute = source.split("def execute_live(", 1)[1].split("\ndef main():", 1)[0]
assert 'allow_stage_marker=True' in armed_validation
assert 'arm["head"] != PREPARED_HEAD' in armed_validation
assert armed_validation.index('COMMON.read_regular(MARKER.marker_path(root)) != expected(arm, 0)') < armed_validation.index('"pm-attempted.json"')
assert 'arm = validate_armed_live()' in execute
assert execute.index('"pm-attempted.json"') < execute.index('subprocess.run(["insmod", str(MARKER_MODULE)]')
assert execute.index('str(MARKER_MODULE)]') < execute.index('str(ABORT_MODULE)]')
assert execute.index('"arm_vector").write_text') < execute.index('"armed").write_text("Y\\n")')
assert execute.index('"armed").write_text("Y\\n")') < execute.index("completed = subprocess.run(command")
assert '"--bluetooth-off", "--wifi-unbind"' in execute
assert 'count == 1' in execute and 'stage == 2' in execute
assert 'after["page_sha256"] == arm["swap_header_before"]["page_sha256"]' in execute

with tempfile.TemporaryDirectory(prefix="t2-efi-prewrite-clear-") as temporary:
  root = Path(temporary)
  boot_id = root / "proc/sys/kernel/random/boot_id"
  boot_id.parent.mkdir(parents=True)
  boot_id.write_text(arm["boot_id"] + "\n")
  state = root / probe.STATE
  state.mkdir(parents=True)
  armed = {**arm, "head": probe.PREPARED_HEAD, "swap_header_before": {"page_sha256": "c" * 64}}
  (state / "armed.json").write_text(json.dumps(armed))
  (state / "pm-attempted.json").write_text(json.dumps({
    "kind": probe.KIND + "-pm-attempted", "boot_id": arm["boot_id"], "vector": vector,
    "marker_module_sha256": probe.MARKER_SHA256, "abort_module_sha256": probe.ABORT_SHA256,
  }))
  result = {
    "kind": probe.KIND + "-result", "boot_id": arm["boot_id"], "vector": vector,
    "success": False, "observed_stage": 2, "efi_status": "0", "interceptions": 1,
    "swap_header_after": {"page_sha256": "c" * 64},
  }
  (state / "result.json").write_text(json.dumps(result))
  (state / "cleanup.json").write_text(json.dumps({
    "kind": probe.KIND + "-cleanup", "boot_id": arm["boot_id"],
    "abort_module_unloaded": True, "marker_module_unloaded": True, "errors": [],
  }))
  variable = probe.MARKER.marker_path(root)
  variable.parent.mkdir(parents=True)
  variable.write_bytes(probe.expected(armed, 2))
  refused(lambda: probe.clear_success(root), "Only the exact returned-and-cleaned")
  assert variable.exists() and not (state / "clear-intent.json").exists()
  result["success"] = True
  (state / "result.json").write_text(json.dumps(result))
  assert probe.clear_success(root) is True
  assert not variable.exists()
  assert json.loads((state / "clear-intent.json").read_text())["stage2_value_hex"] == probe.expected(armed, 2).hex()
  assert json.loads((state / "cleared.json").read_text())["stage2_sha256"] == arm["stage2_sha256"]
  assert (state / "pm-attempted.json").exists()
  refused(lambda: probe.clear_success(root), "EFI stage-2 marker differs")

print("PASS: EFI/pre-write boundary identity, guard ordering and controlled-abort contract")
