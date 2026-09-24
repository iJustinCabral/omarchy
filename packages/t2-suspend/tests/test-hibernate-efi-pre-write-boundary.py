#!/usr/bin/python3
"""Check the one-use EFI plus pre-write-abort boundary without host PM."""

import hashlib
import importlib.util
from pathlib import Path


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
execute = source.split("def execute_live(", 1)[1].split("\ndef main():", 1)[0]
assert execute.index('"pm-attempted.json"') < execute.index('subprocess.run(["insmod", str(MARKER_MODULE)]')
assert execute.index('str(MARKER_MODULE)]') < execute.index('str(ABORT_MODULE)]')
assert execute.index('"arm_vector").write_text') < execute.index('"armed").write_text("Y\\n")')
assert execute.index('"armed").write_text("Y\\n")') < execute.index("completed = subprocess.run(command")
assert '"--bluetooth-off", "--wifi-unbind"' in execute
assert 'count == 1' in execute and 'stage == 2' in execute
assert 'after["page_sha256"] == arm["swap_header_before"]["page_sha256"]' in execute

print("PASS: EFI/pre-write boundary identity, guard ordering and controlled-abort contract")
