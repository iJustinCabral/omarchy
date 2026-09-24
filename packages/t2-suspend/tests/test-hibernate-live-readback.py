#!/usr/bin/python3
"""Check one-use live readback transaction without touching host power or swap."""

import importlib.util
from pathlib import Path


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-readback-ftrace/run-live-readback.py"
spec = importlib.util.spec_from_file_location("t2_live_readback", script)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

try:
  probe.execute()
except ValueError as error:
  assert "operator at the power button" in str(error)
else:
  raise AssertionError("Live image-I/O execution accepted without an operator gate")

source = script.read_text()
prepare = source.split("def prepare():", 1)[1].split("\ndef validate_armed():", 1)[0]
validate = source.split("def validate_armed():", 1)[1].split("\ndef require_hooks():", 1)[0]
execute = source.split("def execute(", 1)[1].split("\ndef main():", 1)[0]

assert prepare.index("evidence = validate_stock()") < prepare.index('STATE.mkdir(mode=0o700)')
assert prepare.index('"prepare-intent.json"') < prepare.index('"mkswapfile"')
assert prepare.index('"mkswapfile"') < prepare.index('"armed.json"')
assert 'alternate == STOCK_OFFSET' in prepare
assert 'str(SWAP_FILE) in active_swap_paths()' in validate
assert '(STATE / "pm-attempted.json").exists()' in validate
assert 'arm.get("alternate_offset") != swap_offset(SWAP_FILE)' in validate
assert execute.index("arm = validate_armed()") < execute.index('"pm-attempted.json"')
assert execute.index('"pm-attempted.json"') < execute.index('command("swapon"')
assert execute.index('command("swapon"') < execute.index('expected_marker(arm, 0)')
assert execute.index('expected_marker(arm, 0)') < execute.index('command("insmod", str(MARKER_MODULE))')
assert execute.index('command("insmod", str(ABORT_MODULE))') < execute.index('require_hooks()')
assert execute.index('"arm_vector").write_text') < execute.index('"armed").write_text("Y\\n")')
assert execute.index('"armed").write_text("Y\\n")') < execute.index('write_resume_offset(arm["alternate_offset"])')
assert execute.index('"pm-enter-intent.json"') < execute.index('completed = subprocess.run(command_line')
assert '"--bluetooth-off",' in execute and '"--wifi-unbind"' in execute
assert 'result["observed_stage"] == 2' in execute
assert 'result["interceptions"] == 1' in execute
assert 'stock_after["page_sha256"] == arm["stock_header"]["page_sha256"]' in execute
assert execute.index('write_resume_offset(STOCK_OFFSET)') < execute.index('command("swapoff", str(SWAP_FILE))')
assert 'if alternate_signature == "normal-swap-signature":' in execute
assert '"alternate_swap_active": str(SWAP_FILE) in active_swap_paths()' in execute

print("PASS: separate swap readback runner guards one-use PM entry and restores the stock offset")
