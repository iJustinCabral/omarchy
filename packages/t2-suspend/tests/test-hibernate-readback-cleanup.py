#!/usr/bin/python3
"""Check exact stock-return cleanup ordering without modifying host state."""

from pathlib import Path


script = Path(__file__).resolve().parents[1] / "experiments/hibernate-readback-ftrace/cleanup-after-stock-reboot.py"
source = script.read_text()
state = source.split("def exact_state():", 1)[1].split("\ndef current_stock():", 1)[0]
stock = source.split("def current_stock():", 1)[1].split("\ndef require_marker(", 1)[0]
intent = source.split("def mark_reboot_intent():", 1)[1].split("\ndef validate_return():", 1)[0]
returned = source.split("def validate_return():", 1)[1].split("\ndef record_return():", 1)[0]
cleanup = source.split("def cleanup_return():", 1)[1].split("\ndef main():", 1)[0]

for name in ("prepare-intent.json", "armed.json", "pm-attempted.json", "pm-enter-intent.json", "result.json", "cleanup.json"):
  assert name in source
assert 'COMMON.sha256_file(STATE / name) != expected' in state
assert 'result.get("success") is not True' in state
assert 'result.get("interceptions") != 1' in state
assert '"timed out after 60 seconds" not in cleanup["errors"][0]' in state
assert 'COMMON.require_live_stock(root, allow_stage_marker=True)' in stock
assert 'COMMON.require_live_arm_preflight(root)' in stock
assert 'HEADER.read_header(RUNNER.DEVICE, RUNNER.STOCK_OFFSET)["page_sha256"] != STOCK_HEADER_SHA256' in stock
assert 'alternate = HEADER.read_header(RUNNER.DEVICE, ALT_OFFSET)' in stock
assert 'alternate["page_sha256"] != RETURN_ALT_HEADER_SHA256' in stock
assert 'alternate["flags"] != 4' in stock
assert 'alternate["first_map_page"] != RETURN_ALT_FIRST_MAP_PAGE' in stock
assert 'RUNNER.swap_offset(RUNNER.SWAP_FILE) != ALT_OFFSET' in stock
assert intent.index('current = current_stock()') < intent.index('"reboot-intent.json"')
assert 'current != SOURCE_BOOT' in intent
assert 'current == SOURCE_BOOT' in returned
assert 'str(RUNNER.SWAP_FILE) in RUNNER.active_swap_paths()' in returned
assert 'str(RUNNER.SWAP_FILE) in Path("/etc/fstab").read_text()' in returned
assert 'value = require_marker(arm)' in returned
assert cleanup.index('observed = validate_return()') < cleanup.index('"clear-intent.json"')
assert cleanup.index('"clear-intent.json"') < cleanup.index('variable.unlink()')
assert cleanup.index('"marker-cleared.json"') < cleanup.index('RUNNER.SWAP_FILE.unlink()')
assert cleanup.index('str(RUNNER.SWAP_FILE) in RUNNER.active_swap_paths()') < cleanup.index('RUNNER.SWAP_FILE.unlink()')
assert '"swapfile-removed.json"' in cleanup

print("PASS: exact stock-return cleanup preserves terminal PM evidence and checks inactive swap")
