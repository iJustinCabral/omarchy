#!/usr/bin/python3
"""Check RTC marker stage mapping without loading a module or changing time."""

import importlib.util
from pathlib import Path


directory = Path(__file__).resolve().parents[1] / "experiments/hibernate-rtc-stage-marker"
source = (directory / "mba_hibernate_rtc_stage_marker.c").read_text()
spec = importlib.util.spec_from_file_location("hibernate_rtc_stage_marker", directory / "marker.py")
marker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(marker)

assert marker.file_hash() == 928
for number, function in enumerate(("hibernate", "swsusp_write", "hibernation_platform_enter", "acpi_hibernation_enter"), 1):
  assert '{ .function = "' + function + '", .value = ' + str(number) + ' }' in source
  result = marker.decode(f"{number}:928:42")
  assert result["recognized"] is True
  assert result["stage"] == marker.STAGES[number]
assert marker.decode("0:928:42")["stage"] == "armed-before-hibernate"
assert marker.magic_from_rtc("2048-05-13", "00:00:01") == "0:928:0"
for value in range(5):
  encoded = value + 16 * (928 + 997 * 42)
  year = encoded % 100
  encoded //= 100
  month = encoded % 12 + 1
  encoded //= 12
  day = encoded % 28 + 1
  encoded //= 28
  hour = encoded % 24
  encoded //= 24
  minute = encoded * 3
  assert marker.magic_from_rtc(f"20{year:02d}-{month:02d}-{day:02d}", f"{hour:02d}:{minute:02d}:00") == f"{value}:928:42"
for magic in ("2:927:42", "5:928:42", "2:928:1009"):
  assert marker.decode(magic)["recognized"] is False
for magic in ("", "2:928", "2:928:-1", "two:928:42"):
  try:
    marker.decode(magic)
  except ValueError:
    pass
  else:
    raise AssertionError("Malformed PM trace magic accepted: " + repr(magic))
for date, time in (("2026-09-23", "22:44:00"), ("2026-09-29", "22:45:00"), ("2026-09-23", "22:45")):
  try:
    marker.magic_from_rtc(date, time)
  except ValueError:
    pass
  else:
    raise AssertionError("Unencoded RTC value accepted: " + date + " " + time)

assert "if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) || READ_ONCE(stage))" in source
assert "generate_pm_trace(&trace_data, 0);" in source
assert "generate_pm_trace(&trace_data, next);" in source
assert "error = mc146818_get_time(&rtc_time, 1000);" in source
assert "error = rtc_valid_tm(&rtc_time);" in source
assert "rtc_seconds < system_seconds - 120 || rtc_seconds > system_seconds + 120" in source
assert source.index("rtc_seconds < system_seconds - 120") < source.index("WRITE_ONCE(pm_trace_rtc_abused, false);")
assert "FTRACE_OPS_FL_IPMODIFY" not in source
assert "ftrace_regs_set_instruction_pointer" not in source
print("PASS: stock-kernel RTC marker maps ordered stages without changing hibernation control flow")
