#!/usr/bin/env python3
"""Verify that prepared AVE has no BCE queue graph to reconstruct."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile


assert len(sys.argv) == 2, "usage: test-ave-hibernation-idle.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1])
ave = (root / "drivers/staging/t2bce/t2bce_ave/ave.c").read_text()
video = (root / "drivers/staging/t2bce/t2bce_ave/video.c").read_text()
encoder = (root / "drivers/staging/t2bce/t2bce_ave/encoder.c").read_text()


def function(source, name, return_type):
  match = re.search(r"(?:static )?" + return_type + r" " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


prepare = function(ave, "t2bce_ave_pm_prepare", "int")
drop = function(ave, "t2bce_ave_pm_drop_no_state_queues", "void")
rebuild = function(ave, "t2bce_ave_pm_rebuild_no_state_queues", "int")
video_suspend = function(video, "t2bce_ave_video_suspend", "void")
session_teardown = function(video, "t2bce_ave_shutdown_session", "bool")
session_setup = function(encoder, "t2bce_ave_session_setup", "int")

assert "t2bce_ave_video_suspend(ave->video);" in prepare
assert "t2bce_ave_shutdown_session(adev)" in video_suspend
assert session_teardown.index("t2bce_ave_session_teardown") < session_teardown.index("adev->session = NULL")
assert "t2bce_ave_queues_create(bce, &session->queues)" in session_setup
assert encoder.count("t2bce_ave_queues_create(") == 1
assert "t2bce_ave_queues_destroy(&session->queues);" in encoder
assert ".pm_drop_no_state_queues = t2bce_ave_pm_drop_no_state_queues" in ave
assert ".pm_rebuild_no_state_queues = t2bce_ave_pm_rebuild_no_state_queues" in ave

harness = r'''
#include <assert.h>

struct t2bce_ave_device { int session_active; };
struct t2bce_ave_module { struct t2bce_ave_device *video; };

static void t2bce_ave_video_suspend(struct t2bce_ave_device *video)
{
  video->session_active = 0;
}
'''
harness += prepare + drop + rebuild
harness += r'''
int main(void)
{
  struct t2bce_ave_device video = { .session_active = 1 };
  struct t2bce_ave_module ave = { .video = &video };

  assert(t2bce_ave_pm_prepare(&ave) == 0);
  assert(!video.session_active);
  t2bce_ave_pm_drop_no_state_queues(&ave);
  assert(t2bce_ave_pm_rebuild_no_state_queues(&ave) == 0);
  assert(!video.session_active);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-ave-hibernate-") as directory:
  source = Path(directory) / "ave-hibernation-idle.c"
  binary = Path(directory) / "ave-hibernation-idle"
  source.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
  subprocess.run([str(binary)], check=True)

print("PASS: prepared AVE owns no BCE queues and does not block hibernation rebuild")
