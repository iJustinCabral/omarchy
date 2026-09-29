#!/usr/bin/env python3
"""Check mailbox channel pause/resume pairing and the refusal after a skipped resume."""

from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from t2bce_pm_harness import COMMON_RESET, compile_and_run, function, harness

assert len(sys.argv) == 2, "usage: test-mailbox-channel-pairing.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1]) / "drivers/staging/t2bce/t2bce_core"
core = (root / "t2bce_main.c").read_text()
header = (root / "t2bce.h").read_text()

assert "bool resume_skipped;" in header
pause = function(core, "bce_pm_channel_pause", "int")
resume = function(core, "bce_pm_channel_resume", "void")
assert pause.index("mailbox_channel_active") < pause.index("bce_mailbox_channel_pause")
assert resume.index("mailbox_channel_active") < resume.index("bce_mailbox_channel_resume")

# The wrappers latch resume_skipped on every early -EIO; resume_mode clears it under pm_lock;
# suspend_common refuses before it touches clients, the engine or the channel.
for name in ("t2bce_resume_with_shared_dma", "t2bce_restore"):
  body = function(core, name, "int")
  assert re.search(r"pci_dma_restore_failed\) \{\n\s+bce->resume_skipped = true;\n\s+return -EIO;", body), name
mode = function(core, "t2bce_resume_mode", "int")
assert mode.index("mutex_lock(&bce->pm_lock)") < mode.index("resume_skipped = false")
common = function(core, "t2bce_suspend_common", "int")
assert common.index("mutex_lock(&bce->pm_lock)") < common.index("bce->resume_skipped") < common.index("clients_pm_reset")
assert common.index("bce->resume_skipped") < common.index("bce_pm_suspend_prepare")
# t2bce_shutdown only pauses a channel that is not already held.
shutdown = function(core, "t2bce_shutdown", "void")
assert "if (bce->mailbox_channel_active)" in shutdown and "bce_pm_channel_pause" in shutdown

body = COMMON_RESET + r'''
int main(void) {
  struct t2bce_device bce;
  struct device dev = { .bce = &bce };
  int status;

  /* Pause and resume are idempotent and never double-lock or double-unlock. */
  reset(&bce);
  assert(bce_pm_channel_pause(&bce) == 0);
  assert(!bce.mailbox_channel_active && bce.mbox.channel_lock.locked);
  assert(bce_pm_channel_pause(&bce) == 0);         /* second pause: no second lock */
  assert(bce.mbox.channel_lock.locked);
  bce_pm_channel_resume(&bce);
  assert(bce.mailbox_channel_active && !bce.mbox.channel_lock.locked);
  bce_pm_channel_resume(&bce);                      /* second resume: no unlock of a free mutex */
  assert(!bce.mbox.channel_lock.locked);

  /* A pause whose mailbox never drains releases the lock and leaves the channel active. */
  reset(&bce);
  bce.mbox.mb_status = 1;
  assert(bce_pm_channel_pause(&bce) == -ETIMEDOUT);
  assert(bce.mailbox_channel_active && !bce.mbox.channel_lock.locked);
  bce_pm_channel_resume(&bce);
  assert(!bce.mbox.channel_lock.locked);

  /* Failed thaw after a hibernation freeze: the freeze holds the channel and the interrupt gate. */
  reset(&bce);
  status = t2bce_suspend_common(&dev, true);        /* .freeze */
  assert(status == 0 && bce.mbox.channel_lock.locked && !bce.mailbox_channel_active);
  assert(irq_disables == 1 && bce.no_state_queues_dropped && bce.dma.cmd_cmdq == NULL);
  bce.pci_dma_restore_failed = true;
  status = t2bce_resume_with_shared_dma(&dev);      /* .thaw refused by the noirq latch */
  assert(status == -EIO && bce.resume_skipped && resume_calls == 0);
  assert(bce.mbox.channel_lock.locked);             /* still held: the resume never ran */
  clients_prepare = 0;
  int resets = clients_reset;
  status = t2bce_suspend_common(&dev, true);        /* .poweroff must neither lock again nor quiesce */
  assert(status == -EBUSY);
  assert(clients_prepare == 0 && clients_reset == resets);
  assert(bce.mbox.channel_lock.locked && !bce.pm_lock.locked);
  assert(irq_disables == 1);                        /* not disabled a second time */

  /* The refusal does not depend on the command queue being absent, and the pause is safe anyway. */
  {
    static struct bce_cmdq cmdq;
    bce.dma.cmd_cmdq = &cmdq;
    assert(bce_pm_channel_pause(&bce) == 0);        /* would deadlock without the guard */
    assert(t2bce_suspend_common(&dev, true) == -EBUSY);
  }

  /* The image-restore wrapper is not part of the harness; ordinary S3 never sets the flag. */
  reset(&bce);
  assert(t2bce_suspend_common(&dev, false) == 0);
  assert(!bce.resume_skipped);
  return 0;
}
'''
compile_and_run(harness(core, body), "channel-pairing")
print("PASS: mailbox channel pairing is idempotent and a skipped resume refuses a second freeze")
