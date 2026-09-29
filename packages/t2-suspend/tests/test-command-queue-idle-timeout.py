#!/usr/bin/env python3
"""Check the bounded command-queue idle wait and its propagation, without loading modules."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from t2bce_pm_harness import COMMON_RESET, compile_and_run, function, harness

assert len(sys.argv) == 2, "usage: test-command-queue-idle-timeout.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1]) / "drivers/staging/t2bce"
core = (root / "t2bce_core/t2bce_main.c").read_text()
queue = (root / "t2bce_dma/queue.c").read_text()
header = (root / "t2bce_dma/include/t2bce_dma_queue.h").read_text()

# The wait itself: bounded, non-void, declared to match.
wait_source = function(queue, "t2bce_dma_wait_command_queue_idle", "int", static=False)
assert re.search(r"\bwait_event_timeout\(", wait_source), "idle wait must be timed"
assert not re.search(r"\bwait_event\(", wait_source), "untimed wait_event is forbidden"
assert "-ETIMEDOUT" in wait_source
assert "int t2bce_dma_wait_command_queue_idle(struct t2bce_dma_engine *dma);" in header
timeout_ms = int(re.search(r"#define T2BCE_DMA_IDLE_TIMEOUT_MS (\d+)", header).group(1))
assert 1000 <= timeout_ms <= 10000, timeout_ms

# Every consumer of the wait, and of each layer above it, checks the result.
consumers = []
for path in sorted(root.rglob("*.c")):
  for match in re.finditer(r"t2bce_dma_wait_command_queue_idle\(", path.read_text()):
    consumers.append(path.name)
assert sorted(consumers) == ["queue.c", "t2bce_main.c"], consumers  # definition plus one caller
disable = function(core, "bce_dma_engine_disable", "int")
assert "return t2bce_dma_wait_command_queue_idle(&bce->dma);" in disable
assert not re.search(r"static void bce_dma_engine_disable", core)
assert len(re.findall(r"bce_dma_engine_disable\(bce\)", core)) == 1
prepare = function(core, "bce_pm_suspend_prepare", "int")
assert "status = bce_dma_engine_disable(bce);" in prepare
assert prepare.index("bce_dma_engine_disable") < prepare.index("bce_pm_channel_pause")
callers = re.findall(r"^\s*(?:status = )?bce_pm_suspend_prepare\(bce\)", core, re.M)
assert len(callers) == 2 and all("status = " in call for call in callers), callers

wait_harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
typedef unsigned long jiffies_t;
#define T2BCE_DMA_IDLE_TIMEOUT_MS ''' + str(timeout_ms) + r'''
#define pr_err(...) ((void)0)
#define msecs_to_jiffies(ms) ((jiffies_t)(ms))
struct wq { int dummy; };
struct bce_queue_sq { struct wq idle_wait; int available_commands; int el_count; };
struct bce_cmdq { struct bce_queue_sq *sq; };
struct t2bce_dma_engine { struct bce_cmdq *cmd_cmdq; };
#define atomic_read(p) (*(p))
static jiffies_t last_timeout;
static int waits;
/* Timed wait: evaluates the condition once; a false condition models the timeout expiring. */
#define wait_event_timeout(wq, cond, timeout) ({ waits++; last_timeout = (timeout); (cond) ? 1L : 0L; })
''' + wait_source + r'''
int main(void) {
  struct bce_queue_sq sq = { .available_commands = 31, .el_count = 32 };
  struct bce_cmdq cmdq = { .sq = &sq };
  struct t2bce_dma_engine dma = { .cmd_cmdq = &cmdq };
  assert(t2bce_dma_wait_command_queue_idle(&dma) == 0);
  assert(last_timeout == T2BCE_DMA_IDLE_TIMEOUT_MS);
  sq.available_commands = 30; /* one command never completed */
  assert(t2bce_dma_wait_command_queue_idle(&dma) == -ETIMEDOUT);
  assert(waits == 2);
  return 0;
}
'''
compile_and_run(wait_harness, "idle-wait")

prop_body = COMMON_RESET + r'''
static void assert_running_state(struct t2bce_device *bce) {
  assert(bce->dma.available == 1);            /* submission gate reopened */
  assert(bce->mailbox_channel_active);         /* channel not left paused */
  assert(!bce->mbox.channel_lock.locked);
  assert(!bce->pm_lock.locked && !bce->dma_completion_lock.locked);
  assert(irq_disables == 0);                   /* interrupt never disabled after a failed suspend */
  assert(!bce->stateful_suspend_valid);
}

int main(void) {
  struct t2bce_device bce;
  struct device dev = { .bce = &bce };
  int status;

  /* Success: the gate stays closed, the channel is held, the interrupt is disabled. */
  reset(&bce);
  status = t2bce_suspend_common(&dev, true);
  assert(status == 0);
  assert(bce.dma.available == 0 && !bce.mailbox_channel_active && bce.mbox.channel_lock.locked);
  assert(xhci_stops == 2 && irq_disables == 1 && wait_calls == 2);
  assert(!bce.pm_lock.locked && bce.no_state_queues_dropped);

  /* Timeout on the first quiesce (ordinary or hibernation suspend before the fallback). */
  reset(&bce);
  wait_fail_from = 1;
  status = t2bce_suspend_common(&dev, false);
  assert(status == -ETIMEDOUT);
  assert(wait_calls == 1 && xhci_stops == 0);
  assert(clients_prepare == 1 && clients_abort == 1);
  assert(completions_processed >= 1);         /* visible completions were reaped */
  assert_running_state(&bce);

  /* Timeout on the second quiesce, after the fallback already reopened the transport once. */
  reset(&bce);
  wait_fail_from = 2;
  status = t2bce_suspend_common(&dev, true);
  assert(status == -ETIMEDOUT);
  assert(wait_calls == 2 && fallback_sends == 0);
  assert(clients_abort == 1);
  assert(irq_enables >= 1 && xhci_starts >= 1);
  assert_running_state(&bce);

  /* The same failure is not sticky: a later suspend succeeds. */
  wait_fail_from = 0;
  status = t2bce_suspend_common(&dev, true);
  assert(status == 0 && bce.mbox.channel_lock.locked);
  return 0;
}
'''
compile_and_run(harness(core, prop_body), "idle-propagation")
print("PASS: command-queue idle wait is bounded and its failure unwinds freeze and suspend")
