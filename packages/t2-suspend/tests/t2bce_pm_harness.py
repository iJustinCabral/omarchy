"""Shared C model of the t2bce_core suspend prologue for the offline PM regression tests.

The real functions are extracted from the patched t2bce_main.c and compiled against
stubs: bce_dma_engine_disable, bce_dma_engine_enable, bce_pm_wait_mailbox_idle,
bce_pm_channel_pause, bce_pm_channel_resume, bce_pm_suspend_prepare,
bce_pm_suspend_abort, bce_pm_suspend_no_state_fallback, t2bce_suspend_common and
t2bce_resume_with_shared_dma.  Mutexes are non-recursive: taking a held mutex
fails an assertion, which models the deadlock; releasing a free one does too.
"""

from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name, return_type="int", static=True):
  prefix = "static " if static else ""
  match = re.search(prefix + return_type + " " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


C_PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
typedef uint16_t u16;
typedef uint64_t u64;
typedef uint32_t u32;

struct mutex { int locked; };
static void mutex_lock(struct mutex *m) { assert(!m->locked && "mutex taken twice: deadlock"); m->locked = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->locked && "mutex released while free"); m->locked = 0; }
static void usleep_range(int a, int b) { (void)a; (void)b; }
#define atomic_read(p) (*(p))

struct bce_queue_sq { int dummy; };
struct bce_cmdq { int dummy; };
struct t2bce_dma_engine {
  struct bce_cmdq *cmd_cmdq;
  int available;
};
struct bce_mailbox { struct mutex channel_lock; int mb_status; };
struct bce_xhci_pm { int dummy; };
struct t2bce_device {
  struct t2bce_dma_engine dma;
  struct bce_mailbox mbox;
  struct bce_xhci_pm xhci_pm;
  struct mutex pm_lock, dma_completion_lock;
  bool mailbox_channel_active;
  bool stateful_suspend_valid, no_state_fallback, no_state_resume, no_state_rebuild_failed;
  bool no_state_early_wake_attempted, no_state_queues_dropped;
  bool pci_dma_restore_failed, resume_skipped;
  int no_state_early_wake_status;
};
struct device { struct t2bce_device *bce; };
struct pci_dev { struct t2bce_device *bce; };

/* Instrumentation. */
static int wait_calls, wait_fail_from;   /* fail idle wait from this call number on (0: never) */
static int completions_processed, xhci_stops, xhci_starts, irq_enables, irq_disables;
static int clients_prepare, clients_abort, clients_reset, fallback_sends, resume_calls;
static int clients_prepare_status;

static void t2bce_dma_disable(struct t2bce_dma_engine *dma) { dma->available = 0; }
static void t2bce_dma_enable(struct t2bce_dma_engine *dma) { dma->available = 1; }
static int t2bce_dma_wait_command_queue_idle(struct t2bce_dma_engine *dma) {
  (void)dma;
  wait_calls++;
  if (wait_fail_from && wait_calls >= wait_fail_from)
    return -ETIMEDOUT;
  return 0;
}
static void bce_process_dma_completions_locked(struct t2bce_device *bce) { (void)bce; completions_processed++; }
static void bce_process_dma_completions(struct t2bce_device *bce) {
  mutex_lock(&bce->dma_completion_lock);
  completions_processed++;
  mutex_unlock(&bce->dma_completion_lock);
}
static int bce_mailbox_channel_pause(struct bce_mailbox *mb) { mutex_lock(&mb->channel_lock); return 0; }
static void bce_mailbox_channel_resume(struct bce_mailbox *mb) { mutex_unlock(&mb->channel_lock); }
static void bce_xhci_pm_stop(struct bce_xhci_pm *pm) { (void)pm; xhci_stops++; }
static void bce_xhci_pm_start(struct bce_xhci_pm *pm, bool cold) { (void)pm; (void)cold; xhci_starts++; }
static void bce_dma_irq_enable(struct t2bce_device *bce) { (void)bce; irq_enables++; }
static void bce_dma_irq_disable(struct t2bce_device *bce) { (void)bce; irq_disables++; }
static void t2bce_core_clients_pm_reset(struct t2bce_device *bce) { (void)bce; clients_reset++; }
static int t2bce_core_clients_pm_prepare(struct t2bce_device *bce) { (void)bce; clients_prepare++; return clients_prepare_status; }
static void t2bce_core_clients_pm_abort(struct t2bce_device *bce) { (void)bce; clients_abort++; }
static bool t2bce_core_clients_pm_can_rebuild_no_state(struct t2bce_device *bce) { (void)bce; return true; }
static void t2bce_core_clients_pm_mark_no_state_resume(struct t2bce_device *bce) { (void)bce; }
static int t2bce_core_clients_pm_prepare_no_state(struct t2bce_device *bce) { (void)bce; return 0; }
static bool bce_stateful_supported(struct t2bce_device *bce) { (void)bce; return false; }
static int bce_pm_suspend_try_state(struct t2bce_device *bce) { (void)bce; return -EIO; }
static int bce_pm_suspend_fallback_no_state(struct t2bce_device *bce) { (void)bce; fallback_sends++; return 0; }
static int bce_pm_block_queue_dma(struct t2bce_device *bce) { (void)bce; return 0; }
static void bce_pm_drop_no_state_queue_graph(struct t2bce_device *bce) {
  bce->dma.cmd_cmdq = NULL;
  bce->no_state_queues_dropped = true;
}
static void t2bce_block_shared_dma(struct t2bce_device *bce) { (void)bce; }
static struct t2bce_device *pci_get_drvdata(struct pci_dev *p) { return p->bce; }
static struct pci_dev *to_pci_dev(struct device *d) { static struct pci_dev p; p.bce = d->bce; return &p; }
static int t2bce_restore_shared_dma(struct t2bce_device *bce) { (void)bce; return 0; }
static int t2bce_resume(struct device *dev) { (void)dev; resume_calls++; return 0; }
'''

FUNCTIONS = (
  ("bce_dma_engine_disable", "int"),
  ("bce_dma_engine_enable", "void"),
  ("bce_pm_wait_mailbox_idle", "int"),
  ("bce_pm_channel_pause", "int"),
  ("bce_pm_channel_resume", "void"),
  ("bce_pm_suspend_prepare", "int"),
  ("bce_pm_suspend_abort", "void"),
  ("bce_pm_suspend_no_state_fallback", "int"),
  ("t2bce_suspend_common", "int"),
  ("t2bce_resume_with_shared_dma", "int"),
)


def harness(core_source, body):
  """Return C source: prelude, the real extracted functions, then BODY."""
  real = "".join(function(core_source, name, ret) for name, ret in FUNCTIONS)
  return C_PRELUDE + real + body


COMMON_RESET = r'''
static void reset(struct t2bce_device *bce) {
  memset(bce, 0, sizeof(*bce));
  static struct bce_cmdq cmdq;
  bce->dma.cmd_cmdq = &cmdq;
  bce->dma.available = 1;
  bce->mailbox_channel_active = true;
  wait_calls = wait_fail_from = 0;
  completions_processed = xhci_stops = xhci_starts = irq_enables = irq_disables = 0;
  clients_prepare = clients_abort = clients_reset = fallback_sends = resume_calls = 0;
  clients_prepare_status = 0;
}
'''


def compile_and_run(source, name):
  with tempfile.TemporaryDirectory() as directory:
    c_file = Path(directory) / (name + ".c")
    binary = Path(directory) / name
    c_file.write_text(source)
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", str(c_file), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
