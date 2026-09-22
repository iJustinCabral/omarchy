#!/usr/bin/env python3
"""Exercise the offline BCE cold-S4 queue reconstruction candidate."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 2, "usage: test-cold-s4-rebuild.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1])
core = (root / "drivers/staging/t2bce/t2bce_core/t2bce_main.c").read_text()
transport_h = (root / "drivers/staging/t2bce/t2bce_core/include/t2bce_core_transport.h").read_text()
transport_c = (root / "drivers/staging/t2bce/t2bce_core/transport.c").read_text()
vhci = (root / "drivers/staging/t2bce/t2bce_vhci/vhci.c").read_text()
vhci_queue = (root / "drivers/staging/t2bce/t2bce_vhci/queue.c").read_text()
audio = (root / "drivers/staging/t2bce/t2bce_audio/audio.c").read_text()
audio_bce = (root / "drivers/staging/t2bce/t2bce_audio/protocol_bce.c").read_text()


def function(source, name, return_type="int"):
  match = re.search(r"(?:static )?" + return_type + r" " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


restore_queue_dma = function(core, "bce_pm_restore_queue_dma", "void")
block_queue_dma = function(core, "bce_pm_block_queue_dma")
drop_graph = function(core, "bce_pm_drop_no_state_queue_graph", "void")
rebuild_graph = function(core, "bce_pm_rebuild_no_state_queue_graph")
suspend_no_state = function(core, "bce_pm_suspend_no_state")
suspend_common = function(core, "t2bce_suspend_common")
resume_mode = function(core, "t2bce_resume_mode")
resume_wrapper = function(core, "t2bce_resume_with_shared_dma")
restore = function(core, "t2bce_restore")

assert ".freeze = t2bce_freeze" in core
assert ".poweroff = t2bce_freeze" in core
assert ".restore = t2bce_restore" in core
assert ".poweroff_noirq = t2bce_suspend_noirq" in core
assert ".freeze = t2audio_suspend" in audio
assert ".thaw = t2audio_resume" in audio
assert ".restore = t2audio_resume" in audio
assert "t2bce_resume_mode(dev, true)" in restore
assert "t2bce_resume(dev)" in resume_wrapper
assert suspend_no_state.index("pm_can_rebuild_no_state") < suspend_no_state.index("pm_prepare_no_state")
assert suspend_no_state.index("pm_prepare_no_state") < suspend_no_state.index("bce_pm_suspend_fallback_no_state")
assert suspend_no_state.index("bce_pm_suspend_fallback_no_state") < suspend_no_state.index("bce_pm_block_queue_dma")
assert suspend_no_state.index("bce_pm_block_queue_dma") < suspend_no_state.index("bce_pm_drop_no_state_queue_graph")
assert block_queue_dma.index("pci_clear_master") < block_queue_dma.rindex("pci_read_config_word")
assert drop_graph.index("synchronize_irq") < drop_graph.index("pm_drop_no_state_queues")
assert drop_graph.index("pm_drop_no_state_queues") < drop_graph.index("bce_free_command_queues")
assert rebuild_graph.index("bce_fw_version_handshake") < rebuild_graph.index("bce_create_command_queues")
assert rebuild_graph.index("bce_create_command_queues") < rebuild_graph.index("pm_rebuild_no_state_queues")
assert "wake_status && !allow_cold_boot" in resume_mode
assert "if (bce->no_state_early_wake_attempted)" in resume_mode
assert resume_mode.index("no_state_early_wake_status") < resume_mode.index("bce_pm_resume_no_state(bce)")
assert resume_mode.index("wake_status && !allow_cold_boot") < resume_mode.index("bce_xhci_pm_start")
assert "!bce->no_state_rebuild_failed" in core

for callback in ("pm_abort", "pm_drop_no_state_queues", "pm_rebuild_no_state_queues"):
  assert callback in transport_h
  assert f"t2bce_core_clients_{callback}" in transport_c
  assert f".{callback} =" in vhci
  assert f".{callback} =" in audio

vhci_drop = function(vhci, "bce_vhci_pm_drop_no_state_queues", "void")
vhci_rebuild = function(vhci, "bce_vhci_pm_rebuild_no_state_queues")
assert vhci_drop.index("cancel_work_sync") < vhci_drop.index("destroy_event_queues")
assert vhci_drop.index("destroy_event_queues") < vhci_drop.index("destroy_message_queues")
assert vhci_rebuild.index("create_message_queues") < vhci_rebuild.index("create_event_queues")
assert "q->sq = NULL;" in vhci_queue
assert "q->cq = NULL;" in vhci_queue

audio_resume = function(audio, "t2audio_resume")
audio_refresh = function(audio, "t2audio_refresh_bs_mapping")
assert audio_resume.index("t2audio_wait_remote_alive") < audio_resume.index("t2audio_refresh_bs_mapping")
assert audio_resume.index("t2audio_refresh_bs_mapping") < audio_resume.index("T2AUDIO_REMOTE_ACCESS_ON")
assert audio_refresh.index("pci_resource_len") < audio_refresh.index("a->bs =")
assert "sizeof(*a->bs) > bs_bar_len - bs_base" in audio_refresh
assert "t2audio_bce_destroy(userdata);" in audio
assert "return t2audio_bce_init(userdata);" in audio
assert "memset(q, 0, sizeof(*q));" in audio_bce
assert audio_bce.index("t2bce_core_destroy_sq(dev->bce, q->sq);") < audio_bce.index("q->sq = NULL;")

harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)

typedef uint16_t u16;
struct pci_dev { void *data; u16 command; int reads; bool fail_clear; };
struct device { struct pci_dev *pdev; };
struct t2bce_dma_engine { bool is_being_removed; };
struct bce_xhci_pm { int unused; };
struct mutex { int unused; };
struct t2bce_device {
  struct pci_dev *pci, *pci0;
  struct t2bce_dma_engine dma;
  struct bce_xhci_pm xhci_pm;
  struct mutex pm_lock;
  bool stateful_suspend_valid;
  bool no_state_fallback;
  bool no_state_resume;
  bool no_state_queues_dropped;
  bool no_state_rebuild_failed;
  bool no_state_early_wake_attempted;
  int no_state_early_wake_status;
  bool queue_dma_blocked;
  bool queue_dma_was_master;
};

enum event {
  EV_RESET, EV_PREPARE, EV_SUSPEND_PREPARE, EV_CAN_REBUILD,
  EV_PREPARE_NO_STATE, EV_SLEEP_NO_STATE, EV_BLOCK_DMA, EV_SYNC_IRQ, EV_DROP_CLIENTS,
  EV_FREE_COMMANDS, EV_MARK_RESUME, EV_SUSPEND_ABORT, EV_CLIENT_ABORT,
  EV_RESTORE_NO_STATE, EV_RESUME_FINISH, EV_XHCI_INITIAL, EV_CHANNEL_RESUME,
  EV_HANDSHAKE, EV_CREATE_COMMANDS, EV_REBUILD_CLIENTS, EV_STATEFUL_SAVE,
  EV_STATEFUL_RESTORE
};
static enum event events[128];
static int event_count;
static bool can_rebuild = true, stateful_supported = true;
static int prepare_status, suspend_prepare_status, sleep_status;
static int stateful_save_status, stateful_restore_status, restore_no_state_status;
static int handshake_status, create_commands_status, rebuild_clients_status;

static void record(enum event event) { events[event_count++] = event; }
static int find_event(enum event event) {
  for (int i = 0; i < event_count; i++)
    if (events[i] == event)
      return i;
  return -1;
}
static int count_event_between(enum event event, int start, int end) {
  int count = 0;
  for (int i = start; i < end; i++)
    if (events[i] == event)
      count++;
  return count;
}
static void reset_controls(void) {
  event_count = 0;
  can_rebuild = true;
  stateful_supported = true;
  prepare_status = suspend_prepare_status = sleep_status = 0;
  stateful_save_status = stateful_restore_status = restore_no_state_status = 0;
  handshake_status = create_commands_status = rebuild_clients_status = 0;
}

static struct pci_dev *to_pci_dev(struct device *dev) { return dev->pdev; }
static void *pci_get_drvdata(struct pci_dev *pdev) { return pdev->data; }
static int pci_read_config_word(struct pci_dev *pdev, int where, u16 *value) {
  assert(where == PCI_COMMAND);
  pdev->reads++;
  *value = pdev->command;
  return 0;
}
static void pci_clear_master(struct pci_dev *pdev) {
  record(EV_BLOCK_DMA);
  if (!pdev->fail_clear)
    pdev->command &= ~PCI_COMMAND_MASTER;
}
static void pci_set_master(struct pci_dev *pdev) { pdev->command |= PCI_COMMAND_MASTER; }
static int pci_irq_vector(struct pci_dev *pdev, unsigned int nr) {
  (void)pdev; assert(nr == 4); return 44;
}
static void synchronize_irq(unsigned int irq) { assert(irq == 44); record(EV_SYNC_IRQ); }
static void mutex_lock(struct mutex *lock) { (void)lock; }
static void mutex_unlock(struct mutex *lock) { (void)lock; }
static void t2bce_core_clients_pm_reset(struct t2bce_device *bce) { (void)bce; record(EV_RESET); }
static int t2bce_core_clients_pm_prepare(struct t2bce_device *bce) { (void)bce; record(EV_PREPARE); return prepare_status; }
static void t2bce_core_clients_pm_abort(struct t2bce_device *bce) { (void)bce; record(EV_CLIENT_ABORT); }
static int bce_pm_suspend_prepare(struct t2bce_device *bce) { (void)bce; record(EV_SUSPEND_PREPARE); return suspend_prepare_status; }
static void bce_pm_suspend_abort(struct t2bce_device *bce) { (void)bce; record(EV_SUSPEND_ABORT); }
static bool bce_stateful_supported(struct t2bce_device *bce) { (void)bce; return stateful_supported; }
static int bce_pm_suspend_try_state(struct t2bce_device *bce) {
  record(EV_STATEFUL_SAVE);
  if (!stateful_save_status)
    bce->stateful_suspend_valid = true;
  return stateful_save_status;
}
static bool t2bce_core_clients_pm_can_rebuild_no_state(struct t2bce_device *bce) { (void)bce; record(EV_CAN_REBUILD); return can_rebuild; }
static void t2bce_core_clients_pm_prepare_no_state(struct t2bce_device *bce) { (void)bce; record(EV_PREPARE_NO_STATE); }
static int bce_pm_suspend_fallback_no_state(struct t2bce_device *bce) { (void)bce; record(EV_SLEEP_NO_STATE); return sleep_status; }
static void t2bce_core_clients_pm_drop_no_state_queues(struct t2bce_device *bce) { (void)bce; record(EV_DROP_CLIENTS); }
static void bce_free_command_queues(struct t2bce_device *bce) { (void)bce; record(EV_FREE_COMMANDS); }
static void t2bce_core_clients_pm_mark_no_state_resume(struct t2bce_device *bce) { (void)bce; record(EV_MARK_RESUME); }
static int bce_fw_version_handshake(struct t2bce_device *bce) { (void)bce; record(EV_HANDSHAKE); return handshake_status; }
static int bce_create_command_queues(struct t2bce_device *bce) { (void)bce; record(EV_CREATE_COMMANDS); return create_commands_status; }
static int t2bce_core_clients_pm_rebuild_no_state_queues(struct t2bce_device *bce) { (void)bce; record(EV_REBUILD_CLIENTS); return rebuild_clients_status; }
static int bce_pm_resume_stateful(struct t2bce_device *bce) { (void)bce; record(EV_STATEFUL_RESTORE); return stateful_restore_status; }
static int bce_pm_resume_no_state(struct t2bce_device *bce) { (void)bce; record(EV_RESTORE_NO_STATE); return restore_no_state_status; }
static void bce_pm_resume_finish(struct t2bce_device *bce) { (void)bce; record(EV_RESUME_FINISH); }
static void bce_xhci_pm_start(struct bce_xhci_pm *pm, bool initial) { (void)pm; assert(initial); record(EV_XHCI_INITIAL); }
static void bce_pm_channel_resume(struct t2bce_device *bce) { (void)bce; record(EV_CHANNEL_RESUME); }
'''
harness += restore_queue_dma + block_queue_dma + drop_graph + rebuild_graph + suspend_no_state + suspend_common + resume_mode
harness += r'''
static void init_device(struct t2bce_device *bce, struct pci_dev functions[2], struct device *dev) {
  *bce = (struct t2bce_device){0};
  functions[0] = (struct pci_dev){.command = PCI_COMMAND_MASTER};
  functions[1] = (struct pci_dev){.command = PCI_COMMAND_MASTER};
  bce->pci = &functions[0];
  bce->pci0 = &functions[1];
  functions[0].data = bce;
  dev->pdev = &functions[0];
}

int main(void) {
  struct t2bce_device bce, snapshot;
  struct pci_dev functions[2];
  struct device dev;
  int first_freeze_end, first_thaw_end, second_freeze_end;

  reset_controls(); init_device(&bce, functions, &dev);
  assert(t2bce_suspend_common(&dev, true) == 0);
  assert(bce.no_state_queues_dropped && bce.no_state_resume && bce.no_state_fallback);
  assert(find_event(EV_PREPARE_NO_STATE) < find_event(EV_SLEEP_NO_STATE));
  assert(find_event(EV_SLEEP_NO_STATE) < find_event(EV_BLOCK_DMA));
  assert(find_event(EV_BLOCK_DMA) < find_event(EV_SYNC_IRQ));
  assert(find_event(EV_DROP_CLIENTS) < find_event(EV_FREE_COMMANDS));
  assert(bce.queue_dma_blocked && bce.queue_dma_was_master);
  assert(!(functions[0].command & PCI_COMMAND_MASTER));

  /* Linux snapshots the queue-absent state, thaws the source kernel, then
   * freezes it again for either PMSG_QUIESCE (test-resume/image restore) or
   * PMSG_HIBERNATE (real S4 poweroff).  Atomic restore must use the earlier
   * snapshot, not the queue graph rebuilt during the source-kernel thaw.
   */
  reset_controls(); init_device(&bce, functions, &dev);
  assert(t2bce_suspend_common(&dev, true) == 0);
  snapshot = bce;
  first_freeze_end = event_count;
  assert(snapshot.no_state_queues_dropped && snapshot.no_state_resume);
  assert(t2bce_resume_mode(&dev, false) == 0);
  first_thaw_end = event_count;
  assert(!bce.no_state_queues_dropped && !bce.no_state_rebuild_failed);
  assert(t2bce_suspend_common(&dev, true) == 0);
  second_freeze_end = event_count;
  assert(bce.no_state_queues_dropped && bce.no_state_resume);
  assert(snapshot.no_state_queues_dropped && snapshot.no_state_resume);
  bce = snapshot;
  functions[0].data = &bce;
  assert(t2bce_resume_mode(&dev, true) == 0);
  assert(!bce.no_state_queues_dropped && !bce.no_state_rebuild_failed);
  assert(count_event_between(EV_DROP_CLIENTS, 0, first_freeze_end) == 1);
  assert(count_event_between(EV_REBUILD_CLIENTS, first_freeze_end, first_thaw_end) == 1);
  assert(count_event_between(EV_DROP_CLIENTS, first_thaw_end, second_freeze_end) == 1);
  assert(count_event_between(EV_REBUILD_CLIENTS, second_freeze_end, event_count) == 1);

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; bce.no_state_resume = true;
  bce.no_state_early_wake_attempted = true;
  assert(t2bce_resume_mode(&dev, false) == 0);
  assert(find_event(EV_RESTORE_NO_STATE) < 0);
  assert(find_event(EV_RESUME_FINISH) < find_event(EV_HANDSHAKE));

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; bce.no_state_resume = true;
  bce.no_state_early_wake_attempted = true;
  bce.no_state_early_wake_status = -ETIMEDOUT;
  assert(t2bce_resume_mode(&dev, false) == -ETIMEDOUT);
  assert(find_event(EV_RESTORE_NO_STATE) < 0);
  assert(find_event(EV_XHCI_INITIAL) < 0 && bce.no_state_rebuild_failed);

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; bce.no_state_resume = true;
  bce.no_state_early_wake_attempted = true;
  bce.no_state_early_wake_status = -ETIMEDOUT;
  assert(t2bce_resume_mode(&dev, true) == 0);
  assert(find_event(EV_RESTORE_NO_STATE) < 0);
  assert(find_event(EV_XHCI_INITIAL) < find_event(EV_CHANNEL_RESUME));

  reset_controls(); init_device(&bce, functions, &dev); can_rebuild = false;
  assert(t2bce_suspend_common(&dev, true) == -EOPNOTSUPP);
  assert(find_event(EV_SLEEP_NO_STATE) < 0 && find_event(EV_DROP_CLIENTS) < 0);
  assert(find_event(EV_SUSPEND_ABORT) >= 0 && find_event(EV_CLIENT_ABORT) >= 0);

  reset_controls(); init_device(&bce, functions, &dev); sleep_status = -EIO;
  assert(t2bce_suspend_common(&dev, true) == -EIO);
  assert(find_event(EV_DROP_CLIENTS) < 0);
  assert(find_event(EV_SUSPEND_ABORT) >= 0 && find_event(EV_CLIENT_ABORT) >= 0);

  reset_controls(); init_device(&bce, functions, &dev); functions[0].fail_clear = true;
  assert(t2bce_suspend_common(&dev, true) == -EIO);
  assert(find_event(EV_SLEEP_NO_STATE) < find_event(EV_BLOCK_DMA));
  assert(find_event(EV_DROP_CLIENTS) < 0 && find_event(EV_FREE_COMMANDS) < 0);
  assert(find_event(EV_SUSPEND_ABORT) >= 0 && find_event(EV_CLIENT_ABORT) >= 0);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(functions[0].command & PCI_COMMAND_MASTER);

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; bce.no_state_resume = true;
  assert(t2bce_resume_mode(&dev, false) == 0);
  assert(find_event(EV_RESTORE_NO_STATE) < find_event(EV_RESUME_FINISH));
  assert(find_event(EV_RESUME_FINISH) < find_event(EV_HANDSHAKE));
  assert(find_event(EV_HANDSHAKE) < find_event(EV_CREATE_COMMANDS));
  assert(find_event(EV_CREATE_COMMANDS) < find_event(EV_REBUILD_CLIENTS));
  assert(!bce.no_state_queues_dropped && !bce.no_state_rebuild_failed);

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; restore_no_state_status = -ETIMEDOUT;
  assert(t2bce_resume_mode(&dev, false) == -ETIMEDOUT);
  assert(find_event(EV_XHCI_INITIAL) < 0 && find_event(EV_HANDSHAKE) < 0);
  assert(bce.no_state_rebuild_failed);

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; restore_no_state_status = -ETIMEDOUT;
  assert(t2bce_resume_mode(&dev, true) == 0);
  assert(find_event(EV_XHCI_INITIAL) < find_event(EV_CHANNEL_RESUME));
  assert(find_event(EV_CHANNEL_RESUME) < find_event(EV_HANDSHAKE));

  reset_controls(); init_device(&bce, functions, &dev);
  bce.no_state_queues_dropped = true; rebuild_clients_status = -ENOMEM;
  assert(t2bce_resume_mode(&dev, false) == -ENOMEM);
  assert(bce.no_state_queues_dropped && bce.no_state_rebuild_failed);
  assert(find_event(EV_REBUILD_CLIENTS) < find_event(EV_SYNC_IRQ));
  assert(find_event(EV_DROP_CLIENTS) < find_event(EV_FREE_COMMANDS));

  reset_controls(); init_device(&bce, functions, &dev);
  assert(t2bce_suspend_common(&dev, false) == 0);
  assert(find_event(EV_STATEFUL_SAVE) >= 0 && find_event(EV_SLEEP_NO_STATE) < 0);
  assert(t2bce_resume_mode(&dev, false) == 0);
  assert(find_event(EV_STATEFUL_RESTORE) >= 0);
  return 0;
}
'''

with tempfile.TemporaryDirectory() as directory:
  source = Path(directory) / "cold-s4-harness.c"
  binary = Path(directory) / "cold-s4-harness"
  source.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
  subprocess.run([str(binary)], check=True)

print("PASS: hibernation snapshots discard and rebuild the complete BCE queue graph")
