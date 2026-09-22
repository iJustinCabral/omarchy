#!/usr/bin/env python3
"""Exercise the experimental T2 noirq DMA gate without loading modules."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 4, "usage: test-dma-quiesce.py T2BCE_MAIN_C T2BCE_H BCM4377_C"
bce_source = Path(sys.argv[1]).read_text()
bce_header = Path(sys.argv[2]).read_text()
bluetooth_source = Path(sys.argv[3]).read_text()


def function(source, name, return_type="int"):
  match = re.search(r"static " + return_type + " " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


bce_restore_queue_dma = function(bce_source, "bce_pm_restore_queue_dma", "void")
bce_block_queue_dma = function(bce_source, "bce_pm_block_queue_dma")
bce_block = function(bce_source, "t2bce_block_shared_dma", "void")
bce_save = function(bce_source, "t2bce_save_shared_pci_state")
bce_suspend = function(bce_source, "t2bce_suspend_noirq")
bce_resume_noirq = function(bce_source, "t2bce_resume_noirq")
bce_restore_dma = function(bce_source, "t2bce_restore_shared_dma")
bce_resume_wrapper = function(bce_source, "t2bce_resume_with_shared_dma")
bce_image_restore = function(bce_source, "t2bce_restore")
assert "struct pci_dev *pci, *pci0, *pci2, *pci3;" in bce_header
assert "bool pci_dma_restore_failed;" in bce_header
assert "bool queue_dma_blocked;" in bce_header
assert "bool queue_dma_was_master;" in bce_header
assert "unsigned long pci_master_mask;" in bce_header
assert bce_block_queue_dma.index("pci_clear_master") < bce_block_queue_dma.rindex("pci_read_config_word")
assert bce_block_queue_dma.index("pci_clear_master") < bce_block_queue_dma.index("queue_dma_blocked = true")
assert "{ bce->pci0, bce->pci, bce->pci2, bce->pci3 }" in bce_suspend
assert bce_suspend.index("pci_read_config_word") < bce_suspend.index("pci_clear_master")
assert bce_suspend.index("pci_clear_master") < bce_suspend.index("t2bce_save_shared_pci_state")
assert bce_suspend.index("t2bce_save_shared_pci_state") < bce_suspend.index("bce->pci_master_mask = master_mask")
assert ".freeze_noirq = t2bce_suspend_noirq" in bce_source
assert ".thaw_noirq = t2bce_resume_noirq" in bce_source
assert ".restore_noirq = t2bce_resume_noirq" in bce_source
assert ".resume = t2bce_resume_with_shared_dma" in bce_source
assert ".thaw = t2bce_resume_with_shared_dma" in bce_source
assert ".restore = t2bce_restore" in bce_source
assert bce_resume_wrapper.index("pci_dma_restore_failed") < bce_resume_wrapper.index("t2bce_resume(dev)")
if "t2bce_resume_mode(dev, true)" in bce_image_restore:
  image_restore_call = "t2bce_resume_mode(dev, true)"
else:
  image_restore_call = "t2bce_resume(dev)"
assert bce_image_restore.index("pci_dma_restore_failed") < bce_image_restore.index(image_restore_call)
assert "Leave the\n     * unbound SEP function blocked" in bce_image_restore

bce_harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(i) (1UL << (i))
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
typedef uint16_t u16;
struct pci_dev {
  u16 command, saved_command;
  int reads, saves, fail_read_at, fail_save_at, fail_clear, fail_set;
  void *data;
};
struct t2bce_device {
  struct pci_dev *pci, *pci0, *pci2, *pci3;
  bool pci_dma_restore_failed;
  bool queue_dma_blocked;
  bool queue_dma_was_master;
  unsigned long pci_master_mask;
};
struct device { struct pci_dev *pdev; };
static struct pci_dev *to_pci_dev(struct device *dev) { return dev->pdev; }
static void *pci_get_drvdata(struct pci_dev *pdev) { return pdev->data; }
static int pci_read_config_word(struct pci_dev *pdev, int where, u16 *value) {
  assert(where == PCI_COMMAND);
  pdev->reads++;
  if (pdev->fail_read_at && pdev->reads == pdev->fail_read_at)
    return -EIO;
  *value = pdev->command;
  return 0;
}
static void pci_clear_master(struct pci_dev *pdev) {
  if (!pdev->fail_clear)
    pdev->command &= ~PCI_COMMAND_MASTER;
}
static void pci_set_master(struct pci_dev *pdev) {
  if (!pdev->fail_set)
    pdev->command |= PCI_COMMAND_MASTER;
}
static int pci_save_state(struct pci_dev *pdev) {
  pdev->saves++;
  if (pdev->fail_save_at && pdev->saves == pdev->fail_save_at)
    return -EIO;
  pdev->saved_command = pdev->command;
  return 0;
}
'''
bce_harness += bce_restore_queue_dma + bce_block_queue_dma + bce_block + bce_save + bce_suspend + bce_resume_noirq + bce_restore_dma
bce_harness += r'''
static void test_two_pass_image_restore(void) {
  struct pci_dev functions[4] = {
    {.command = PCI_COMMAND_MASTER}, {.command = PCI_COMMAND_MASTER},
    {.command = PCI_COMMAND_MASTER}, {.command = 0},
  };
  struct pci_dev snapshot_functions[4];
  struct t2bce_device bce = {
    .pci0 = &functions[0], .pci = &functions[1],
    .pci2 = &functions[2], .pci3 = &functions[3],
  };
  struct t2bce_device snapshot_bce;
  struct pci_dev owner = {.data = &bce};
  struct device dev = {.pdev = &owner};

  /* Queue teardown blocks BCE first.  The first noirq pass carries that
   * original master state into the shared-link snapshot.
   */
  assert(bce_pm_block_queue_dma(&bce) == 0);
  assert(bce.queue_dma_blocked && bce.queue_dma_was_master);
  assert(!(functions[1].command & PCI_COMMAND_MASTER));
  assert(t2bce_suspend_noirq(&dev) == 0);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  snapshot_bce = bce;
  memcpy(snapshot_functions, functions, sizeof(functions));
  assert(snapshot_bce.pci_master_mask == 7);

  /* The source kernel thaws, restores DMA, then blocks it again while the
   * image-loading kernel is quiesced for atomic restoration.
   */
  assert(t2bce_resume_noirq(&dev) == 0);
  assert(t2bce_restore_shared_dma(&bce) == 0);
  assert(t2bce_suspend_noirq(&dev) == 0);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));

  /* Atomic restore rewinds both driver and PCI saved-state memory to the
   * first blocked snapshot.  restore_noirq must preserve that gate until
   * ordinary queue reconstruction completes.
   */
  bce = snapshot_bce;
  memcpy(functions, snapshot_functions, sizeof(functions));
  owner.data = &bce;
  assert(t2bce_resume_noirq(&dev) == 0);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++) {
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
    assert(!(functions[i].saved_command & PCI_COMMAND_MASTER));
  }

  /* The image-restore callback consumes the saved mask without re-enabling
   * the unbound SEP function; BCE, ANS, and audio recover in their drivers.
   */
  bce.pci_master_mask = 0;
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
}

int main(void) {
  struct pci_dev functions[4] = {
    {.command = PCI_COMMAND_MASTER}, {.command = PCI_COMMAND_MASTER},
    {.command = PCI_COMMAND_MASTER}, {.command = 0},
  };
  struct t2bce_device bce = {
    .pci0 = &functions[0], .pci = &functions[1],
    .pci2 = &functions[2], .pci3 = &functions[3],
  };
  struct pci_dev owner = {.data = &bce};
  struct device dev = {.pdev = &owner};

  test_two_pass_image_restore();

  assert(bce_pm_block_queue_dma(&bce) == 0);
  assert(bce.queue_dma_blocked && bce.queue_dma_was_master);
  assert(t2bce_suspend_noirq(&dev) == 0);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++) {
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
    assert(!(functions[i].saved_command & PCI_COMMAND_MASTER));
  }
  assert(t2bce_resume_noirq(&dev) == 0);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
  assert(t2bce_restore_shared_dma(&bce) == 0);
  assert(bce.pci_master_mask == 0);
  assert((functions[0].command & PCI_COMMAND_MASTER));
  assert((functions[1].command & PCI_COMMAND_MASTER));
  assert((functions[2].command & PCI_COMMAND_MASTER));
  assert(!(functions[3].command & PCI_COMMAND_MASTER));

  functions[1].reads = 0;
  functions[1].fail_read_at = 1;
  assert(bce_pm_block_queue_dma(&bce) == -EIO);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(functions[1].command & PCI_COMMAND_MASTER);
  functions[1].fail_read_at = 0;

  functions[1].reads = 0;
  functions[1].fail_clear = 1;
  assert(bce_pm_block_queue_dma(&bce) == -EIO);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(functions[1].command & PCI_COMMAND_MASTER);
  functions[1].fail_clear = 0;

  functions[1].reads = 0;
  functions[1].fail_read_at = 2;
  assert(bce_pm_block_queue_dma(&bce) == -EIO);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(functions[1].command & PCI_COMMAND_MASTER);
  functions[1].fail_read_at = 0;

  functions[1].command = 0;
  functions[1].reads = 0;
  assert(bce_pm_block_queue_dma(&bce) == 0);
  assert(bce.queue_dma_blocked && !bce.queue_dma_was_master);
  bce_pm_restore_queue_dma(&bce);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert(!(functions[1].command & PCI_COMMAND_MASTER));
  functions[1].command = PCI_COMMAND_MASTER;

  for (int i = 0; i < 4; i++) {
    functions[i].reads = 0;
    functions[i].saves = 0;
  }
  assert(bce_pm_block_queue_dma(&bce) == 0);
  functions[2].fail_clear = 1;
  assert(t2bce_suspend_noirq(&dev) == -EIO);
  assert(bce.pci_master_mask == 0);
  assert(!bce.queue_dma_blocked && !bce.queue_dma_was_master);
  assert((functions[0].command & PCI_COMMAND_MASTER));
  assert((functions[1].command & PCI_COMMAND_MASTER));
  assert((functions[2].command & PCI_COMMAND_MASTER));
  assert(!(functions[3].command & PCI_COMMAND_MASTER));
  for (int i = 0; i < 4; i++)
    assert(functions[i].saved_command == functions[i].command);

  functions[2].fail_clear = 0;
  for (int i = 0; i < 4; i++) {
    functions[i].reads = 0;
    functions[i].saves = 0;
  }
  functions[2].fail_save_at = 1;
  assert(t2bce_suspend_noirq(&dev) == -EIO);
  assert(bce.pci_master_mask == 0);
  for (int i = 0; i < 4; i++)
    assert(functions[i].saved_command == functions[i].command);

  functions[2].fail_save_at = 0;
  for (int i = 0; i < 4; i++) {
    functions[i].reads = 0;
    functions[i].saves = 0;
  }
  assert(t2bce_suspend_noirq(&dev) == 0);
  functions[2].command = PCI_COMMAND_MASTER;
  assert(t2bce_resume_noirq(&dev) == -EIO);
  assert(bce.pci_dma_restore_failed);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));

  bce.pci_dma_restore_failed = false;
  functions[2].fail_set = 1;
  assert(t2bce_restore_shared_dma(&bce) == -EIO);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
  functions[2].fail_set = 0;
  assert(t2bce_restore_shared_dma(&bce) == 0);
  assert(bce.pci_master_mask == 0);
  return 0;
}
'''

bluetooth_suspend = function(bluetooth_source, "bcm4377_suspend_noirq")
bluetooth_restore = function(bluetooth_source, "bcm4377_restore_busmaster")
assert bluetooth_suspend.index("pci_read_config_word") < bluetooth_suspend.index("pci_clear_master")
assert "bcm4377->pm_was_busmaster = command & PCI_COMMAND_MASTER;" in bluetooth_suspend
assert ".freeze_noirq = bcm4377_suspend_noirq" in bluetooth_source
assert ".thaw_noirq = bcm4377_resume_noirq" in bluetooth_source
assert ".restore_noirq = bcm4377_resume_noirq" in bluetooth_source
bluetooth_resume = function(bluetooth_source, "bcm4377_resume_noirq")
assert "READ_ONCE(bcm4377->transport_lost)" in bluetooth_restore
assert bluetooth_restore.index("pci_set_master(pdev)") < bluetooth_restore.index("pci_read_config_word")
assert bluetooth_restore.index("pci_read_config_word") < bluetooth_restore.rindex("pci_clear_master(pdev)")
assert bluetooth_resume.index("WRITE_ONCE(bcm4377->resume_config_failed, false)") < bluetooth_resume.rindex("bcm4377_restore_busmaster")

bluetooth_harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define READ_ONCE(x) (x)
typedef uint16_t u16;
struct bcm4377_data { bool pm_was_busmaster, transport_lost; };
struct pci_dev { u16 command; int reads; int fail_read_at; int fail_clear, fail_set; void *data; };
struct device { struct pci_dev *pdev; };
static struct pci_dev *to_pci_dev(struct device *dev) { return dev->pdev; }
static void *pci_get_drvdata(struct pci_dev *pdev) { return pdev->data; }
static int pci_read_config_word(struct pci_dev *pdev, int where, u16 *value) {
  assert(where == PCI_COMMAND);
  pdev->reads++;
  if (pdev->fail_read_at && pdev->reads == pdev->fail_read_at)
    return -EIO;
  *value = pdev->command;
  return 0;
}
static void pci_clear_master(struct pci_dev *pdev) {
  if (!pdev->fail_clear)
    pdev->command &= ~PCI_COMMAND_MASTER;
}
static void pci_set_master(struct pci_dev *pdev) {
  if (!pdev->fail_set)
    pdev->command |= PCI_COMMAND_MASTER;
}
'''
bluetooth_harness += bluetooth_suspend + bluetooth_restore
bluetooth_harness += r'''
int main(void) {
  struct bcm4377_data state = {0};
  struct pci_dev pdev = {.command = PCI_COMMAND_MASTER, .data = &state};
  struct device dev = {.pdev = &pdev};
  assert(bcm4377_suspend_noirq(&dev) == 0);
  assert(state.pm_was_busmaster);
  assert(!(pdev.command & PCI_COMMAND_MASTER));
  assert(bcm4377_restore_busmaster(&pdev, &state) == 0);
  assert(!state.pm_was_busmaster);
  assert(pdev.command & PCI_COMMAND_MASTER);

  pdev.command = PCI_COMMAND_MASTER;
  pdev.reads = 0;
  pdev.fail_clear = 1;
  assert(bcm4377_suspend_noirq(&dev) == -EIO);
  assert(!state.pm_was_busmaster);
  assert(pdev.command & PCI_COMMAND_MASTER);
  pdev.reads = 0;
  pdev.fail_clear = 0;
  pdev.fail_read_at = 2;
  assert(bcm4377_suspend_noirq(&dev) == -EIO);
  assert(!state.pm_was_busmaster);
  assert(pdev.command & PCI_COMMAND_MASTER);

  pdev.reads = 0;
  pdev.fail_read_at = 0;
  assert(bcm4377_suspend_noirq(&dev) == 0);
  pdev.reads = 0;
  pdev.fail_read_at = 1;
  assert(bcm4377_restore_busmaster(&pdev, &state) == -EIO);
  assert(state.pm_was_busmaster);
  assert(!(pdev.command & PCI_COMMAND_MASTER));
  pdev.reads = 0;
  pdev.fail_read_at = 0;
  assert(bcm4377_restore_busmaster(&pdev, &state) == 0);
  assert(!state.pm_was_busmaster);
  assert(pdev.command & PCI_COMMAND_MASTER);

  pdev.reads = 0;
  assert(bcm4377_suspend_noirq(&dev) == 0);
  state.transport_lost = true;
  assert(bcm4377_restore_busmaster(&pdev, &state) == 0);
  assert(!state.pm_was_busmaster);
  assert(!(pdev.command & PCI_COMMAND_MASTER));
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-dma-quiesce-") as directory:
  root = Path(directory)
  for name, harness in (("bce", bce_harness), ("bluetooth", bluetooth_harness)):
    source = root / f"{name}.c"
    binary = root / name
    source.write_text(harness)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: T2 DMA gates persist blocked PCI state through noirq and restore only after recovery")
