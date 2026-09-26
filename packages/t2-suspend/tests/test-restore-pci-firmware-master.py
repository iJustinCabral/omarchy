#!/usr/bin/python3
"""Compare extracted Linux 7.2.6 PCI freeze with candidate shared DMA gating.

This offline regression demonstrates a coverage gap, not hardware DMA activity
or the cause of any failed restore. Pass the pinned kernel and candidate trees.
"""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 3, "usage: test-restore-pci-firmware-master.py LINUX_7_2_6_ROOT CANDIDATE_ROOT"
kernel, candidate = map(Path, sys.argv[1:])
makefile = (kernel / "Makefile").read_text()
for key, value in (("VERSION", "7"), ("PATCHLEVEL", "2"), ("SUBLEVEL", "6")):
  assert re.search(rf"^{key} = {value}$", makefile, re.M), "requires pinned Linux 7.2.6"
pci = (kernel / "drivers/pci/pci.c").read_text()
driver = (kernel / "drivers/pci/pci-driver.c").read_text()
header = (kernel / "include/linux/pci.h").read_text()
core = (candidate / "drivers/staging/t2bce/t2bce_core/t2bce_main.c").read_text()


def function(source, name):
  match = re.search(r"^(?:static )?(?:inline )?(?:void|int) " + name + r"\([^;]+?\)\n\{", source, re.M)
  assert match, f"missing {name}"
  index, depth = match.end(), 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


# All decisions under test come from the supplied sources. Stubs below model
# only PCI configuration access and unrelated PM/platform plumbing.
extracted = "".join((
  function(header, "pci_is_enabled"),
  function(pci, "do_pci_disable_device"),
  function(pci, "pci_disable_enabled_device"),
  function(driver, "pci_pm_default_suspend"),
  function(driver, "pci_pm_freeze"),
  function(driver, "pci_pm_freeze_noirq"),
  function(core, "t2bce_save_shared_pci_state"),
  function(core, "t2bce_suspend_noirq"),
))

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define PMSG_FREEZE 1
#define BIT(i) (1UL << (i))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
typedef uint16_t u16;
struct device;
struct dev_pm_ops {
  int (*freeze)(struct device *);
  int (*freeze_noirq)(struct device *);
};
struct driver { const struct dev_pm_ops *pm; };
struct pci_dev;
struct device { struct pci_dev *pdev; struct driver *driver; };
struct pci_dev {
  struct device dev;
  int enable_cnt;
  u16 command, saved_command;
  unsigned int saves, disables;
  bool state_saved, bridge;
  void *data;
};
struct t2bce_device {
  struct pci_dev *pci0, *pci, *pci2, *pci3;
  bool pci_dma_restore_failed, queue_dma_blocked, queue_dma_was_master;
  unsigned long pci_master_mask;
};
static int atomic_read(const int *value) { return *value; }
static struct pci_dev *to_pci_dev(struct device *dev) { return dev->pdev; }
static void *pci_get_drvdata(struct pci_dev *pdev) { return pdev->data; }
static bool pci_has_subordinate(struct pci_dev *pdev) { return pdev->bridge; }
static int pci_read_config_word(struct pci_dev *pdev, int reg, u16 *value) {
  assert(reg == PCI_COMMAND); *value = pdev->command; return 0;
}
static void pci_write_config_word(struct pci_dev *pdev, int reg, u16 value) {
  assert(reg == PCI_COMMAND); pdev->command = value;
}
static void pci_clear_master(struct pci_dev *pdev) { pdev->command &= ~PCI_COMMAND_MASTER; }
static void pci_set_master(struct pci_dev *pdev) { pdev->command |= PCI_COMMAND_MASTER; }
static void pcibios_disable_device(struct pci_dev *pdev) { pdev->disables++; }
static bool pci_has_legacy_pm_support(struct pci_dev *pdev) { (void)pdev; return false; }
static int pci_legacy_suspend(struct device *dev, int state) { (void)dev; (void)state; assert(false); return 0; }
static int pci_legacy_suspend_late(struct device *dev) { (void)dev; assert(false); return 0; }
static bool pm_runtime_suspended(struct device *dev) { (void)dev; return false; }
static void pm_runtime_resume(struct device *dev) { (void)dev; }
static void suspend_report_result(struct device *dev, int (*callback)(struct device *), int error) {
  (void)dev; (void)callback; (void)error;
}
static int pci_save_state(struct pci_dev *pdev) {
  pdev->saved_command = pdev->command; pdev->state_saved = true; pdev->saves++; return 0;
}
static void pci_pm_set_unknown_state(struct pci_dev *pdev) { (void)pdev; }
'''
harness += extracted
harness += r'''
static void init_function(struct pci_dev *pdev, int enable_count, bool master) {
  *pdev = (struct pci_dev){ .enable_cnt = enable_count,
    .command = (u16)(0x100 | (master ? PCI_COMMAND_MASTER : 0)) };
  pdev->dev.pdev = pdev;
}
int main(void) {
  struct pci_dev functions[4];
  struct t2bce_device bce = { .pci0 = &functions[0], .pci = &functions[1],
    .pci2 = &functions[2], .pci3 = &functions[3] };

  // Real generic main/noirq freeze of an unbound firmware-enabled endpoint.
  init_function(&functions[0], 0, true);
  assert(pci_pm_freeze(&functions[0].dev) == 0);
  assert(pci_pm_freeze_noirq(&functions[0].dev) == 0);
  assert(functions[0].command & PCI_COMMAND_MASTER);
  assert(functions[0].saved_command & PCI_COMMAND_MASTER);
  assert(functions[0].disables == 0 && functions[0].saves == 1);

  // Positive control: a Linux-enabled endpoint takes the disable branch.
  init_function(&functions[0], 1, true);
  assert(pci_pm_freeze(&functions[0].dev) == 0);
  assert(pci_pm_freeze_noirq(&functions[0].dev) == 0);
  assert(!(functions[0].command & PCI_COMMAND_MASTER));
  assert(!(functions[0].saved_command & PCI_COMMAND_MASTER));
  assert(functions[0].disables == 1);

  // Every master-mask combination, with mixed Linux enable counts: the real
  // candidate gate clears every sibling and saves the disabled configuration.
  for (unsigned long mask = 0; mask < BIT(4); mask++) {
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++) {
      init_function(&functions[i], i % 2, !!(mask & BIT(i)));
      functions[i].data = &bce;
    }
    bce.queue_dma_blocked = false;
    bce.queue_dma_was_master = false;
    assert(t2bce_suspend_noirq(&functions[1].dev) == 0);
    assert(bce.pci_master_mask == mask);
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++) {
      assert(functions[i].command == 0x100);
      assert(functions[i].saved_command == 0x100);
      assert(functions[i].saves == 1);
      assert(functions[i].enable_cnt == (int)(i % 2));
    }
  }
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="restore-pci-firmware-master-") as directory:
  source = Path(directory) / "harness.c"
  binary = Path(directory) / "harness"
  source.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True)
  subprocess.run([str(binary)], check=True)

print("PASS: extracted Linux 7.2.6 unbound PCI freeze preserves firmware MASTER with enable_cnt=0; candidate shared noirq gate clears and saves all siblings")
print("Coverage evidence only: this does not establish restore-boot PCI state, active DMA, or failure causality")
