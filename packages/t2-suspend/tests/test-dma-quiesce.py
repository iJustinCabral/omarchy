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


def function(source, name):
  match = re.search(r"static int " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


bce_suspend = function(bce_source, "t2bce_suspend_noirq")
bce_resume = function(bce_source, "t2bce_resume_noirq")
assert "struct pci_dev *pci, *pci0, *pci2, *pci3;" in bce_header
assert "unsigned long pci_master_mask;" in bce_header
assert "{ bce->pci0, bce->pci, bce->pci2, bce->pci3 }" in bce_suspend
assert bce_suspend.index("pci_read_config_word") < bce_suspend.index("pci_clear_master")
assert bce_suspend.index("pci_clear_master") < bce_suspend.index("bce->pci_master_mask = master_mask")
assert ".freeze_noirq = t2bce_suspend_noirq" in bce_source
assert ".thaw_noirq = t2bce_resume_noirq" in bce_source
assert ".restore_noirq = t2bce_resume_noirq" in bce_source

bce_harness = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(i) (1UL << (i))
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
typedef uint16_t u16;
struct pci_dev { u16 command; int reads; int fail_read_at; int fail_clear; void *data; };
struct t2bce_device {
  struct pci_dev *pci, *pci0, *pci2, *pci3;
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
static void pci_set_master(struct pci_dev *pdev) { pdev->command |= PCI_COMMAND_MASTER; }
'''
bce_harness += bce_suspend + bce_resume
bce_harness += r'''
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

  assert(t2bce_suspend_noirq(&dev) == 0);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
  assert(t2bce_resume_noirq(&dev) == 0);
  assert(bce.pci_master_mask == 0);
  assert((functions[0].command & PCI_COMMAND_MASTER));
  assert((functions[1].command & PCI_COMMAND_MASTER));
  assert((functions[2].command & PCI_COMMAND_MASTER));
  assert(!(functions[3].command & PCI_COMMAND_MASTER));

  functions[2].fail_clear = 1;
  assert(t2bce_suspend_noirq(&dev) == -EIO);
  assert(bce.pci_master_mask == 0);
  assert((functions[0].command & PCI_COMMAND_MASTER));
  assert((functions[1].command & PCI_COMMAND_MASTER));
  assert((functions[2].command & PCI_COMMAND_MASTER));
  assert(!(functions[3].command & PCI_COMMAND_MASTER));

  functions[2].fail_clear = 0;
  assert(t2bce_suspend_noirq(&dev) == 0);
  functions[2].reads = 0;
  functions[2].fail_read_at = 1;
  assert(t2bce_resume_noirq(&dev) == -EIO);
  assert(bce.pci_master_mask == 7);
  for (int i = 0; i < 4; i++)
    assert(!(functions[i].command & PCI_COMMAND_MASTER));
  functions[2].reads = 0;
  functions[2].fail_read_at = 0;
  assert(t2bce_resume_noirq(&dev) == 0);
  assert(bce.pci_master_mask == 0);
  return 0;
}
'''

bluetooth_suspend = function(bluetooth_source, "bcm4377_suspend_noirq")
assert bluetooth_suspend.index("pci_read_config_word") < bluetooth_suspend.index("pci_clear_master")
assert "bcm4377->pm_was_busmaster = command & PCI_COMMAND_MASTER;" in bluetooth_suspend
assert ".freeze_noirq = bcm4377_suspend_noirq" in bluetooth_source
assert ".thaw_noirq = bcm4377_resume_noirq" in bluetooth_source
assert ".restore_noirq = bcm4377_resume_noirq" in bluetooth_source
bluetooth_resume = function(bluetooth_source, "bcm4377_resume_noirq")
assert "bcm4377->pm_was_busmaster &&" in bluetooth_resume
assert "!READ_ONCE(bcm4377->transport_lost)" in bluetooth_resume
assert bluetooth_resume.index("WRITE_ONCE(bcm4377->resume_config_failed, false)") < bluetooth_resume.rindex("pci_set_master(pdev)")

bluetooth_harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
typedef uint16_t u16;
struct bcm4377_data { bool pm_was_busmaster; };
struct pci_dev { u16 command; int reads; int fail_read_at; int fail_clear; void *data; };
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
static void pci_set_master(struct pci_dev *pdev) { pdev->command |= PCI_COMMAND_MASTER; }
'''
bluetooth_harness += bluetooth_suspend
bluetooth_harness += r'''
int main(void) {
  struct bcm4377_data state = {0};
  struct pci_dev pdev = {.command = PCI_COMMAND_MASTER, .data = &state};
  struct device dev = {.pdev = &pdev};
  assert(bcm4377_suspend_noirq(&dev) == 0);
  assert(state.pm_was_busmaster);
  assert(!(pdev.command & PCI_COMMAND_MASTER));
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

print("PASS: T2 noirq DMA gates block, verify, unwind, and restore prior bus masters")
