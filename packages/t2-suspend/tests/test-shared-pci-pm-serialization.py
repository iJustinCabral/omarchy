#!/usr/bin/env python3
"""Exercise shared T2 PCI system-PM serialization offline."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 2, "usage: test-shared-pci-pm-serialization.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1])
core = (root / "drivers/staging/t2bce/t2bce_core/t2bce_main.c").read_text()
header = (root / "drivers/staging/t2bce/t2bce_core/t2bce.h").read_text()


def function(source, name, return_type="void"):
  match = re.search(r"(?:static )?" + return_type + r" " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


disable = function(core, "bce_pm_disable_shared_async")
restore = function(core, "bce_pm_restore_shared_async")
probe = function(core, "t2bce_probe", "int")
remove = function(core, "t2bce_remove")
function_set = "{ bce->pci0, bce->pci, bce->pci2, bce->pci3 }"

assert "unsigned long pci_async_suspend_mask;" in header
assert function_set in disable
assert function_set in restore
assert disable.index("device_async_suspend_enabled") < disable.index("device_disable_async_suspend")
assert "bce->pci_async_suspend_mask |= BIT(i);" in disable
assert restore.index("device_enable_async_suspend") < restore.index("pci_async_suspend_mask = 0")
assert probe.index("if (!bce->pci0 || !bce->pci2 || !bce->pci3)") < probe.index("bce_pm_disable_shared_async")
assert probe.index("bce_pm_disable_shared_async") < probe.index("pci_enable_device_mem")
assert "goto fail_shared_pm;" in probe
assert probe.index("fail_shared_pm:") < probe.index("fail_dev0:")
assert "bce_pm_restore_shared_async(bce);" in probe[probe.index("fail_shared_pm:"):probe.index("fail_dev0:")]
assert remove.index("bce_pm_restore_shared_async") < remove.index("pci_dev_put(bce->pci3)")

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define BIT(index) (1UL << (index))

struct device { bool async_suspend; };
struct pci_dev { struct device dev; };
struct t2bce_device {
  struct pci_dev *pci, *pci0, *pci2, *pci3;
  unsigned long pci_async_suspend_mask;
};

static bool device_async_suspend_enabled(struct device *dev) {
  return dev->async_suspend;
}
static void device_disable_async_suspend(struct device *dev) {
  dev->async_suspend = false;
}
static void device_enable_async_suspend(struct device *dev) {
  dev->async_suspend = true;
}
'''
harness += disable + restore
harness += r'''
int main(void) {
  struct pci_dev functions[4];
  struct t2bce_device bce = {
    .pci0 = &functions[0], .pci = &functions[1],
    .pci2 = &functions[2], .pci3 = &functions[3]
  };

  for (unsigned long original = 0; original < BIT(4); original++) {
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++)
      functions[i].dev.async_suspend = original & BIT(i);

    bce_pm_disable_shared_async(&bce);
    assert(bce.pci_async_suspend_mask == original);
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++)
      assert(!functions[i].dev.async_suspend);

    bce_pm_restore_shared_async(&bce);
    assert(bce.pci_async_suspend_mask == 0);
    for (size_t i = 0; i < ARRAY_SIZE(functions); i++)
      assert(functions[i].dev.async_suspend == !!(original & BIT(i)));
  }
  return 0;
}
'''

with tempfile.TemporaryDirectory() as temp_dir:
  source = Path(temp_dir) / "shared-pci-pm.c"
  binary = Path(temp_dir) / "shared-pci-pm"
  source.write_text(harness)
  subprocess.run(
    ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
    check=True,
  )
  subprocess.run([str(binary)], check=True)

print("PASS: shared T2 PCI PM callbacks are serialized and original async policy is restored")
