#!/usr/bin/python3
"""Extract prototype and pinned PCI recovery callbacks; never access host PCI."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 2, "usage: test-cold-pci-guard.py LINUX_7_2_6_ROOT"
kernel = Path(sys.argv[1])
source = (Path(__file__).resolve().parents[1] / "experiments/hibernate-cold-pci-guard/mba_hibernate_cold_pci_guard.c").read_text()
pci = (kernel / "drivers/pci/pci-driver.c").read_text()
pm = (kernel / "drivers/base/power/main.c").read_text()
for key, value in (("VERSION", 7), ("PATCHLEVEL", 2), ("SUBLEVEL", 6)):
  assert re.search(rf"^{key} = {value}$", (kernel / "Makefile").read_text(), re.M)

def function(text, name):
  match = re.search(r"^(?:static )?(?:void|int) " + name + r"\([^;]+?\)\n\{", text, re.M)
  assert match, name
  index, depth = match.end(), 1
  while depth:
    depth += (text[index] == "{") - (text[index] == "}")
    index += 1
  return text[match.start():index] + "\n"

end = function(pm, "dpm_resume_end")
assert end.index("dpm_resume(state)") < end.index("dpm_complete(state)")
save = function((kernel / "drivers/pci/pci.c").read_text(), "pci_save_state")
assert save.index("dev->state_saved = true") < save.index("pci_save_pcie_state")
assert ".complete = mba_complete" in source and ".thaw =" not in source
assert "pci_enable_device" not in source and "pci_request_irq" not in source

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define __iomem
#define ANS_CC 0x14
#define ANS_CSTS 0x1c
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BIT(i) (1UL << (i))
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define PCI_VENDOR_ID_APPLE 0x106b
#define PCI_CLASS_STORAGE_EXPRESS 0x010802
#define PCI_FUNC(v) ((v)&7)
#define PCI_SLOT(v) ((v)>>3)
#define PCI_DEVFN(s,f) (((s)<<3)|(f))
#define IORESOURCE_MEM 1
#define GFP_KERNEL 0
#define WARN_ON(x) assert(!(x))
typedef uint32_t u32;
typedef uint16_t u16;
struct pci_dev;
struct device;
struct dev_pm_ops {
  int (*freeze_noirq)(struct device *); int (*thaw_noirq)(struct device *);
  int (*thaw)(struct device *); void (*complete)(struct device *);
};
struct driver { const struct dev_pm_ops *pm; };
struct device { struct pci_dev *pdev; struct driver *driver; bool async; };
struct pci_driver { const char *name; };
struct pci_device_id { int unused; };
struct pci_dev {
  struct device dev;
  int index, refs, devfn, bus, enable_cnt, current_state;
  u16 vendor, device, command;
  u32 class, saved_config_space[16];
  bool state_saved;
  struct pci_driver *driver;
  void *data;
};
struct mba_guard {
  struct pci_dev *functions[4]; void *ans_regs;
  unsigned long async_mask, original_master_mask;
  bool active, gate_failed;
};
struct kernel_param { int unused; };
static struct mba_guard *instance;
static bool armed, arm_consumed;
static bool gate_active, gate_failed;
static unsigned int gates;
static char vector_prefix[25];
static struct pci_dev devices[4];
static struct pci_driver nvme = { .name="nvme" }, other = { .name="unexpected" };
static u32 regs[8];
static int missing=-1, map_fail, maps, frees, ref_puts;
static unsigned int clear_fail, save_fail, read_fail;
static bool main_recovered;
static unsigned int enabled_before_main;
static unsigned int generic_reenables;
typedef int pci_power_t;
static void *kzalloc(size_t size, int flags) { (void)flags; return calloc(1,size); }
static void kfree(void *p) { frees++; free(p); }
static struct pci_dev *to_pci_dev(struct device *dev) { return dev->pdev; }
static void *pci_get_drvdata(struct pci_dev *p) { return p->data; }
static void pci_set_drvdata(struct pci_dev *p, void *data) { p->data=data; }
static bool pci_is_enabled(struct pci_dev *p) {return p->enable_cnt>0;}
static struct pci_dev *pci_get_slot(int bus, int fn) {
  (void)bus; int i=PCI_FUNC(fn); if(i==missing) return NULL; devices[i].refs++; return &devices[i];
}
static void pci_dev_put(struct pci_dev *p) { assert(p->refs>0); p->refs--; ref_puts++; }
static bool device_async_suspend_enabled(struct device *d) {return d->async;}
static void device_disable_async_suspend(struct device *d) {d->async=false;}
static void device_enable_async_suspend(struct device *d) {d->async=true;}
static unsigned long pci_resource_flags(struct pci_dev *p,int bar) {(void)p;(void)bar;return IORESOURCE_MEM;}
static unsigned long pci_resource_len(struct pci_dev *p,int bar) {(void)p;(void)bar;return sizeof(regs);}
static unsigned long pci_resource_start(struct pci_dev *p,int bar) {(void)p;(void)bar;return 1;}
static void *ioremap(unsigned long start, size_t size) {(void)start;(void)size;if(map_fail)return NULL;maps++;return regs;}
static void iounmap(void *p) {assert(p==regs);maps--;}
static u32 readl(void *p) {return *(u32 *)p;}
static int pci_read_config_word(struct pci_dev *p,int reg,u16 *v) {
  assert(reg==PCI_COMMAND); if(read_fail&BIT(p->index))return -EIO; *v=p->command;return 0;
}
static void pci_clear_master(struct pci_dev *p) {
  if(clear_fail&BIT(p->index))p->command|=PCI_COMMAND_MASTER;
  else p->command&=~PCI_COMMAND_MASTER;
}
static void pci_set_master(struct pci_dev *p) {
  if(!main_recovered) enabled_before_main++;
  p->command|=PCI_COMMAND_MASTER;
}
static int pci_save_state(struct pci_dev *p) {
  p->saved_config_space[1]=p->command;p->state_saved=true;
  return save_fail&BIT(p->index)?-EIO:0;
}
static void pci_restore_state(struct pci_dev *p) {
  if(p->state_saved){p->command=(u16)p->saved_config_space[1];p->state_saved=false;}
}
static bool pci_has_legacy_pm_support(struct pci_dev *p) {(void)p;return false;}
static int pci_legacy_suspend_late(struct device *d) {(void)d;assert(false);return 0;}
static void suspend_report_result(struct device *d,int(*cb)(struct device *),int e){(void)d;(void)cb;(void)e;}
static void pci_pm_set_unknown_state(struct pci_dev *p){(void)p;}
static void pci_pm_power_up_and_verify_state(struct pci_dev *p){(void)p;}
static int pci_legacy_resume(struct device *d){(void)d;assert(false);return 0;}
static int pci_pm_reenable_device(struct pci_dev *p){generic_reenables++;pci_set_master(p);return 0;}
static void pci_dev_complete_resume(struct pci_dev *p){(void)p;}
static void pm_generic_complete(struct device *d){if(d->driver && d->driver->pm->complete)d->driver->pm->complete(d);}
static bool pm_runtime_suspended(struct device *d){(void)d;return false;}
static bool pm_resume_via_firmware(void){return false;}
static void pci_refresh_power_state(struct pci_dev *p){(void)p;}
static void pm_request_resume(struct device *d){(void)d;assert(false);}
static void dev_pm_set_strict_midlayer(struct device *d,bool enabled){(void)d;(void)enabled;}
'''
harness += "".join(function(source, name) for name in (
  "mba_set_arm_prefix", "mba_get_arm_prefix", "mba_prepare", "mba_freeze",
  "mba_freeze_noirq", "mba_thaw_noirq", "mba_complete", "mba_release", "mba_probe", "mba_remove"))
harness += "".join(function(pci, name) for name in (
  "pci_pm_freeze_noirq", "pci_pm_thaw_noirq", "pci_pm_thaw", "pci_pm_complete"))
harness += r'''
static const struct dev_pm_ops ops={.freeze_noirq=mba_freeze_noirq,.thaw_noirq=mba_thaw_noirq,.complete=mba_complete};
static struct driver bus_driver={.pm=&ops};
static void reset(void) {
  assert(!instance && !maps); memset(devices,0,sizeof(devices));memset(regs,0,sizeof(regs));
  const u16 ids[]={0x2005,0x1801,0x1802,0x1803};
  for(int i=0;i<4;i++) {
    devices[i].index=i;devices[i].devfn=i;devices[i].vendor=PCI_VENDOR_ID_APPLE;devices[i].device=ids[i];
    devices[i].dev.pdev=&devices[i];devices[i].dev.async=true;devices[i].command=0x100|PCI_COMMAND_MASTER;
  }
  devices[0].driver=&nvme;devices[0].class=PCI_CLASS_STORAGE_EXPRESS;devices[1].dev.driver=&bus_driver;
  devices[0].command=0x100;
  armed=arm_consumed=false;gates=0;vector_prefix[0]=0;
  gate_active=gate_failed=false;generic_reenables=0;
  missing=-1;map_fail=0;clear_fail=save_fail=read_fail=0;main_recovered=false;enabled_before_main=0;
}
static void probe_arm(void) {
  char value[8];assert(mba_probe(&devices[1],NULL)==0);assert(instance);
  assert(mba_prepare(&devices[1].dev)==-EPERM && mba_freeze(&devices[1].dev)==-EPERM);
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==0);
  assert(mba_get_arm_prefix(value,NULL)==2 && !strcmp(value,"1\n"));
  assert(mba_prepare(&devices[1].dev)==0 && mba_freeze(&devices[1].dev)==0);
}
static void recover(void) {
  // Exercise the actual pinned PCI wrappers in both sibling orders, including
  // PCI core's snapshot restore BEFORE guard thaw_noirq.
  for(int i=3;i>=0;i--) {
    int result=pci_pm_thaw_noirq(&devices[i].dev);
    assert(result==0 || (i==1 && result==-EIO));
  }
  for(int i=0;i<4;i++) assert(!(devices[i].command&PCI_COMMAND_MASTER));
  assert(enabled_before_main==0);
  assert(pci_pm_thaw(&devices[1].dev)==0);
  assert(generic_reenables==0 && enabled_before_main==0);
  main_recovered=true;
  pci_set_master(&devices[0]); // ANS main recovery uses fresh queues.
  pci_pm_complete(&devices[1].dev);
  assert(!instance->active && !gate_active);
  for(int i=0;i<4;i++) assert(devices[i].command&PCI_COMMAND_MASTER);
}
static void remove_guard(void) {
  mba_remove(&devices[1]);assert(!instance && !maps);
  for(int i=0;i<4;i++)assert(devices[i].refs==0 && devices[i].dev.async);
}
int main(void) {
  reset();assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==-EPERM);
  assert(pci_pm_thaw(&devices[2].dev)==0 && generic_reenables==1);
  for(int absent=0;absent<4;absent++) {
    reset();missing=absent;assert(mba_probe(&devices[1],NULL)==-ENODEV);
    for(int i=0;i<4;i++)assert(!devices[i].refs && devices[i].dev.async);
  }
  reset();map_fail=1;assert(mba_probe(&devices[1],NULL)==-ENOMEM);
  for(int i=0;i<4;i++)assert(!devices[i].refs && devices[i].dev.async);
  for(int conflict=0;conflict<4;conflict+=2) {
    reset();devices[conflict].driver=&other;assert(mba_probe(&devices[1],NULL)==-ENODEV);
    for(int i=0;i<4;i++)assert(!devices[i].refs && devices[i].dev.async);
  }
  for(int proof=0;proof<4;proof++) {
    reset();probe_arm();if(proof==0)regs[ANS_CC/4]=1;if(proof==1)regs[ANS_CSTS/4]=1;
    if(proof==2)regs[ANS_CC/4]=~0U;
    if(proof==3)regs[ANS_CSTS/4]=~0U;
    assert(mba_freeze_noirq(&devices[1].dev)==-EBUSY && !instance->active && gate_failed && !gate_active);
    for(int i=0;i<4;i++)assert(!!(devices[i].command&PCI_COMMAND_MASTER)==(i!=0));
    assert(mba_freeze_noirq(&devices[1].dev)==-EPERM);remove_guard();
  }
  reset();probe_arm();read_fail=BIT(2);assert(mba_freeze_noirq(&devices[1].dev)==-EIO && !instance->active);
  for(int i=0;i<4;i++)assert(!!(devices[i].command&PCI_COMMAND_MASTER)==(i!=0));
  read_fail=0;remove_guard();
  reset();probe_arm();devices[0].enable_cnt=1;
  assert(mba_freeze_noirq(&devices[1].dev)==-EBUSY && !instance->active);remove_guard();
  reset();probe_arm();devices[0].command|=PCI_COMMAND_MASTER;
  assert(mba_freeze_noirq(&devices[1].dev)==-EBUSY && !instance->active);remove_guard();
  reset();probe_arm();regs[ANS_CC/4]=1|(1U<<14);regs[ANS_CSTS/4]=1|(1U<<2);
  assert(mba_freeze_noirq(&devices[1].dev)==-EBUSY && !instance->active);remove_guard();
  reset();probe_arm();regs[ANS_CC/4]=1|(1U<<14);regs[ANS_CSTS/4]=1|(2U<<2);
  assert(pci_pm_freeze_noirq(&devices[1].dev)==0);recover();remove_guard();
  for(unsigned mask=0;mask<16;mask+=2) {
    reset();probe_arm();for(int i=0;i<4;i++)devices[i].command=0x100|((mask&BIT(i))?PCI_COMMAND_MASTER:0);
    assert(pci_pm_freeze_noirq(&devices[1].dev)==0);
    assert(gate_active && !gate_failed);
    for(int i=0;i<4;i++)assert(devices[i].command==0x100 && devices[i].saved_config_space[1]==0x100);
    for(int i=0;i<4;i++)assert(pci_pm_freeze_noirq(&devices[i].dev)==(i==1?-EPERM:0));
    for(int i=0;i<4;i++)assert(pci_pm_thaw_noirq(&devices[i].dev)==0);
    assert(!enabled_before_main);
    assert(pci_pm_thaw(&devices[1].dev)==0 && !generic_reenables);
    main_recovered=true;pci_set_master(&devices[0]);pci_pm_complete(&devices[1].dev);
    assert(!gate_active && !gate_failed);
    for(int i=0;i<4;i++)assert(!!(devices[i].command&PCI_COMMAND_MASTER)==(i==0 || !!(mask&BIT(i))));
    remove_guard();
  }
  for(int fail=0;fail<4;fail++) {
    reset();probe_arm();clear_fail=BIT(fail);assert(pci_pm_freeze_noirq(&devices[1].dev)==-EIO);
    assert(instance->active && instance->gate_failed && gate_active && gate_failed && !enabled_before_main);
    for(int i=0;i<4;i++)assert(!(devices[i].saved_config_space[1]&PCI_COMMAND_MASTER));
    clear_fail=0;recover();remove_guard();
    reset();probe_arm();save_fail=BIT(fail);assert(pci_pm_freeze_noirq(&devices[1].dev)==-EIO);
    assert(instance->active && instance->gate_failed && gate_active && gate_failed && !enabled_before_main);
    for(int i=0;i<4;i++)assert(!(devices[i].saved_config_space[1]&PCI_COMMAND_MASTER));
    save_fail=0;recover();remove_guard();
  }
  assert(frees>0 && ref_puts>0);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="cold-pci-guard-test-") as temporary:
  c = Path(temporary) / "test.c"
  binary = Path(temporary) / "test"
  c.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(c), "-o", str(binary)], check=True)
  subprocess.run([str(binary)], check=True)
print("PASS: extracted cold PCI guard proof/refusal, reference cleanup, partial-gate recovery and pinned PCI saved-config replay")
