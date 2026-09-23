#!/usr/bin/env python3
"""Run the actual FLR helper with injected PCI/config/CPU-stop failures."""
from pathlib import Path
import subprocess
import tempfile
here=Path(__file__).resolve().parent
helper=(here/'function-reset.c.inc').read_text()
base=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
typedef uint32_t u32; typedef uint16_t u16;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define PCI_VENDOR_ID_BROADCOM 0x14e4
#define PCI_FUNC(v) ((v)&7)
#define BRCM_CC_4377_CHIP_ID 4377
#define BCMA_CORE_ARM_CR4 0x83e
#define BIT(n) (1U<<(n))
#define DMI_SYS_VENDOR 1
#define DMI_PRODUCT_NAME 2
#define BRCMF_BUS_DOWN 0
#define BRCMFMAC_PCIE_STATE_DOWN 0
#define PCI_COMMAND 4
#define PCI_COMMAND_INTX_DISABLE 0x400
#define dev_info(...) ((void)0)
#define dev_err(...) ((void)0)
struct device {int dummy;};
struct pci_dev {int vendor,device,devfn;struct device dev;};
struct brcmf_bus {int dummy;};
struct brcmf_core {int dummy;};
struct chip {int chip;};
struct brcmf_pciedev_info {struct pci_dev *pdev;struct chip *ci;int state;bool recovery_flr;};
static struct brcmf_core arm;
static struct brcmf_bus bus;
static int model=1,have_arm=1,fail,step,locked,master=1,irq=1,resets,held,probes,config_disabled;
static bool mismatch,allones;
static int next(void) {return ++step==fail?-EIO:0;}
static void *dev_get_drvdata(struct device *d) {(void)d;return &bus;}
static int dmi_match(int id,const char *s) {(void)id;(void)s;return model;}
static struct brcmf_core *brcmf_chip_get_core(struct chip *c,int id) {(void)c;(void)id;return have_arm?&arm:0;}
static int pcie_reset_flr(struct pci_dev *p,bool probe) {
 (void)p;if(probe){probes++;return next();}
 assert(!master&&!irq&&locked&&config_disabled);int r=next();if(!r)resets++;return r;
}
static void brcmf_pcie_fwcon_timer(struct brcmf_pciedev_info *d,bool v) {(void)d;assert(!v);}
static void brcmf_bus_change_state(struct brcmf_bus *b,int s) {(void)b;assert(!s);}
static void brcmf_pcie_release_irq(struct brcmf_pciedev_info *d) {assert(!d->state);irq=0;}
static void pci_cfg_access_lock(struct pci_dev *p) {(void)p;assert(!locked);locked=1;}
static void pci_cfg_access_unlock(struct pci_dev *p) {(void)p;assert(locked);locked=0;}
static void pci_clear_master(struct pci_dev *p) {(void)p;master=0;}
static int pci_read_config_dword(struct pci_dev *p,u16 o,u32 *v) {
 (void)p;assert(locked&&!master);*v=allones?~0U:(u32)o+(mismatch&&resets?1:0);return next();
}
static int pci_write_config_dword(struct pci_dev *p,u16 o,u32 v) {(void)p;assert(resets&&locked&&!master&&v==o);return next();}
static int pcibios_err_to_errno(int n) {return n;}
static int pci_save_state(struct pci_dev *p) {(void)p;assert(!master&&locked);return next();}
static int pci_write_config_word(struct pci_dev *p,int o,int v) {(void)p;assert(o==4&&v==0x400);config_disabled=1;return next();}
static void pci_restore_state(struct pci_dev *p) {(void)p;assert(!master);config_disabled=0;}
static void brcmf_chip_set_passive(struct chip *c) {(void)c;assert(resets&&!master&&!irq);}
static void brcmf_chip_coredisable(struct brcmf_core *c,u32 a,u32 b) {(void)c;(void)a;(void)b;held=1;}
static bool brcmf_chip_iscoreup(struct brcmf_core *c) {(void)c;assert(held);return next()!=0;}
'''
main=r'''
int main(void) {
 struct pci_dev p={0x14e4,0x4488,0,{0}};struct chip c={4377};
 struct brcmf_pciedev_info d={&p,&c,1,false};
 for(fail=0;fail<=20;fail++) {
  step=locked=resets=held=probes=config_disabled=0;master=irq=1;d.state=1;d.recovery_flr=false;
  int ret=brcmf_pcie_recovery_flr(&d);
  assert(!locked);assert((ret==0)==(fail==0));
  if(fail==1) assert(master&&irq&&!d.recovery_flr);
  else assert(!master&&!irq&&d.recovery_flr);
  if(!ret)assert(resets==1&&held);
 }
 fail=0;step=resets=0;mismatch=true;
 assert(brcmf_pcie_recovery_flr(&d)==-EIO&&!locked);mismatch=false;
 step=resets=0;allones=true;assert(brcmf_pcie_recovery_flr(&d)==-EIO&&!locked);allones=false;
 model=0;assert(brcmf_pcie_recovery_flr(&d)==-ENODEV);model=1;
 p.device=0x5fa0;assert(brcmf_pcie_recovery_flr(&d)==-ENODEV);p.device=0x4488;
 p.devfn=1;assert(brcmf_pcie_recovery_flr(&d)==-ENODEV);p.devfn=0;
 have_arm=0;assert(brcmf_pcie_recovery_flr(&d)==-ENODEV);
 puts("PASS: PCI/config/CPU-stop failures; DMA/IRQ order; no fallback; hardware guards");
}
'''
with tempfile.TemporaryDirectory(prefix='t2-flr-test-') as td:
 p=Path(td);(p/'test.c').write_text(base+helper+main)
 subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
