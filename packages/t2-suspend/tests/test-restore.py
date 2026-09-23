#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
h=Path(__file__).resolve().parent
import sys
s=Path(sys.argv[1]).read_text()
assert s.count('return IRQ_HANDLED;') == 2, 'IRQ-only return leaked into another callback'
f=s[s.index('static int bcm4377_resume_noirq('):s.index('static const struct dev_pm_ops bcm4377_ops')]
stub=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
typedef uint16_t u16; typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BIT(n) (1U<<(n))
#define WRITE_ONCE(a,b) ((a)=(b))
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define BCM4377_PCIECFG_BAR0_CORE2_WINDOW1_DEFAULT 0x18011000
#define BCM4377_PCIECFG_BAR2_WINDOW_DEFAULT 0x19000000
struct device {int x;}; struct pci_dev {int x;};
struct hw {unsigned id; u32 bar0_window1,bar0_window2;};
struct bcm4377_data {struct hw *hw; bool resume_config_failed;};
static struct hw hw={0x4377,0x1800b000,0x1810c000};
static struct bcm4377_data state={&hw,false};
static struct pci_dev pci;
static u32 cfg[64]; static int count, fail_at, corrupt, init_calls;
static struct pci_dev *to_pci_dev(struct device *d){return &pci;}
static struct bcm4377_data *pci_get_drvdata(struct pci_dev *p){return &state;}
static int pci_read_config_dword(struct pci_dev *p,int o,u32 *v){
 if(++count==fail_at)return 0x87; *v=cfg[o/4];return 0;
}
static int pcibios_err_to_errno(int r){return r?-EIO:0;}
static int bcm4377_init_cfg(struct bcm4377_data *b){
 init_calls++;
 if(++count==fail_at)return 0x87;
 cfg[0x70/4]=hw.bar0_window2; cfg[0x74/4]=0x18011000;
 cfg[0x80/4]=hw.bar0_window1;cfg[0x84/4]=0x19000000;cfg[0x88/4]|=BIT(16);
 if(corrupt)cfg[0x80/4]=0;return 0;
}
'''
tests=r'''
int main(void){struct device dev;
 for(int failure=0;failure<=11;failure++){
  count=0;fail_at=failure;corrupt=0;state.resume_config_failed=false;
  int rc=bcm4377_resume_noirq(&dev);
  assert(rc==(failure?-EIO:0));assert(state.resume_config_failed==(failure!=0));
 }
 count=0;fail_at=0;corrupt=1;assert(bcm4377_resume_noirq(&dev)==-EIO);assert(state.resume_config_failed);
 count=0;corrupt=0;assert(!bcm4377_resume_noirq(&dev));assert(!state.resume_config_failed);
 hw.id=0x4378;init_calls=0;assert(!bcm4377_resume_noirq(&dev));assert(!init_calls);
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d); (p/'t.c').write_text(stub+f+tests)
 subprocess.run(['cc','-o',str(p/'t'),str(p/'t.c')],check=True)
 subprocess.run([str(p/'t')],check=True)
for name,end in [('bcm4377_irq','static int bcm4377_enqueue'),('bcm4377_resume','/* PCI core'),('bcm4377_ring_doorbell','static int bcm4377_extract_msgid')]:
 # These guards must precede any BAR access in their own function.
 start=s.index('static irqreturn_t '+name+'(') if name.endswith('_irq') else s.index('static int '+name+'(') if name.endswith('_resume') else s.index('static void '+name+'(')
 body=s[start:s.index(end,start)]
 assert body.index('resume_config_failed') < min([body.index(x) for x in ('ioread32','iowrite32') if x in body])
print('PASS: actual restore function: config failures, bad readback, success/retry, sibling exclusion; MMIO guards precede accesses')
