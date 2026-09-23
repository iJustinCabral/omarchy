#!/usr/bin/env python3
"""Execute extracted candidate C with PCI/IRQ/DMA/HCI fault injection."""
from pathlib import Path
import subprocess, tempfile
H=Path(__file__).resolve().parent
import sys
s=Path(sys.argv[1]).read_text()
def function(name):
    import re
    m=re.search(r'static (?:int|void|irqreturn_t) '+name+r'\([^;]+?\)\n\{',s)
    assert m,name
    start=m.start(); i=m.end(); depth=1
    while depth:
        depth += (s[i]=='{')-(s[i]=='}'); i+=1
    return s[start:i]+'\n'
def run(name, code):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d); (p/'t.c').write_text(code)
        subprocess.run(['cc','-Wall','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-but-set-variable','-o',str(p/'t'),str(p/'t.c')],check=True)
        subprocess.run([str(p/'t')],check=True)
    print('PASS:',name)
common=r'''
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define WRITE_ONCE(a,b) ((a)=(b))
#define READ_ONCE(a) (a)
#define dev_info(...) ((void)0)
#define dev_err(...) ((void)0)
struct device {int dummy;}; struct pci_dev {struct device dev;};
struct hw {int id;bool disable_aspm;};
struct hci_dev {void *data;unsigned long flags;};
struct bcm4377_data {struct pci_dev *pdev;struct hw *hw;struct hci_dev *hdev;bool transport_lost,resume_config_failed,irq_blocked,setup_needed,pm_blocked;};
static int disabled,locked,master,resets,zeroed,fail,stage,queued,creates;
static int pci_irq_vector(struct pci_dev *p,int i){return 5;}
static void disable_irq(int i){assert(!disabled);disabled=1;}
static void enable_irq(int i){assert(disabled);disabled=0;}
static void synchronize_irq(int i){}
static void pci_cfg_access_lock(struct pci_dev *p){assert(!locked);locked=1;}
static void pci_cfg_access_unlock(struct pci_dev *p){assert(locked);locked=0;}
static void pci_clear_master(struct pci_dev *p){master=0;}
static void pci_set_master(struct pci_dev *p){assert(zeroed);master=1;}
static int step(int n){stage=n;return fail==n?-EIO:0;}
static int pcie_reset_flr(struct pci_dev *p,bool probe){if(probe)return step(1);assert(locked&&disabled&&!master);int r=step(3);if(!r)resets++;return r;}
static int pci_save_state(struct pci_dev *p){assert(!master);return step(2);}
static void pci_restore_state(struct pci_dev *p){assert(!master);}
static void msleep(int n){assert(n==100&&resets);}
static int bcm4377_init_cfg(struct bcm4377_data *b){return step(4);}
static int pcibios_err_to_errno(int r){return r;}
static int bcm4377_verify_cfg(struct bcm4377_data *b){return step(5);}
static void bcm4377_disable_aspm(struct bcm4377_data *b){}
static void bcm4377_reset_rings(struct bcm4377_data *b){assert(resets&&disabled&&!master&&locked);zeroed++;}
static void dma_wmb(void){assert(zeroed&&!master);}
static int bcm4377_boot(struct bcm4377_data *b){assert(!disabled&&!locked&&master&&!b->irq_blocked&&b->transport_lost);return step(6);}
static int bcm4377_setup_rti(struct bcm4377_data *b){assert(stage==6);return step(7);}
'''
run('FLR support/save/reset/config/readback/boot/RTI failures; DMA order; IRQ balance',common+function('bcm4377_recover_transport')+r'''
int main(void){
 for(fail=0;fail<=7;fail++){
  struct pci_dev p={0};struct hw hw={.id=0x4377,.disable_aspm=true};
  struct bcm4377_data b={.pdev=&p,.hw=&hw,.transport_lost=true,.irq_blocked=true};
  disabled=locked=resets=zeroed=stage=0;master=1;
  int ret=bcm4377_recover_transport(&b);
  assert(!disabled&&!locked);assert(zeroed==(fail==0||fail>=6));
  if(fail){assert(ret==-EIO&&b.transport_lost&&b.irq_blocked&&b.resume_config_failed&&!master&&!b.setup_needed);}
  else {assert(!ret&&!b.transport_lost&&!b.irq_blocked&&!b.resume_config_failed&&master&&b.setup_needed);}
 }
}
''')
# Reuse the actual open/complete functions, replacing only external operations.
open_common=common[:common.index('static int pcie_reset_flr')]+r'''
static struct bcm4377_data *hci_get_drvdata(struct hci_dev *h){return h->data;}
static int bcm4377_recover_transport(struct bcm4377_data *b){resets++;if(fail==1)return -EIO;b->transport_lost=false;return 0;}
static int bcm4377_hci_create_rings(struct hci_dev *h){creates++;return fail==2?-ETIMEDOUT:0;}
static struct pci_dev pci;
static struct bcm4377_data state;
static struct pci_dev *to_pci_dev(struct device *d){return &pci;}
static struct bcm4377_data *pci_get_drvdata(struct pci_dev *p){return &state;}
#define HCI_UP 0
static bool test_bit(int bit,unsigned long *v){return *v&1;}
static int hci_reset_dev(struct hci_dev *h){queued++;return 0;}
'''
run('PM-open exclusion, initially-off deferred recovery, reset/create failure, complete queue gating',open_common+function('bcm4377_hci_open')+function('bcm4377_complete')+r'''
int main(void){
 struct hw hw={.id=0x4377};struct hci_dev h={.data=&state};
 state=(struct bcm4377_data){.pdev=&pci,.hw=&hw,.hdev=&h,.pm_blocked=true,.transport_lost=true};
 assert(bcm4377_hci_open(&h)==-EBUSY&&!resets&&!creates);
 bcm4377_complete(&pci.dev);assert(!queued&&!state.pm_blocked&&state.transport_lost);
 assert(!bcm4377_hci_open(&h)&&resets==1&&creates==1&&!state.transport_lost);
 state.transport_lost=true;h.flags=1;bcm4377_complete(&pci.dev);assert(queued==1);
 fail=1;assert(bcm4377_hci_open(&h)==-EIO&&creates==1&&state.transport_lost);
 fail=2;assert(bcm4377_hci_open(&h)==-ETIMEDOUT&&state.transport_lost&&state.irq_blocked&&!master);
 fail=0;assert(!bcm4377_hci_open(&h)&&!state.transport_lost);
 bcm4377_complete(&pci.dev);assert(queued==1);
}
''')
# Existing restore and transfer-publication harnesses, applied to this actual C.
for rel in ('test-restore.py','test-create-failure.py'):
    test=(H/rel).read_text()
    test=test.replace('h=Path(__file__).resolve().parent',f'h=Path({str(H)!r})')
    if 'test-restore' in rel:
        test=test.replace("s.index('static const struct dev_pm_ops bcm4377_ops')", "s.index('/* Queue the core-owned close/open')")
        test=test.replace('bool resume_config_failed;', 'bool resume_config_failed, transport_lost, irq_blocked;')
    exec(compile(test,rel,'exec'),{'__file__':str(H/'test-recovery.py')})
# Source ownership invariants checked against final source, not generator text.
probe=function('bcm4377_probe')
assert probe.index('bcm4377_prepare_firmware_buffer') < probe.index('devm_request_irq')
assert probe.index('bcm4377_hci_free_dev') < probe.index('bcm4377_stop_dma') < probe.index('hci_register_dev')
assert 'if (!bcm4377->firmware_buffer)' in function('bcm4377_boot')
assert 'pci_reset_function' not in function('bcm4377_recover_transport')
assert 'device_lock(' not in function('bcm4377_recover_transport')
assert function('bcm4377_irq').index('bcm4377->rti_status = rti_status') < function('bcm4377_irq').index('complete(&bcm4377->event)')
print('PASS: resource lifetime, persistent firmware buffer, FLR-only API and completion publication')
ring_stub=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BCM4377_MAX_RING_SIZE 64
#define bitmap_zero(p,n) memset(p,0,8)
struct bcm4377_xfer_ring_entry {char bytes[16];};
struct bcm4377_completion_ring_entry {char bytes[16];};
struct bcm4377_transfer_ring {bool enabled;uint8_t generation;uint64_t msgids[1];void **events;void *ring,*payloads;unsigned n_entries,payload_size,mapped_payload_size;};
struct bcm4377_completion_ring {bool enabled;void *ring;unsigned n_entries,payload_size;};
struct ring_state {char bytes[60];};
struct bcm4377_data {
 struct bcm4377_transfer_ring control_h2d_ring,hci_h2d_ring,hci_d2h_ring,sco_h2d_ring,sco_d2h_ring,acl_h2d_ring,acl_d2h_ring;
 struct bcm4377_completion_ring control_ack_ring,hci_acl_ack_ring,hci_acl_event_ring,sco_ack_ring,sco_event_ring;
 struct ring_state *ring_state;unsigned bootstage,rti_status,event;
};
static void reinit_completion(unsigned *e){*e=0;}
'''
run('all 12 rings reset in place, virtual/null storage, generations and DMA buffer boundaries',ring_stub+function('bcm4377_reset_rings')+r'''
int main(void){
 struct ring_state rs;memset(&rs,0xa5,sizeof(rs));
 struct bcm4377_data b={.ring_state=&rs,.bootstage=2,.rti_status=2,.event=10};
 struct bcm4377_transfer_ring *t[]={&b.control_h2d_ring,&b.hci_h2d_ring,&b.hci_d2h_ring,&b.sco_h2d_ring,&b.sco_d2h_ring,&b.acl_h2d_ring,&b.acl_d2h_ring};
 struct bcm4377_completion_ring *c[]={&b.control_ack_ring,&b.hci_acl_ack_ring,&b.hci_acl_event_ring,&b.sco_ack_ring,&b.sco_event_ring};
 unsigned char tr[7][41],pl[7][17],cr[5][41];void *ev[7][2];
 memset(tr,0xa5,sizeof(tr));memset(pl,0xa5,sizeof(pl));memset(cr,0xa5,sizeof(cr));memset(ev,0xa5,sizeof(ev));
 for(int i=0;i<7;i++)*t[i]=(struct bcm4377_transfer_ring){.enabled=true,.generation=255,.msgids={~0ULL},.events=i==0?ev[i]:0,.ring=i==2||i==4?0:tr[i],.payloads=i>=5?pl[i]:0,.n_entries=2,.payload_size=4,.mapped_payload_size=8};
 for(int i=0;i<5;i++)*c[i]=(struct bcm4377_completion_ring){.enabled=true,.ring=cr[i],.n_entries=2,.payload_size=4};
 bcm4377_reset_rings(&b);
 assert(b.ring_state==&rs&&!b.bootstage&&!b.rti_status&&!b.event);
 for(int i=0;i<60;i++)assert(!rs.bytes[i]);
 for(int i=0;i<7;i++){
  assert(!t[i]->enabled&&!t[i]->generation&&!t[i]->msgids[0]);
  for(int j=0;j<40;j++)assert(tr[i][j]==(i==2||i==4?0xa5:0));assert(tr[i][40]==0xa5);
  for(int j=0;j<16;j++)assert(pl[i][j]==(i>=5?0:0xa5));assert(pl[i][16]==0xa5);
 }
 assert(!ev[0][0]&&!ev[0][1]);
 for(int i=0;i<5;i++){assert(!c[i]->enabled&&c[i]->ring==cr[i]);for(int j=0;j<40;j++)assert(!cr[i][j]);assert(cr[i][40]==0xa5);}
}
'''.replace('));assert(tr', '));\n  assert(tr').replace('));assert(pl', '));\n  assert(pl'))
setup_stub=r'''
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#define dev_err(...) ((void)0)
struct firmware {int x;};struct pci_dev {int dev;};struct hci_dev {void *data;};
struct bcm4377_data;
struct hw {unsigned id;int (*send_calibration)(struct bcm4377_data *);int (*send_ptb)(struct bcm4377_data *,const struct firmware *);};
struct bcm4377_data {struct hw *hw;struct pci_dev *pdev;bool setup_needed;};
static int fail,ptb,bdaddr,requested;
static struct firmware fw;
static void *hci_get_drvdata(struct hci_dev *h){return h->data;}
static const struct firmware *bcm4377_request_blob(struct bcm4377_data *b,const char *kind){requested++;return fail==1?0:&fw;}
static void release_firmware(const struct firmware *f){}
static int send_ptb(struct bcm4377_data *b,const struct firmware *f){ptb++;return fail==2?-EIO:0;}
static int bcm4377_check_bdaddr(struct bcm4377_data *b){bdaddr++;return fail==3?-EIO:0;}
'''
run('PTB setup repeats after cold recovery; remains pending on firmware/PTB/address errors',setup_stub+function('bcm4377_hci_setup')+r'''
int main(void){
 struct hw hw={.id=0x4377,.send_ptb=send_ptb};struct bcm4377_data b={.hw=&hw};struct hci_dev h={.data=&b};
 assert(!bcm4377_hci_setup(&h)&&!requested);
 for(fail=0;fail<=3;fail++){
  b.setup_needed=true;requested=ptb=bdaddr=0;
  int ret=bcm4377_hci_setup(&h);
  assert(requested==1);assert(b.setup_needed==(fail!=0));assert((ret!=0)==(fail!=0));
 }
}
''')
