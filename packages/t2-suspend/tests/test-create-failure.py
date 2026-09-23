#!/usr/bin/env python3
"""Run actual create_transfer_ring C with a failing/successful control transport."""
from pathlib import Path
import subprocess,tempfile
h=Path(__file__).resolve().parent
import sys
s=Path(sys.argv[1]).read_text();a=s.index('static int bcm4377_create_transfer_ring(');b=s.index('static int bcm4377_destroy_transfer_ring(',a)
f=s[a:b]
stub=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define cpu_to_le16(x) (x)
#define cpu_to_le64(x) (x)
#define FIELD_PREP(m,x) (x)
#define BCM4377_XFER_RING_FLAG_VIRTUAL 1
#define BCM4377_XFER_RING_FLAG_SYNC 2
#define BCM4377_XFER_RING_FLAG_PAYLOAD_MAPPED 1
#define BCM4377_CONTROL_MSG_CREATE_XFER_RING 1
#define BCM4377_MSGID_GENERATION 0xff00
#define BCM4377_MSGID_ID 0xff
#define spin_lock_irqsave(l,f) ((f)=0)
#define spin_unlock_irqrestore(l,f) ((void)(f))
struct bcm4377_create_transfer_ring_msg {u32 msg_type,ring_id,ring_id_again,n_elements,completion_ring_id,doorbell,flags,footer_size;u64 ring_iova;};
struct bcm4377_xfer_ring_entry {u16 id,len;u8 flags;u64 payload;};
struct bcm4377_transfer_ring {bool virtual,sync,d2h_buffers_only,enabled;int lock;unsigned ring_id,n_entries,completion_ring,doorbell,payload_size,generation,mapped_payload_size;u64 ring_dma,payloads_dma;void *ring;};
struct state {u16 xfer_ring_head[9],xfer_ring_tail[9];};
struct bcm4377_data {struct state *ring_state;struct bcm4377_transfer_ring control_h2d_ring;};
static int enqueue_result,doorbells;
static int bcm4377_enqueue(struct bcm4377_data *b,struct bcm4377_transfer_ring *r,void *m,unsigned n,bool wait){return enqueue_result;}
static void bcm4377_ring_doorbell(struct bcm4377_data *b,unsigned d,u16 h){doorbells++;}
'''
tests=r'''
int main(void){
 for(int mode=0;mode<3;mode++)for(int fail=0;fail<2;fail++){
  struct state state={0};struct bcm4377_data b={.ring_state=&state};
  struct bcm4377_xfer_ring_entry entries[16],saved[16];memset(entries,0xa5,sizeof(entries));memcpy(saved,entries,sizeof(entries));
  struct bcm4377_transfer_ring r={.ring_id=1,.n_entries=16,.ring=entries,.d2h_buffers_only=mode==1,.virtual=mode==2};
  enqueue_result=fail?-110:0;doorbells=0;
  int rc=bcm4377_create_transfer_ring(&b,&r);
  if(fail){assert(rc==-110);assert(!r.enabled);assert(!doorbells);assert(!memcmp(entries,saved,sizeof(entries)));assert(state.xfer_ring_head[1]!=15);}
  else {assert(rc==0);assert(r.enabled);assert(doorbells==(mode!=0));}
 }
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.c').write_text(stub+f+tests)
 subprocess.run(['cc','-o',str(p/'test'),str(p/'test.c')],check=True);subprocess.run([str(p/'test')],check=True)
print('PASS: failed normal/receive/virtual ring creation publishes no buffers, doorbells or enabled flag; successful creation preserved')
