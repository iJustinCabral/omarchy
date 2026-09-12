#!/usr/bin/env python3
"""Execute the actual patched ndo_open with firmware/transport failure injection."""
from pathlib import Path
import re
import subprocess
import tempfile

here = Path(__file__).resolve().parent
import sys
source = Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix='t2-reenable-') as td:
    root = Path(td)
    target = root/'drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.c'
    target.parent.mkdir(parents=True)
    target.write_bytes(source.read_bytes())
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str(here.parent/'patches/wifi-reenable/0001-brcmfmac-propagate-open-transport-error.patch')], cwd=root, check=True)
    fn = re.search(r'static int brcmf_netdev_open\(.*?\n\}', target.read_text(), re.S).group()
    code = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define BRCMF_BUS_UP 1
#define TOE_TX_CSUM_OL 1
#define NETIF_F_IP_CSUM 1
#define brcmf_dbg(...) ((void)0)
#define bphy_err(...) ((void)0)
struct brcmf_bus { int state; };
struct brcmf_pub { struct brcmf_bus *bus_if; };
struct brcmf_if { struct brcmf_pub *drvr; int pend_8021x_cnt; };
struct net_device { struct brcmf_if *ifp; unsigned features; };
static int reply, up_result, queries, ups, carrier;
static u32 toe;
static struct brcmf_if *netdev_priv(struct net_device *n) {return n->ifp;}
static void atomic_set(int *p,int n) {*p=n;}
static int brcmf_fil_iovar_int_get(struct brcmf_if *p,const char *name,u32 *out) {
 (void)p; assert(!strcmp(name,"toe_ol")); queries++;
 if (!reply) *out=toe;
 return reply;
}
static int brcmf_cfg80211_up(struct net_device *n) {(void)n;ups++;return up_result;}
static void netif_carrier_off(struct net_device *n) {(void)n;carrier++;}
''' + fn + r'''
int main(void) {
 struct brcmf_bus b={1}; struct brcmf_pub d={&b}; struct brcmf_if p={&d,0};
 struct net_device n={&p,0};
 int errors[]={-EIO,-ETIMEDOUT,-ENOMEM,-EBADF};
 for (unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
  reply=errors[i];queries=ups=carrier=0;n.features=0x81;
  assert(brcmf_netdev_open(&n)==reply);
  assert(queries==1 && !ups && !carrier && n.features==0x81);
 }
 /* Firmware responded but rejected optional TOE: still open without checksum. */
 reply=-EBADE;queries=ups=carrier=0;n.features=0x81;
 assert(!brcmf_netdev_open(&n));assert(ups==1 && carrier==1 && n.features==0x80);
 for (unsigned enabled=0;enabled<2;enabled++) {
  reply=0;toe=enabled;n.features=0x80;
  assert(!brcmf_netdev_open(&n));assert(n.features==(0x80|enabled));
 }
 up_result=-EIO;carrier=0;assert(brcmf_netdev_open(&n)==-EIO && !carrier);
 b.state=0;queries=0;assert(brcmf_netdev_open(&n)==-EAGAIN && !queries);
 puts("PASS: transport failures, optional firmware rejection, checksum modes, cfg failure, bus down");
}
'''
    c=root/'test.c'; exe=root/'test'; c.write_text(code)
    subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
