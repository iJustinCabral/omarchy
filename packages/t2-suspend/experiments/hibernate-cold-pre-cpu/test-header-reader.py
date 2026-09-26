#!/usr/bin/python3
"""Fault-test actual header-reader source with mocked read-only syscalls."""
from pathlib import Path
import subprocess
import tempfile

directory = Path(__file__).resolve().parent
harness = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
static unsigned char saved[4096];
static int fault, opens, closes, reads;
static char *mock_realpath(const char *path, char *unused) {
  assert(!strcmp(path,"/dev/mapper/root") && unused==NULL);
  return fault==1 ? NULL : strdup("/dev/dm-0");
}
static int mock_open(const char *path, int flags) {
  assert(!strcmp(path,"/dev/dm-0"));
  assert(flags==(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
  opens++; return fault==2 ? -1 : 55;
}
static int mock_fstat(int fd, struct stat *value) {
  assert(fd==55); value->st_mode=fault==4 ? S_IFREG : S_IFBLK;
  value->st_rdev=makedev(253,fault==5 ? 1 : 0); return fault==3 ? -1 : 0;
}
static int mock_stat(const char *path, struct stat *value) {
  assert(!strcmp(path,"/dev/mapper/root")); value->st_mode=S_IFBLK;
  value->st_rdev=makedev(253,fault==7 ? 1 : 0); return fault==6 ? -1 : 0;
}
static int mock_ioctl(int fd, unsigned long request, uint64_t *size) {
  assert(fd==55 && request==BLKGETSIZE64);
  *size=1923214ULL*4096+(fault==9 ? 4095 : 4096); return fault==8 ? -1 : 0;
}
static ssize_t mock_pread(int fd, void *page, size_t count, off_t offset) {
  assert(fd==55 && count==4096 && offset==1923214LL*4096); reads++;
  memcpy(page,saved,4096); errno=EINTR;
  return fault==10 ? 4095 : fault==11 ? -1 : 4096;
}
static int mock_close(int fd) {assert(fd==55); closes++; return fault==12 ? -1 : 0;}
#define realpath(a,b) mock_realpath(a,b)
#define open(a,b) mock_open(a,b)
#define fstat(a,b) mock_fstat(a,b)
#define stat(a,b) mock_stat(a,b)
#define ioctl(a,b,c) mock_ioctl(a,b,c)
#define pread(a,b,c,d) mock_pread(a,b,c,d)
#define close(a) mock_close(a)
#define main header_cli
'''
harness += '#include "' + str(directory / "read-swap-header.c") + '"\n#undef main\n'
harness += r'''
int main(void) {
  unsigned char page[4096]={0}; uint64_t number=0;
  assert(cold_decimal("1923214",&number)==0 && number==1923214);
  const char *bad[]={"", "-1", "+1", " 1", "01", "1x", "18446744073709551616"};
  for(size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) assert(cold_decimal(bad[i],&number));
  assert(cold_classify(page)==NULL);
  memcpy(page+4086,"SWAPSPACE2",10); assert(cold_classify(page)==NULL);
  page[1024]=1; assert(!strcmp(cold_classify(page),"NORMAL"));
  page[1025]=1; assert(cold_classify(page)==NULL); page[1025]=0;
  memcpy(page+4086,"SWAP-SPACE",10); assert(cold_classify(page)==NULL);
  memcpy(page+4086,"S1SUSPEND\0",10); assert(!strcmp(cold_classify(page),"PENDING"));
  memcpy(saved,page,4096);
  for(fault=1;fault<=12;fault++) {
    opens=closes=reads=0;
    assert(cold_read_header("/dev/mapper/root",1923214,253,0,page));
    assert(closes==(fault>=3 ? 1 : 0));
    assert(reads==(fault>=10 ? 1 : 0));
  }
  fault=opens=closes=reads=0;
  assert(cold_read_header("/dev/mapper/root",UINT64_MAX,253,0,page));
  assert(!opens && !closes && !reads);
  assert(!cold_read_header("/dev/mapper/root",1923214,253,0,page));
  assert(opens==1 && closes==1 && reads==1 && !memcmp(page,saved,4096));
  char *wrong_device[]={"reader","/dev/not-root","1923214","253","0"};
  assert(header_cli(5,wrong_device)==2);
  char *bad_offset[]={"reader","/dev/mapper/root","-1","253","0"};
  assert(header_cli(5,bad_offset)==2);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="cold-header-reader-test-") as tmp:
  root = Path(tmp)
  (root / "harness.c").write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(root / "harness.c"), "-o", str(root / "harness")], check=True)
  subprocess.run([str(root / "harness")], check=True)
print("PASS: exact block-header classification, identity/range/short-read faults, read-only and exactly-once cleanup")
