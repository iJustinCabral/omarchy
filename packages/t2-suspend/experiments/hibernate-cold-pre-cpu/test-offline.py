#!/usr/bin/python3
"""Actual C callbacks and busybox/mkinitcpio hook logic; no host module/PM/EFI."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

directory = Path(__file__).resolve().parent
source = (directory / "mba_hibernate_cold_pre_cpu.c").read_text()
assert '#define TARGET_FUNCTION "hibernate_resume_nonboot_cpu_disable"' in source
assert "module_param_cb(arm_prefix, &arm_prefix_ops, NULL, 0600)" in source
assert "efivar" not in source and "<linux/efi.h>" not in source
assert "kretprobe" not in source

def function(name):
  match = re.search(r"static (?:void|int)(?: notrace| __init| __exit)? " + name + r"\([^;]+?\)\n\{", source)
  assert match, name
  index, depth = match.end(), 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define notrace
#define __init
#define __exit
#define TARGET_FUNCTION "hibernate_resume_nonboot_cpu_disable"
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_wmb() ((void)0)
struct kernel_param { int unused; };
struct ftrace_ops { int unused; };
struct ftrace_regs { unsigned long ip; };
static bool registered, armed, arm_consumed;
static unsigned int interceptions;
static char vector_prefix[25];
static struct ftrace_ops cold_ops;
static int filter_error, register_error;
static unsigned int filters, registrations, frees, unregistrations;
static int ftrace_set_filter(struct ftrace_ops *ops, unsigned char *target, unsigned int length, int reset) {
  assert(ops==&cold_ops && !strcmp((char *)target,TARGET_FUNCTION));
  assert(length==strlen(TARGET_FUNCTION) && !reset);
  filters++; return filter_error;
}
static int register_ftrace_function(struct ftrace_ops *ops) {
  assert(ops==&cold_ops); registrations++; return register_error;
}
static void ftrace_free_filter(struct ftrace_ops *ops) {assert(ops==&cold_ops); frees++;}
static void unregister_ftrace_function(struct ftrace_ops *ops) {
  assert(ops==&cold_ops && !armed && !registered); unregistrations++;
}
static unsigned int cmpxchg(unsigned int *p, unsigned int old, unsigned int next) {
  unsigned int prior=*p; if(prior==old) *p=next; return prior;
}
static void ftrace_regs_set_instruction_pointer(struct ftrace_regs *r, unsigned long ip) {r->ip=ip;}
'''
harness += ''.join(function(name) for name in ("mba_cold_abort", "mba_cold_hook", "mba_set_arm_prefix", "mba_get_arm_prefix", "mba_cold_init", "mba_cold_exit"))
harness += r'''
int main(void) {
  struct ftrace_regs regs={0}; char value[8];
  mba_cold_hook(0,0,NULL,&regs); assert(!regs.ip && !interceptions);
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==-EPERM);
  armed=true; assert(mba_cold_init()==-EPERM); armed=false;
  arm_consumed=true; assert(mba_cold_init()==-EPERM); arm_consumed=false;
  interceptions=1; assert(mba_cold_init()==-EPERM); interceptions=0;
  strcpy(vector_prefix,"0123456789abcdef01234567");
  assert(mba_cold_init()==-EPERM); vector_prefix[0]='\0';
  assert(!registered && !filters && !registrations && !frees);
  filter_error=-EINVAL;
  assert(mba_cold_init()==-EINVAL && !registered);
  assert(filters==1 && !registrations && !frees);
  filter_error=0; register_error=-EBUSY;
  assert(mba_cold_init()==-EBUSY && !registered);
  assert(filters==2 && registrations==1 && frees==1);
  register_error=0;
  assert(mba_cold_init()==0 && registered && !armed && !arm_consumed);
  assert(filters==3 && registrations==2 && frees==1);
  mba_cold_hook(0,0,NULL,&regs); assert(!regs.ip && !interceptions);
  assert(mba_set_arm_prefix("ABCDEF012345678901234567",NULL)==-EINVAL);
  assert(mba_set_arm_prefix("0123456789abcdef01234567\nx",NULL)==-EINVAL);
  assert(mba_set_arm_prefix("short",NULL)==-EINVAL);
  assert(!arm_consumed && !armed);
  assert(mba_set_arm_prefix("0123456789abcdef01234567\n",NULL)==0);
  assert(arm_consumed && armed && !strcmp(vector_prefix,"0123456789abcdef01234567"));
  assert(mba_get_arm_prefix(value,NULL)==2 && !strcmp(value,"1\n"));
  assert(mba_set_arm_prefix("111111111111111111111111",NULL)==-EPERM);
  mba_cold_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_cold_abort && interceptions==1 && !armed);
  assert(mba_cold_abort()==-ECANCELED);
  assert(mba_get_arm_prefix(value,NULL)==2 && !strcmp(value,"0\n"));
  regs.ip=0; mba_cold_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_cold_abort && interceptions==1);
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==-EPERM);
  mba_cold_exit();
  assert(!armed && !registered && unregistrations==1 && frees==2);
  return 0;
}
'''

guid = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"
prefix = "0123456789abcdef01234567"
script = r'''
. /usr/lib/initcpio/init_functions
getarg() { [[ $1 == "quiet" ]] && printf 'y\n'; }
err() { printf 'ERROR %s\n' "$*"; }
plymouth() { printf 'plymouth\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/order"; }
launch_interactive_shell() { printf 'shell\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/order"; exit 81; }
insmod() {
  [[ $MOCK == "insmod-fail" ]] && return 1
  local m=$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/mba_hibernate_cold_pre_cpu
  mkdir -p "$m/parameters"
  printf 'SRC\n' > "$m/srcversion"
  printf '0\n' > "$m/parameters/arm_prefix"
  printf 'N\n' > "$m/parameters/arm_consumed"
  printf '0\n' > "$m/parameters/interceptions"
  cold_write_arm() {
    printf '1\n' > "$cold_sys/parameters/arm_prefix"
    printf 'Y\n' > "$cold_sys/parameters/arm_consumed"
    printf '%s\n' "$cold_prefix" > "$cold_sys/parameters/vector_prefix"
  }
}
. "$1/hooks/omarchy-t2-cold-pre-cpu"
run_hook || exit 82
printf 'pre-return\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/order"
if [[ -e $cold_intent ]]; then
  # Synchronous resume is simulated, never invoked on the host.
  printf 'resume-enter\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/order"
  if [[ $MOCK != "no-intercept" ]]; then
    printf '0\n' > "$cold_sys/parameters/arm_prefix"
    printf '1\n' > "$cold_sys/parameters/interceptions"
  fi
  printf '\007\000\000\000MBRS\001\043\105\147\211\253\315\357\001\043\105\147\007' > "$cold_marker"
  case $MOCK in
    wrong-stage) printf '\007\000\000\000MBRS\001\043\105\147\211\253\315\357\001\043\105\147\006' > "$cold_marker" ;;
    wrong-vector) printf 'aaaaaaaaaaaaaaaaaaaaaaaa\n' > "$cold_sys/parameters/vector_prefix" ;;
    wrong-src) printf 'WRONG\n' > "$cold_sys/srcversion" ;;
    stale-return) printf 'retained' > "$cold_vars/OmarchyT2ColdPreCpuReturned${cold_prefix}-$cold_guid" ;;
    corrupt-hash) printf 'bad\n' > "$cold_dir/abort.sha256" ;;
    readback-fail)
      hexdump() {
        case "$*" in
          *OmarchyT2ColdPreCpuReturned*) printf 'bad\n' ;;
          *) /usr/bin/hexdump "$@" ;;
        esac
      }
      ;;
  esac
  printf 'resume-return\n' >> "$OMARCHY_T2_COLD_PRE_CPU_ROOT/order"
fi
. "$1/hooks/omarchy-t2-cold-pre-cpu-return"
run_hook
'''

with tempfile.TemporaryDirectory(prefix="cold-pre-cpu-offline-") as tmp:
  temp = Path(tmp)
  (temp / "callbacks.c").write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(temp / "callbacks.c"), "-o", str(temp / "callbacks")], check=True)
  subprocess.run([str(temp / "callbacks")], check=True)
  for mode in ("absent", "success", "no-intercept", "wrong-stage", "wrong-vector", "wrong-src", "stale-return", "corrupt-hash", "readback-fail", "insmod-fail", "bad-hash", "bad-marker", "symlink-marker"):
    root = temp / mode
    files = root / "usr/lib/omarchy-t2-cold-pre-cpu"
    files.mkdir(parents=True)
    (root / "run").mkdir()
    variables = root / "sys/firmware/efi/efivars"
    variables.mkdir(parents=True)
    (files / "functions").write_bytes((directory / "functions").read_bytes())
    (files / "abort.ko").write_bytes(b"synthetic offline module")
    (files / "abort.sha256").write_text(hashlib.sha256((files / "abort.ko").read_bytes()).hexdigest() + "\n")
    (files / "abort.srcversion").write_text("SRC\n")
    (files / "restore.variable").write_text("OmarchyT2RestoreStageV2-" + guid + "\n")
    marker = variables / ("OmarchyT2RestoreStageV2-" + guid)
    if mode != "absent":
      marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\0")
    if mode == "bad-hash":
      (files / "abort.sha256").write_text("bad\n")
    if mode == "bad-marker":
      marker.write_bytes(b"bad")
    if mode == "symlink-marker":
      marker.rename(root / "retained")
      marker.symlink_to(root / "retained")
    result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-c", script, "ash", str(directory)], env={"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root), "MOCK": mode}, capture_output=True, text=True)
    order = (root / "order").read_text().splitlines()
    witness = variables / ("OmarchyT2ColdPreCpuReturned" + prefix + "-" + guid)
    if mode == "absent":
      assert result.returncode == 0 and order == ["pre-return"]
      assert not witness.exists()
    elif mode == "success":
      assert result.returncode == 81, result.stdout
      assert order == ["pre-return", "resume-enter", "resume-return", "plymouth", "shell"], (order, result.stdout, result.stderr)
      assert witness.read_bytes() == bytes.fromhex("07000000") + b"MBCP" + prefix.encode() + b"\1"
      assert "exact diagnostic armed" not in result.stdout
    else:
      assert result.returncode == 81, (mode, result.stdout, result.stderr)
      assert order[-2:] == ["plymouth", "shell"]
      if mode == "stale-return":
        assert witness.read_bytes() == b"retained"
      elif mode == "readback-fail":
        assert witness.exists() and "exact recovered interception not proved" in result.stdout
      else:
        assert not witness.exists(), mode
      if mode in ("bad-hash", "bad-marker", "symlink-marker", "insmod-fail"):
        assert "resume-enter" not in order
print("PASS: extracted C one-use abort and ash quiet/fail-closed return witnesses (no host PM)")
