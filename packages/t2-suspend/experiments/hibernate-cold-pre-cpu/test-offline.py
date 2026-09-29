#!/usr/bin/python3
"""Actual C callbacks and busybox/mkinitcpio hook logic; no host module/PM/EFI."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import importlib.util
import shutil

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
hook_chain = "udev encrypt omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker resume omarchy-t2-cold-pre-cpu-return"
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
  # Adjacent existing marker hook is simulated before the resume wrapper.
  mkdir -p "$cold_root/sys/module/mba_hibernate_efi_restore_marker/parameters"
  printf '1\n' > "$cold_root/sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix"
  printf '0\n' > "$cold_root/sys/module/mba_hibernate_efi_restore_marker/parameters/stage"
fi
case $MOCK in
  pending-appears) printf 'PENDING\n' > "$cold_root/header-state" ;;
  marker-disappears) rm "$cold_marker" ;;
  helper-after-pre) printf 'changed' >> "$cold_dir/header-reader" ;;
  stock-after-pre) printf 'changed' >> "$cold_dir/stock-resume" ;;
  abort-module-disappears) rm "$cold_sys/parameters/arm_prefix" ;;
  marker-arm-lost) printf '0\n' > "$cold_root/sys/module/mba_hibernate_efi_restore_marker/parameters/arm_prefix" ;;
esac
fake_stock_resume() {
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
  printf 'NORMAL\n' > "$cold_root/header-state"
 else
   printf 'ordinary-resume\n' >> "$cold_root/order"
 fi
}
. "$1/../hibernate-cold-common/hooks/resume"
run_hook || exit 83
. "$1/hooks/omarchy-t2-cold-pre-cpu-return"
run_hook
'''

with tempfile.TemporaryDirectory(prefix="cold-pre-cpu-offline-") as tmp:
  temp = Path(tmp)
  (temp / "callbacks.c").write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(temp / "callbacks.c"), "-o", str(temp / "callbacks")], check=True)
  subprocess.run([str(temp / "callbacks")], check=True)
  for mode in ("absent", "success", "no-intercept", "wrong-stage", "wrong-vector", "wrong-src", "stale-return", "corrupt-hash", "readback-fail", "insmod-fail", "bad-hash", "bad-marker", "symlink-marker", "pending-missing-marker", "unknown-header", "reader-error", "wrong-offset", "duplicate-resume", "wrong-resume", "noresume", "disabled-hook", "bad-order", "late-resume", "normal-stale-marker", "pending-appears", "marker-disappears", "systemd-helper", "helper-after-pre", "stock-after-pre", "abort-module-disappears", "marker-arm-lost"):
    root = temp / mode
    files = root / "usr/lib/omarchy-t2-cold-pre-cpu"
    files.mkdir(parents=True)
    (root / "run").mkdir()
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "proc/sys/kernel/ftrace_enabled").write_text("1\n")
    (root / "sys/power").mkdir(parents=True)
    (root / "proc/cmdline").write_text("quiet resume=/dev/mapper/root resume_offset=1923214\n")
    (root / "sys/power/resume_offset").write_text("1923214\n")
    variables = root / "sys/firmware/efi/efivars"
    variables.mkdir(parents=True)
    (files / "functions").write_bytes((directory / "functions").read_bytes())
    common = root / "usr/lib/omarchy-t2-cold-common"
    common.mkdir()
    (common / "functions").write_bytes((directory.parent / "hibernate-cold-common/functions").read_bytes())
    (common / "protocol").write_text("cold-pre-cpu-abort-v1\n")
    (files / "abort.ko").write_bytes(b"synthetic offline module")
    (files / "abort.sha256").write_text(hashlib.sha256((files / "abort.ko").read_bytes()).hexdigest() + "\n")
    (files / "abort.srcversion").write_text("SRC\n")
    (files / "restore.variable").write_text("OmarchyT2RestoreStageV2-" + guid + "\n")
    for name, value in (("resume.device", "/dev/mapper/root"), ("resume.offset", "1923214"), ("resume.devnum", "253:0")):
      (files / name).write_text(value + "\n")
    reader = files / "header-reader"
    reader.write_text('#!/bin/bash\n[[ $* == "/dev/mapper/root 1923214 253 0" ]] || exit 71\n[[ $MOCK != "reader-error" ]] || exit 72\nread -r state < "$OMARCHY_T2_COLD_PRE_CPU_ROOT/header-state"\nprintf "%s\\n" "$state"\n')
    reader.chmod(0o700)
    (files / "header-reader.sha256").write_text(hashlib.sha256(reader.read_bytes()).hexdigest() + "\n")
    (root / "header-state").write_text("NORMAL\n" if mode in ("absent", "normal-stale-marker", "pending-appears") else "PENDING\n")
    stock = files / "stock-resume"
    stock.write_text("run_hook() { fake_stock_resume; }\n")
    (files / "stock-resume.sha256").write_text(hashlib.sha256(stock.read_bytes()).hexdigest() + "\n")
    marker = variables / ("OmarchyT2RestoreStageV2-" + guid)
    if mode not in ("absent", "pending-missing-marker", "pending-appears"):
      marker.write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\0")
    if mode == "bad-hash":
      (files / "abort.sha256").write_text("bad\n")
    if mode == "bad-marker":
      marker.write_bytes(b"bad")
    if mode == "symlink-marker":
      marker.rename(root / "retained")
      marker.symlink_to(root / "retained")
    if mode == "unknown-header":
      (root / "header-state").write_text("UNKNOWN\n")
    if mode == "wrong-offset":
      (root / "sys/power/resume_offset").write_text("999\n")
    if mode == "duplicate-resume":
      (root / "proc/cmdline").write_text("resume=/dev/mapper/root resume_offset=1923214 resume=/dev/mapper/root\n")
    if mode == "wrong-resume":
      (root / "proc/cmdline").write_text("resume=/dev/other resume_offset=1923214\n")
    if mode == "noresume":
      (root / "proc/cmdline").write_text("resume=/dev/mapper/root resume_offset=1923214 noresume\n")
    if mode == "disabled-hook":
      (root / "proc/cmdline").write_text("resume=/dev/mapper/root resume_offset=1923214 disablehooks=resume\n")
    if mode == "systemd-helper":
      helper = root / "usr/lib/systemd/systemd-hibernate-resume"
      helper.parent.mkdir(parents=True)
      helper.write_text("#!/bin/bash\nexit 89\n")
      helper.chmod(0o700)
    result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-c", script, "ash", str(directory)], env={"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root), "MOCK": mode, "HOOKS": hook_chain if mode != "bad-order" else hook_chain.replace("omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker", "omarchy-t2-restore-marker omarchy-t2-cold-pre-cpu"), "LATEHOOKS": "resume" if mode == "late-resume" else ""}, capture_output=True, text=True)
    assert (root / "order").exists(), (result.stdout, result.stderr)
    order = (root / "order").read_text().splitlines()
    witness = variables / ("OmarchyT2ColdPreCpuReturned" + prefix + "-" + guid)
    if mode == "absent":
      assert result.returncode == 0 and order == ["pre-return", "ordinary-resume"], (result.stdout, result.stderr, order)
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
      if mode in ("bad-hash", "bad-marker", "symlink-marker", "insmod-fail", "pending-missing-marker", "unknown-header", "reader-error", "wrong-offset", "duplicate-resume", "wrong-resume", "noresume", "disabled-hook", "bad-order", "late-resume", "normal-stale-marker", "pending-appears", "marker-disappears", "systemd-helper", "helper-after-pre", "stock-after-pre", "abort-module-disappears", "marker-arm-lost"):
        assert "resume-enter" not in order

  spec = importlib.util.spec_from_file_location("cold_order", directory / "audit-order.py")
  order_module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(order_module)
  config = 'HOOKS="' + hook_chain + '"\n' + ''.join(name + '=""\n' for name in ("EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"))
  order_module.audit_config(config)
  invalid = [config.replace("encrypt ", ""), config.replace("resume ", "resume resume "), config.replace(" resume ", " fsck resume "), config.replace('LATEHOOKS=""', 'LATEHOOKS="resume"'), config.replace("omarchy-t2-cold-pre-cpu omarchy-t2-restore-marker", "omarchy-t2-restore-marker omarchy-t2-cold-pre-cpu")]
  for bad_config in invalid:
    try:
      order_module.audit_config(bad_config)
    except ValueError:
      pass
    else:
      raise AssertionError("Invalid cold hook order accepted")

  # Execute the real mkinitcpio dispatcher, existing marker and stock resume
  # control flow. Only absolute filesystem prefixes are relocated to fixtures;
  # module insertion and the stock sysfs printf remain explicitly simulated.
  runtime = Path("/usr/lib/initcpio/init_functions").read_text()
  dispatch = re.search(r"run_hookfunctions\(\) \{\n.*?\n\}", runtime, re.S).group(0)
  assert dispatch.count('"/hooks/$hook"') == 2
  dispatch = dispatch.replace('"/hooks/$hook"', '"$MOCK_HOOKS/$hook"')
  stock_source = Path("/usr/lib/initcpio/hooks/resume").read_text()
  stock_fixture = stock_source.replace("/sys/power/resume", "${OMARCHY_T2_COLD_PRE_CPU_ROOT}/sys/power/resume").replace("/usr/lib/systemd/systemd-hibernate-resume", "${OMARCHY_T2_COLD_PRE_CPU_ROOT}/usr/lib/systemd/systemd-hibernate-resume")
  fake_resume = re.search(r"fake_stock_resume\(\) \{\n.*?\n\}", script, re.S).group(0)
  mocks = script.split('. "$1/hooks/omarchy-t2-cold-pre-cpu"')[0].replace("insmod() {", "cold_insmod() {")
  driver = mocks + dispatch + "\n" + fake_resume + r'''
getarg() {
  case $1 in
    quiet) printf 'y\n' ;;
    resume) printf '/dev/mapper/root\n' ;;
  esac
  return 0
}
resolve_device() {
  [[ $1 == "/dev/mapper/root" ]] || exit 93
  printf '%s/dev/mapper/root\n' "$OMARCHY_T2_COLD_PRE_CPU_ROOT"
}
stat() {
  [[ "$1" == "-Lc" && "$2" == "0x%t 0x%T" && "$3" == "$OMARCHY_T2_COLD_PRE_CPU_ROOT/dev/mapper/root" ]] || exit 94
  printf '0xfd 0x0\n'
}
printf() {
  if [[ "$1" == "%d:%d" ]]; then
    [[ $2 == "0xfd" && $3 == "0x0" ]] || exit 95
    fake_stock_resume
  fi
  command printf "$@"
}
insmod() {
  if [[ $1 == "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/omarchy-t2-cold-pre-cpu/abort.ko" ]]; then
    cold_insmod "$@"
  else
    [[ $1 == "$OMARCHY_T2_COLD_PRE_CPU_ROOT/usr/lib/omarchy-t2-restore-marker/marker.ko" ]] || exit 96
    local marker=$OMARCHY_T2_COLD_PRE_CPU_ROOT/sys/module/mba_hibernate_efi_restore_marker
    mkdir -p "$marker/parameters"
    printf 'SRC\n' > "$marker/srcversion"
    printf '0\n' > "$marker/parameters/arm_prefix"
    printf '0\n' > "$marker/parameters/stage"
    write_restore_arm_prefix() { printf '1\n' > "$2"; }
  fi
}
run_hookfunctions run_hook hook $HOOKS
'''
  for mode in ("ordinary-flow", "controlled-flow"):
    root = temp / mode
    shutil.copytree(temp / "absent", root)
    (root / "order").unlink()
    files = root / "usr/lib/omarchy-t2-cold-pre-cpu"
    (files / "stock-resume").write_text(stock_fixture)
    (root / "sys/power/resume").write_text("0:0")
    (files / "stock-resume.sha256").write_text(hashlib.sha256(stock_fixture.encode()).hexdigest() + "\n")
    marker_files = root / "usr/lib/omarchy-t2-restore-marker"
    marker_files.mkdir()
    (marker_files / "marker.version").write_text("v2\n")
    (marker_files / "marker.ko").write_bytes(b"synthetic existing restore marker")
    (marker_files / "marker.sha256").write_text(hashlib.sha256((marker_files / "marker.ko").read_bytes()).hexdigest() + "\n")
    (marker_files / "marker.srcversion").write_text("SRC\n")
    hooks = root / "hooks"
    hooks.mkdir()
    for name in ("omarchy-t2-cold-pre-cpu", "resume", "omarchy-t2-cold-pre-cpu-return"):
      source_directory = directory.parent / "hibernate-cold-common" if name == "resume" else directory
      shutil.copyfile(source_directory / "hooks" / name, hooks / name)
      (hooks / name).chmod(0o700)
    shutil.copyfile(directory.parent / "hibernate-candidate-initcpio/hooks/omarchy-t2-restore-marker", hooks / "omarchy-t2-restore-marker")
    (hooks / "omarchy-t2-restore-marker").chmod(0o700)
    if mode == "controlled-flow":
      (root / "header-state").write_text("PENDING\n")
      (root / "sys/firmware/efi/efivars" / ("OmarchyT2RestoreStageV2-" + guid)).write_bytes(bytes.fromhex("07000000") + b"MBRS" + bytes.fromhex(prefix) + b"\0")
    result = subprocess.run(["/usr/lib/initcpio/busybox", "ash", "-c", driver, "ash", str(directory)], env={"PATH": os.environ["PATH"], "OMARCHY_T2_COLD_PRE_CPU_ROOT": str(root), "OMARCHY_T2_RESTORE_MARKER_ROOT": str(root), "MOCK_HOOKS": str(hooks), "MOCK": mode, "HOOKS": hook_chain}, capture_output=True, text=True)
    assert (root / "order").exists(), (result.stdout, result.stderr)
    order = (root / "order").read_text().splitlines()
    if mode == "ordinary-flow":
      assert result.returncode == 0 and order == ["ordinary-resume"], (result.stdout, result.stderr, order)
      assert (root / "sys/power/resume").read_text() == "253:0"
    else:
      assert result.returncode == 81 and order == ["resume-enter", "resume-return", "plymouth", "shell"], (result.stdout, result.stderr, order)
      witness = root / "sys/firmware/efi/efivars" / ("OmarchyT2ColdPreCpuReturned" + prefix + "-" + guid)
      assert witness.exists()
print("PASS: extracted C one-use abort and ash quiet/fail-closed return witnesses (no host PM)")
subprocess.run(["python3", str(directory / "test-header-reader.py")], check=True)
