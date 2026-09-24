#!/usr/bin/python3
"""Exercise the cold-restore marker's one-use callback sequence without host PM."""

from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-restore-marker"
source = (root / "mba_hibernate_efi_restore_marker.c").read_text()
assert 'L"OmarchyT2RestoreStage"' in source
assert 'L"OmarchyT2RestoreStageV2"' in source
assert 'MODULE_INFO(mba_restore_variable, "v2")' in source
assert 'EFI_GUID(0x5e17d2ad, 0x021f, 0x4d45, 0xa8, 0xe5, 0xf4, 0xc1, 0x91, 0x98, 0x3e, 0x27)' in source
assert 'FTRACE_OPS_FL_IPMODIFY' not in source
assert 'if (READ_ONCE(armed))\n    return -EPERM;' in source
assert 'module_param_cb(arm_prefix, &arm_prefix_ops, NULL, 0600)' in source
assert 'memcmp(actual, expected, sizeof(actual))' in source
assert 'attrs != MARKER_ATTRS' in source and 'size != sizeof(actual)' in source
assert 'efivar_trylock()' in source and 'efivar_set_variable_locked(' in source
assert 'efi.set_variable_nonblocking' in source
assert '.kp.symbol_name = "swsusp_check"' in source
assert '.kp.symbol_name = "swsusp_read"' in source
hooks = re.findall(r'\{ \.function = "([^"]+)", \.value = (\d+) \}', source)
assert hooks == [
  ("swsusp_check", "1"),
  ("swsusp_read", "3"),
  ("hibernation_restore", "5"),
  ("dpm_suspend_start", "6"),
  ("dpm_suspend_end", "7"),
]


def function(name):
  match = re.search(r"static (?:efi_status_t|void|int) notrace " + name + r"\([^;]+?\)\n\{", source)
  assert match, name
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define notrace
#define MARKER_SIZE 17
#define MARKER_ATTRS 7
#define EFI_SUCCESS 0
#define EFI_NOT_READY 6
#define EFI_DEVICE_ERROR 7
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value) = (next))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
typedef uint8_t u8;
typedef unsigned long efi_status_t;
typedef uint16_t efi_char16_t;
typedef struct { unsigned int unused; } efi_guid_t;
struct ftrace_ops { unsigned int unused; };
struct ftrace_regs { unsigned int unused; };
struct kretprobe_instance { unsigned int unused; };
struct pt_regs { long return_value; };
#define regs_return_value(regs) ((regs)->return_value)
struct mba_stage_hook { const char *function; unsigned int value; struct ftrace_ops ops; };
static u8 marker[MARKER_SIZE];
static bool armed;
static unsigned int stage, writes;
static unsigned long last_efi_status;
static efi_status_t next_status;
static efi_char16_t marker_name[] = { 'M', 0 };
static efi_guid_t marker_guid;
static u8 last_value[MARKER_SIZE];
static unsigned int cmpxchg(unsigned int *address, unsigned int old, unsigned int next)
{
  unsigned int previous = *address;
  if (previous == old) *address = next;
  return previous;
}
static int efivar_trylock(void) { return 0; }
static void efivar_unlock(void) { }
static efi_status_t efivar_set_variable_locked(efi_char16_t *name, efi_guid_t *guid,
                                               unsigned int attrs, unsigned long size,
                                               u8 *value, bool nonblocking)
{
  (void)name; (void)guid;
  assert(attrs == 7 && size == MARKER_SIZE && nonblocking);
  writes++;
  memcpy(last_value, value, MARKER_SIZE);
  return next_status;
}
'''
harness += (function("mba_write_stage") + function("mba_advance") +
            function("mba_stage_callback") + function("mba_check_return") +
            function("mba_read_return"))
harness += r'''
static void callback(unsigned int value)
{
  struct mba_stage_hook hook = { .value = value };
  mba_stage_callback(0, 0, &hook.ops, NULL);
}
static void check_return(long value)
{
  struct pt_regs regs = { .return_value = value };
  mba_check_return(NULL, &regs);
}
static void read_return(long value)
{
  struct pt_regs regs = { .return_value = value };
  mba_read_return(NULL, &regs);
}
int main(void)
{
  memcpy(marker, "MBRS", 4);
  marker[4] = 0x52;
  callback(1);
  assert(stage == 0 && writes == 0);
  armed = true;
  callback(3);
  assert(stage == 0 && writes == 0);
  callback(1); check_return(0);
  callback(3); read_return(0);
  callback(5); callback(6); callback(7);
  assert(stage == 7 && writes == 7 && last_value[16] == 7);
  assert(last_value[4] == 0x52);
  callback(7);
  assert(writes == 7);

  armed = true; stage = writes = 0;
  callback(1); check_return(-22);
  assert(!armed && stage == 1 && writes == 1);
  callback(3);
  assert(stage == 1 && writes == 1);

  armed = true; stage = writes = 0;
  callback(1); check_return(0); callback(3); read_return(-5);
  assert(!armed && stage == 3 && writes == 3);
  callback(5);
  assert(stage == 3 && writes == 3);

  armed = true; stage = writes = 0; next_status = EFI_DEVICE_ERROR;
  callback(1);
  assert(stage == 1 && writes == 1 && !armed && last_efi_status == EFI_DEVICE_ERROR);
  next_status = EFI_SUCCESS;
  callback(3);
  assert(stage == 1 && writes == 1);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-restore-marker-callback-") as directory:
  c_file = Path(directory) / "callback.c"
  executable = Path(directory) / "callback"
  c_file.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), str(c_file)], check=True)
  subprocess.run([str(executable)], check=True)

print("PASS: cold-restore EFI hooks are monotonic, one-use and fail closed")
