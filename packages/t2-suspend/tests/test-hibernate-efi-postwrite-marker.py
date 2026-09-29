#!/usr/bin/python3
"""Execute the new post-write callback with a fake EFI writer, never host PM."""

from pathlib import Path
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-postwrite-marker"
source = (root / "mba_hibernate_efi_postwrite_marker.c").read_text()
assert 'L"OmarchyT2PostwriteStage"' in source
assert '#ifdef MBA_POSTWRITE_SOURCE_MARKER_V3\nstatic efi_char16_t marker_name[] = L"OmarchyT2PostwriteStageV3";' in source
assert '#elif defined(MBA_POSTWRITE_SOURCE_MARKER_V2)\nstatic efi_char16_t marker_name[] = L"OmarchyT2PostwriteStageV2";' in source
assert 'MODULE_INFO(mba_postwrite_variable, "v2")' in source
assert 'MODULE_INFO(mba_postwrite_variable, "v3")' in source
assert 'EFI_GUID(0x47a2fceb, 0x87bc, 0x4e58, 0x8d, 0x83, 0x23, 0xf6, 0x2f, 0xfb, 0x33, 0x93)' in source
assert 'FTRACE_OPS_FL_IPMODIFY' not in source
assert 'if (READ_ONCE(armed))\n    return -EPERM;' in source
assert 'module_param_cb(arm_vector, &arm_vector_ops, NULL, 0600)' in source
assert 'memcmp(actual, expected, sizeof(actual))' in source
assert 'attrs != MARKER_ATTRS' in source and 'size != sizeof(actual)' in source
assert 'efivar_trylock()' in source and 'efivar_set_variable_locked(' in source
assert 'efi.set_variable_nonblocking' in source
assert '.kp.symbol_name = "swsusp_write"' in source
assert '.kp.symbol_name = "hibernate"' in source
hooks = re.findall(r'\{ \.function = "([^"]+)", \.value = (\d+) \}', source)
assert hooks == [
  ("hibernate", "1"), ("swsusp_write", "2"),
  ("hibernation_platform_enter", "3"), ("kernel_power_off", "3"),
  ("acpi_hibernation_enter", "4"),
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
static bool write_succeeded;
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
harness += (function("mba_write_stage") + function("mba_stage_callback") +
            function("mba_write_return") + function("mba_hibernate_return"))
harness += r'''
static void callback(unsigned int value)
{
  struct mba_stage_hook hook = { .value = value };
  mba_stage_callback(0, 0, &hook.ops, NULL);
}
static void write_return(long value)
{
  struct pt_regs regs = { .return_value = value };
  mba_write_return(NULL, &regs);
}
int main(void)
{
  memcpy(marker, "MBPW", 4);
  marker[4] = 0x7a;
  callback(1);
  assert(stage == 0 && writes == 0);
  armed = true;
  callback(3);
  assert(stage == 0 && writes == 0);
  callback(1);
  callback(2);
  assert(stage == 2 && writes == 2 && last_value[16] == 2);
  callback(3);
  assert(stage == 2 && writes == 2);
  write_return(0);
  callback(3);
  assert(stage == 3 && writes == 3 && last_value[16] == 3);
  callback(4);
  assert(stage == 4 && writes == 4 && last_value[16] == 4);
  assert(last_value[4] == 0x7a);
  mba_hibernate_return(NULL, NULL);
  assert(!armed);

  armed = true; write_succeeded = false; stage = writes = 0;
  callback(1);
  callback(2);
  write_return(-5);
  assert(!armed && !write_succeeded && stage == 2);
  callback(3);
  assert(stage == 2 && writes == 2);

  armed = true; write_succeeded = false; stage = writes = 0; next_status = EFI_DEVICE_ERROR;
  callback(1);
  assert(stage == 1 && writes == 1 && !armed && last_efi_status == EFI_DEVICE_ERROR);
  next_status = EFI_SUCCESS;
  callback(2);
  assert(stage == 1 && writes == 1);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-postwrite-callback-") as directory:
  c_file = Path(directory) / "callback.c"
  executable = Path(directory) / "callback"
  c_file.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), str(c_file)], check=True)
  subprocess.run([str(executable)], check=True)

print("PASS: post-write EFI hooks are monotonic, one-use and fail closed")
