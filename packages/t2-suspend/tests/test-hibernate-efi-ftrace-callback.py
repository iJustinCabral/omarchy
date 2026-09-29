#!/usr/bin/python3
"""Execute extracted EFI ftrace callback logic without loading a kernel module."""

from pathlib import Path
import re
import subprocess
import tempfile


source = (Path(__file__).resolve().parents[1] / "experiments/hibernate-efi-ftrace-marker/mba_hibernate_efi_ftrace_marker.c").read_text()


def function(name):
  match = re.search(r"static (?:efi_status_t|void) notrace " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
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
struct mba_stage_hook {
  const char *function;
  unsigned int value;
  struct ftrace_ops ops;
};

static u8 marker[MARKER_SIZE], entry_marker[MARKER_SIZE];
static bool armed, entry_armed;
static unsigned int stage, entry_stage;
static unsigned long last_efi_status, entry_efi_status;
static efi_char16_t marker_name[] = { 'S', 0 }, entry_name[] = { 'E', 0 };
static efi_guid_t marker_guid, entry_guid;
static unsigned int writes;
static efi_status_t next_status;
static u8 last_value[MARKER_SIZE];
static efi_char16_t *last_name;

static unsigned int cmpxchg(unsigned int *address, unsigned int old, unsigned int next)
{
  unsigned int observed = *address;
  if (observed == old)
    *address = next;
  return observed;
}

static efi_status_t mba_write_variable(efi_char16_t *name, efi_guid_t *guid, u8 *value)
{
  (void)guid;
  writes++;
  last_name = name;
  memcpy(last_value, value, MARKER_SIZE);
  return next_status;
}
'''
harness += function("mba_write_stage") + function("mba_write_entry_stage") + function("mba_stage_callback")
harness += r'''
static void callback(struct mba_stage_hook *hook)
{
  mba_stage_callback(0, 0, &hook->ops, NULL);
}

static void reset(void)
{
  armed = entry_armed = false;
  stage = entry_stage = 0;
  last_efi_status = entry_efi_status = 0;
  writes = 0;
  next_status = EFI_SUCCESS;
  memset(marker, 0, sizeof(marker));
  memset(entry_marker, 0, sizeof(entry_marker));
}

int main(void)
{
  struct mba_stage_hook hibernate = { .value = 1 };
  struct mba_stage_hook swsusp_write = { .value = 2 };

  reset();
  callback(&hibernate);
  callback(&swsusp_write);
  assert(writes == 0 && stage == 0 && entry_stage == 0);

  reset();
  memcpy(entry_marker, "MBFE", 4);
  entry_marker[4] = 0xa5;
  entry_armed = true;
  callback(&hibernate);
  assert(writes == 1 && last_name == entry_name && entry_stage == 1);
  assert(last_value[4] == 0xa5 && last_value[16] == 1);
  assert(entry_efi_status == EFI_SUCCESS && !entry_armed && stage == 0);
  callback(&hibernate);
  callback(&swsusp_write);
  assert(writes == 1);

  reset();
  memcpy(entry_marker, "MBFE", 4);
  entry_armed = true;
  next_status = EFI_NOT_READY;
  callback(&hibernate);
  assert(writes == 1 && entry_stage == 1);
  assert(entry_efi_status == EFI_NOT_READY && !entry_armed);
  next_status = EFI_SUCCESS;
  callback(&hibernate);
  assert(writes == 1);

  reset();
  memcpy(marker, "MBA9", 4);
  marker[4] = 0x5a;
  armed = true;
  callback(&swsusp_write);
  assert(writes == 0 && stage == 0);
  callback(&hibernate);
  assert(writes == 1 && last_name == marker_name && stage == 1);
  assert(last_value[4] == 0x5a && last_value[16] == 1);
  callback(&hibernate);
  assert(writes == 1);
  callback(&swsusp_write);
  assert(writes == 2 && stage == 2 && last_value[16] == 2);
  callback(&swsusp_write);
  assert(writes == 2);

  reset();
  armed = true;
  callback(&hibernate);
  next_status = EFI_DEVICE_ERROR;
  callback(&swsusp_write);
  assert(writes == 2 && stage == 2);
  assert(last_efi_status == EFI_DEVICE_ERROR && !armed);
  next_status = EFI_SUCCESS;
  callback(&swsusp_write);
  assert(writes == 2);

  reset();
  armed = true;
  next_status = EFI_DEVICE_ERROR;
  callback(&hibernate);
  assert(writes == 1 && stage == 1 && !armed);
  callback(&swsusp_write);
  assert(writes == 1 && stage == 1);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-efi-ftrace-callback-") as temporary:
  c_file = Path(temporary) / "callback.c"
  binary = Path(temporary) / "callback"
  c_file.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(binary), str(c_file)], check=True)
  subprocess.run([str(binary)], check=True)

print("PASS: extracted EFI ftrace callback writes once and disarms on failure")
