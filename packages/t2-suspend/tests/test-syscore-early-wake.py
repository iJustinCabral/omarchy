#!/usr/bin/env python3
"""Exercise the interrupt-independent BCE syscore wake path offline."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

assert len(sys.argv) == 2, "usage: test-syscore-early-wake.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1])
core = (root / "drivers/staging/t2bce/t2bce_core/t2bce_main.c").read_text()
header = (root / "drivers/staging/t2bce/t2bce_core/t2bce.h").read_text()
mailbox = (root / "drivers/staging/t2bce/t2bce_core/mailbox.c").read_text()
mailbox_header = (root / "drivers/staging/t2bce/t2bce_core/mailbox.h").read_text()


def function(source, name, return_type="int"):
  match = re.search(r"static " + return_type + " " + name + r"\([^;]+?\)\n\{", source)
  if match is None:
    match = re.search(return_type + " " + name + r"\([^;]+?\)\n\{", source)
  assert match, f"missing {name}"
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


poll = function(mailbox, "bce_mailbox_send_locked_poll")
retrieve = function(mailbox, "bce_mailbox_retrive_response")
syscore_resume = function(core, "t2bce_syscore_resume", "void")
resume_mode = function(core, "t2bce_resume_mode")

assert "#include <linux/iopoll.h>" in mailbox
assert "readl_poll_timeout_atomic" in poll
assert poll.index("atomic_cmpxchg") < poll.index("iowrite32")
assert poll.index("iowrite32") < poll.index("readl_poll_timeout_atomic")
assert poll.index("readl_poll_timeout_atomic") < poll.index("bce_mailbox_retrive_response")
assert poll.index("bce_mailbox_retrive_response") < poll.index("atomic_set")
assert "bce_mailbox_send_locked_poll" in mailbox_header
assert "bool no_state_early_wake_attempted;" in header
assert "int no_state_early_wake_status;" in header
assert "#include <linux/syscore_ops.h>" in core
assert "register_syscore(&t2bce_syscore);" in core
assert "unregister_syscore(&t2bce_syscore);" in core
assert core.index("register_syscore(&t2bce_syscore);") > core.index("pci_register_driver(&t2bce_pci_driver)")
assert core.index("unregister_syscore(&t2bce_syscore);") < core.index("pci_unregister_driver(&t2bce_pci_driver);", core.index("static void __exit"))
assert syscore_resume.index("no_state_resume") < syscore_resume.index("bce_mailbox_send_locked_poll")
assert syscore_resume.index("no_state_queues_dropped") < syscore_resume.index("bce_mailbox_send_locked_poll")
assert syscore_resume.index("no_state_early_wake_attempted = true") < syscore_resume.index("bce_mailbox_send_locked_poll")
assert syscore_resume.index("pci_read_config_word") < syscore_resume.index("bce_mailbox_send_locked_poll")
assert "BCE_MB_TYPE(response) != BCE_MB_RESTORE_NO_STATE" in syscore_resume
assert "if (bce->no_state_early_wake_attempted)" in resume_mode
assert resume_mode.index("no_state_early_wake_status") < resume_mode.index("bce_pm_resume_no_state(bce)")
assert resume_mode.index("wake_status && !allow_cold_boot") < resume_mode.index("cold restore")

harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define REG_MBOX_OUT_BASE 0x820
#define REG_MBOX_REPLY_COUNTER 0x108
#define REG_MBOX_REPLY_BASE 0x810
#define BCE_SYSCORE_WAKE_TIMEOUT_US 1000000
#define BCE_MB_RESTORE_NO_STATE 0x15
#define PCI_COMMAND 4
#define PCI_COMMAND_MASTER 4
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define BCE_MB_MSG(type, value) (((uint64_t)(type) << 58) | ((value) & 0x3ffffffffffffffULL))
#define BCE_MB_TYPE(value) ((uint32_t)((value) >> 58))
#define READ_ONCE(value) (value)
#define __iomem
#define pr_debug(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { int value; } atomic_t;
struct bce_mailbox {
  u8 *reg_mb;
  atomic_t mb_status;
  u64 mb_result;
};
struct pci_dev { uint16_t command; bool fail_read; };
struct t2bce_device {
  struct pci_dev *pci, *pci0, *pci2, *pci3;
  struct bce_mailbox mbox;
  bool no_state_resume;
  bool no_state_queues_dropped;
  bool no_state_early_wake_attempted;
  int no_state_early_wake_status;
};
struct syscore_ops { void (*resume)(void *data); };
struct syscore { const struct syscore_ops *ops; };

static struct t2bce_device *global_bce;
static struct pci_dev functions[4];
static int writes;

static int atomic_cmpxchg(atomic_t *value, int old, int new_value) {
  int previous = value->value;
  if (previous == old)
    value->value = new_value;
  return previous;
}
static void atomic_set(atomic_t *value, int new_value) { value->value = new_value; }
static int pci_read_config_word(struct pci_dev *pdev, int where, uint16_t *value) {
  assert(where == PCI_COMMAND);
  if (pdev->fail_read)
    return -EIO;
  *value = pdev->command;
  return 0;
}
static u32 ioread32(void *address) { return *(u32 *)address; }
static void iowrite32(u32 value, void *address) { *(u32 *)address = value; writes++; }
#define readl_poll_timeout_atomic(addr, val, cond, delay_us, timeout_us) ({ \
  int __status = -ETIMEDOUT; \
  (void)(delay_us); (void)(timeout_us); \
  for (int __i = 0; __i < 4; __i++) { \
    (val) = ioread32(addr); \
    if (cond) { __status = 0; break; } \
  } \
  __status; \
})
'''
harness += retrieve + poll + syscore_resume
harness += r'''
static void set_reply(u8 *mmio, u32 type) {
  u64 reply = (u64)type << 58;
  *(u32 *)(mmio + REG_MBOX_REPLY_COUNTER) = 1U << 20;
  *(u32 *)(mmio + REG_MBOX_REPLY_BASE) = (u32)reply;
  *(u32 *)(mmio + REG_MBOX_REPLY_BASE + 4) = (u32)(reply >> 32);
}

static void reset_device(struct t2bce_device *bce, u8 *mmio) {
  memset(mmio, 0, 0x900);
  memset(functions, 0, sizeof(functions));
  *bce = (struct t2bce_device){0};
  bce->pci0 = &functions[0];
  bce->pci = &functions[1];
  bce->pci2 = &functions[2];
  bce->pci3 = &functions[3];
  bce->mbox.reg_mb = mmio;
  global_bce = bce;
  writes = 0;
}

int main(void) {
  u8 mmio[0x900];
  struct t2bce_device bce;

  reset_device(&bce, mmio);
  t2bce_syscore_resume(NULL);
  assert(!bce.no_state_early_wake_attempted);
  assert(writes == 0);

  reset_device(&bce, mmio);
  bce.no_state_resume = true;
  bce.no_state_queues_dropped = true;
  bce.pci3->command = PCI_COMMAND_MASTER;
  set_reply(mmio, BCE_MB_RESTORE_NO_STATE);
  t2bce_syscore_resume(NULL);
  assert(bce.no_state_early_wake_attempted);
  assert(bce.no_state_early_wake_status == -EIO);
  assert(writes == 0);

  reset_device(&bce, mmio);
  bce.no_state_resume = true;
  bce.no_state_queues_dropped = true;
  set_reply(mmio, BCE_MB_RESTORE_NO_STATE);
  t2bce_syscore_resume(NULL);
  assert(bce.no_state_early_wake_attempted);
  assert(bce.no_state_early_wake_status == 0);
  assert(bce.mbox.mb_status.value == 0);
  assert(writes == 4);
  assert(BCE_MB_TYPE(*(u64 *)(mmio + REG_MBOX_OUT_BASE)) == BCE_MB_RESTORE_NO_STATE);
  t2bce_syscore_resume(NULL);
  assert(writes == 4);

  reset_device(&bce, mmio);
  bce.no_state_resume = true;
  bce.no_state_queues_dropped = true;
  set_reply(mmio, 0x1a);
  t2bce_syscore_resume(NULL);
  assert(bce.no_state_early_wake_attempted);
  assert(bce.no_state_early_wake_status == -EINVAL);
  assert(bce.mbox.mb_status.value == 0);

  reset_device(&bce, mmio);
  bce.no_state_resume = true;
  bce.no_state_queues_dropped = true;
  t2bce_syscore_resume(NULL);
  assert(bce.no_state_early_wake_attempted);
  assert(bce.no_state_early_wake_status == -ETIMEDOUT);
  assert(bce.mbox.mb_status.value == 0);

  reset_device(&bce, mmio);
  bce.mbox.mb_status.value = 1;
  set_reply(mmio, BCE_MB_RESTORE_NO_STATE);
  u64 response = 0;
  assert(bce_mailbox_send_locked_poll(&bce.mbox,
          BCE_MB_MSG(BCE_MB_RESTORE_NO_STATE, 0), &response, 1000) == -EEXIST);
  assert(writes == 0);
  return 0;
}
'''

with tempfile.TemporaryDirectory() as directory:
  source = Path(directory) / "syscore-early-wake.c"
  binary = Path(directory) / "syscore-early-wake"
  source.write_text(harness)
  subprocess.run(
    ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
    check=True,
  )
  subprocess.run([str(binary)], check=True)

print("PASS: BCE no-state wake runs from syscore with polling and fail-closed reuse")
