#!/usr/bin/python3
"""Exercise the candidate VHCI waiter lifetime after command timeouts."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile


assert len(sys.argv) == 2, "usage: test-vhci-command-timeout.py PATCHED_SOURCE_ROOT"
root = Path(sys.argv[1]) / "drivers/staging/t2bce/t2bce_vhci"
source = (root / "queue.c").read_text()
header = (root / "queue.h").read_text()
assert "bool quarantined;" in header


def function(name):
  match = re.search(r"(?:static )?(?:int|void) " + name + r"\([^;]+?\)\n\{", source)
  assert match, name
  index = match.end()
  depth = 1
  while depth:
    depth += (source[index] == "{") - (source[index] == "}")
    index += 1
  return source[match.start():index] + "\n"


functions = "\n".join(function(name) for name in (
  "bce_vhci_command_queue_create",
  "bce_vhci_command_queue_deliver_completion",
  "bce_vhci_command_queue_quarantine",
  "__bce_vhci_command_queue_execute",
  "bce_vhci_command_queue_execute",
))
assert functions.index("bce_vhci_command_queue_quarantine(cq);") < functions.index("return status;", functions.index("cannot reserve cancellation"))

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#define BCE_VHCI_ABORT 3
#define BCE_VHCI_SUCCESS 0
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
struct completion { int unused; };
struct spinlock { int unused; };
struct mutex { int unused; };
struct bce_vhci_message { unsigned short cmd, status; };
struct bce_vhci_message_queue { void *sq; };
struct bce_vhci_command_queue_completion {
  struct bce_vhci_message *result;
  struct completion completion;
};
struct bce_vhci_command_queue {
  struct bce_vhci_message_queue *mq;
  struct bce_vhci_command_queue_completion completion;
  struct spinlock completion_lock;
  struct mutex mutex;
  bool quarantined;
};
static void init_completion(struct completion *value) { (void)value; }
static void reinit_completion(struct completion *value) { (void)value; }
static void complete(struct completion *value) { (void)value; }
static void spin_lock_init(struct spinlock *value) { (void)value; }
static void spin_lock(struct spinlock *value) { (void)value; }
static void spin_unlock(struct spinlock *value) { (void)value; }
static void mutex_init(struct mutex *value) { (void)value; }
static void mutex_lock(struct mutex *value) { (void)value; }
static void mutex_unlock(struct mutex *value) { (void)value; }

enum scenario { RESERVE_CANCEL_FAIL, CANCEL_TIMEOUT, REPLY_MISMATCH, SUCCESS };
static enum scenario scenario;
static struct bce_vhci_command_queue *active;
static unsigned int reserve_calls, wait_calls, writes;
static unsigned short last_cmd;
static int t2bce_core_reserve_submission(void *sq, unsigned long *timeout)
{
  (void)sq; (void)timeout;
  reserve_calls++;
  if (scenario == RESERVE_CANCEL_FAIL && reserve_calls == 2)
    return -EAGAIN;
  return 0;
}
static void bce_vhci_message_queue_write(struct bce_vhci_message_queue *mq,
                                         struct bce_vhci_message *value)
{
  (void)mq;
  writes++;
  last_cmd = value->cmd;
}
static void bce_vhci_command_queue_deliver_completion(struct bce_vhci_command_queue *cq,
                                                       struct bce_vhci_message *msg);
static unsigned long wait_for_completion_timeout(struct completion *completion, unsigned long timeout)
{
  struct bce_vhci_message reply = { .cmd = last_cmd | 0x8000, .status = BCE_VHCI_SUCCESS };
  (void)completion; (void)timeout;
  wait_calls++;
  if (scenario == REPLY_MISMATCH || scenario == SUCCESS) {
    if (scenario == REPLY_MISMATCH)
      reply.cmd = 0x8fff;
    bce_vhci_command_queue_deliver_completion(active, &reply);
    return 1;
  }
  return 0;
}
'''
harness += functions
harness += r'''
static void reset(enum scenario next, struct bce_vhci_command_queue *queue,
                  struct bce_vhci_message_queue *mq)
{
  scenario = next;
  active = queue;
  reserve_calls = wait_calls = writes = 0;
  last_cmd = 0;
  bce_vhci_command_queue_create(queue, mq);
}
int main(void)
{
  struct bce_vhci_command_queue queue = { 0 };
  struct bce_vhci_message_queue mq = { 0 };
  struct bce_vhci_message request = { .cmd = 0x42 };
  struct bce_vhci_message result = { 0 };
  struct bce_vhci_message late = { .cmd = 0x8042 };

  reset(RESERVE_CANCEL_FAIL, &queue, &mq);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == -EAGAIN);
  assert(queue.quarantined && queue.completion.result == NULL && writes == 1);
  result.cmd = 0x1234;
  bce_vhci_command_queue_deliver_completion(&queue, &late);
  assert(result.cmd == 0x1234);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == -EIO);
  assert(writes == 1 && reserve_calls == 2);

  reset(CANCEL_TIMEOUT, &queue, &mq);
  assert(!queue.quarantined);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == -ETIMEDOUT);
  assert(queue.quarantined && queue.completion.result == NULL && writes == 2);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == -EIO);
  assert(writes == 2);

  reset(REPLY_MISMATCH, &queue, &mq);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == -EIO);
  assert(queue.quarantined && queue.completion.result == NULL && writes == 1);

  reset(SUCCESS, &queue, &mq);
  assert(bce_vhci_command_queue_execute(&queue, &request, &result, 5) == 0);
  assert(!queue.quarantined && queue.completion.result == NULL && writes == 1);
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="t2-vhci-command-timeout-") as directory:
  c_file = Path(directory) / "timeout.c"
  executable = Path(directory) / "timeout"
  c_file.write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), str(c_file)], check=True)
  subprocess.run([str(executable)], check=True)

print("PASS: VHCI command timeout clears stale waiter and quarantines desynchronized queue")
