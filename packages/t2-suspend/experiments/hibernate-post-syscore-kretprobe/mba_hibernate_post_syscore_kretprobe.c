// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/syscore_ops.h>

struct post_syscore_probe_state {
  bool intercept;
};

static bool armed;
static unsigned int successful_calls;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(successful_calls, uint, 0400);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Convert successful restore syscore suspend to ECANCELED");
MODULE_PARM_DESC(successful_calls, "Number of armed successful syscore suspend calls");
MODULE_PARM_DESC(interceptions, "Number of restore syscore suspend calls intercepted");

static int syscore_suspend_entry(struct kretprobe_instance *instance,
                                 struct pt_regs *regs)
{
  struct post_syscore_probe_state *state = (void *)instance->data;

  (void)regs;
  state->intercept = READ_ONCE(armed);
  return 0;
}

static int syscore_suspend_return(struct kretprobe_instance *instance,
                                  struct pt_regs *regs)
{
  struct post_syscore_probe_state *state = (void *)instance->data;
  unsigned int call;
  long error;

  if (!state->intercept)
    return 0;

  error = regs_return_value(regs);
  if (error) {
    pr_notice("mba-hibernate-post-syscore: syscore suspend failed with %ld; preserving error\n",
              error);
    return 0;
  }

  call = READ_ONCE(successful_calls) + 1;
  WRITE_ONCE(successful_calls, call);
  if (call == 1) {
    pr_info("mba-hibernate-post-syscore: image-creation syscore suspend complete; continuing\n");
  } else if (call == 2) {
    syscore_resume();
    regs_set_return_value(regs, -ECANCELED);
    WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
    pr_notice("mba-hibernate-post-syscore: image-restore syscore suspend and explicit resume complete; aborting before processor and memory restore\n");
  }

  return 0;
}

static struct kretprobe syscore_suspend_probe = {
  .kp.symbol_name = "syscore_suspend",
  .entry_handler = syscore_suspend_entry,
  .handler = syscore_suspend_return,
  .data_size = sizeof(struct post_syscore_probe_state),
  .maxactive = 1,
};

static int __init mba_hibernate_post_syscore_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = register_kretprobe(&syscore_suspend_probe);
  if (error)
    return error;

  pr_info("mba-hibernate-post-syscore: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_post_syscore_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_kretprobe(&syscore_suspend_probe);
  pr_info("mba-hibernate-post-syscore: unloaded; missed %d instances\n",
          syscore_suspend_probe.nmissed);
}

module_init(mba_hibernate_post_syscore_init);
module_exit(mba_hibernate_post_syscore_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore after syscore suspend");
MODULE_LICENSE("GPL");
