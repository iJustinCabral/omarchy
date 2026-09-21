// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/module.h>

#define TARGET_FUNCTION "hibernate_resume_nonboot_cpu_disable"

static bool armed;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Skip hibernation restore CPU disable with ECANCELED");
MODULE_PARM_DESC(interceptions, "Number of CPU-disable calls intercepted");

static int notrace mba_hibernate_skip_cpu_disable(void)
{
  WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
  pr_notice("mba-hibernate-pre-cpu: late/noirq and platform pre-restore complete; aborting before CPU disable\n");
  return -ECANCELED;
}

static void notrace mba_hibernate_pre_cpu_hook(unsigned long ip,
                                               unsigned long parent_ip,
                                               struct ftrace_ops *ops,
                                               struct ftrace_regs *fregs)
{
  (void)ip;
  (void)parent_ip;
  (void)ops;
  if (READ_ONCE(armed))
    ftrace_regs_set_instruction_pointer(fregs,
                                        (unsigned long)mba_hibernate_skip_cpu_disable);
}

static struct ftrace_ops pre_cpu_ops = {
  .func = mba_hibernate_pre_cpu_hook,
  .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
           FTRACE_OPS_FL_IPMODIFY,
};

static int __init mba_hibernate_pre_cpu_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = ftrace_set_filter(&pre_cpu_ops, (unsigned char *)TARGET_FUNCTION,
                            sizeof(TARGET_FUNCTION) - 1, 0);
  if (error)
    return error;

  error = register_ftrace_function(&pre_cpu_ops);
  if (error) {
    ftrace_free_filter(&pre_cpu_ops);
    return error;
  }

  pr_info("mba-hibernate-pre-cpu: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_pre_cpu_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_ftrace_function(&pre_cpu_ops);
  ftrace_free_filter(&pre_cpu_ops);
  pr_info("mba-hibernate-pre-cpu: unloaded\n");
}

module_init(mba_hibernate_pre_cpu_init);
module_exit(mba_hibernate_pre_cpu_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore after late/noirq and before CPU disable");
MODULE_LICENSE("GPL");
