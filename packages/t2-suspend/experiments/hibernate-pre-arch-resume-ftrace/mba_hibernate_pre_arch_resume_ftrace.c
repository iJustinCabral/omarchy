// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/module.h>

#define TARGET_FUNCTION "swsusp_arch_resume"

static bool armed;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Skip architecture hibernation resume with ECANCELED");
MODULE_PARM_DESC(interceptions, "Number of architecture resume calls intercepted");

static int notrace mba_hibernate_skip_arch_resume(void)
{
  WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
  pr_notice("mba-hibernate-pre-arch-resume: processor state saved; aborting before atomic memory restore\n");
  return -ECANCELED;
}

static void notrace mba_hibernate_pre_arch_resume_hook(unsigned long ip,
                                                       unsigned long parent_ip,
                                                       struct ftrace_ops *ops,
                                                       struct ftrace_regs *fregs)
{
  (void)ip;
  (void)parent_ip;
  (void)ops;
  if (READ_ONCE(armed))
    ftrace_regs_set_instruction_pointer(fregs,
                                        (unsigned long)mba_hibernate_skip_arch_resume);
}

static struct ftrace_ops pre_arch_resume_ops = {
  .func = mba_hibernate_pre_arch_resume_hook,
  .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
           FTRACE_OPS_FL_IPMODIFY,
};

static int __init mba_hibernate_pre_arch_resume_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = ftrace_set_filter(&pre_arch_resume_ops,
                            (unsigned char *)TARGET_FUNCTION,
                            sizeof(TARGET_FUNCTION) - 1, 0);
  if (error)
    return error;

  error = register_ftrace_function(&pre_arch_resume_ops);
  if (error) {
    ftrace_free_filter(&pre_arch_resume_ops);
    return error;
  }

  pr_info("mba-hibernate-pre-arch-resume: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_pre_arch_resume_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_ftrace_function(&pre_arch_resume_ops);
  ftrace_free_filter(&pre_arch_resume_ops);
  pr_info("mba-hibernate-pre-arch-resume: unloaded\n");
}

module_init(mba_hibernate_pre_arch_resume_init);
module_exit(mba_hibernate_pre_arch_resume_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore before architecture memory replacement");
MODULE_LICENSE("GPL");
