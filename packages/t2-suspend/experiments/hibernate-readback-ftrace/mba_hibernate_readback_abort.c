// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#define TARGET_FUNCTION "hibernation_restore"

static bool armed;
static bool registered;
static unsigned int interceptions;
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(interceptions, "One-use readback-complete interceptions");

static int notrace mba_skip_atomic_restore(int platform_mode)
{
  (void)platform_mode;
  pr_notice("mba-hibernate-readback: image readback complete; aborting before atomic restore\n");
  return -ECANCELED;
}

static void notrace mba_readback_hook(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
  (void)ip;
  (void)parent_ip;
  (void)ops;
  if (!READ_ONCE(armed) || cmpxchg(&interceptions, 0, 1) != 0)
    return;

  WRITE_ONCE(armed, false);
  ftrace_regs_set_instruction_pointer(fregs,
                                      (unsigned long)mba_skip_atomic_restore);
}

static struct ftrace_ops readback_ops = {
  .func = mba_readback_hook,
  .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
           FTRACE_OPS_FL_IPMODIFY,
};

static int mba_set_armed(const char *value, const struct kernel_param *parameter)
{
  bool requested;
  int error;

  (void)parameter;
  error = kstrtobool(value, &requested);
  if (error)
    return error;
  if (requested && (!READ_ONCE(registered) || READ_ONCE(armed) ||
                    READ_ONCE(interceptions) != 0))
    return -EPERM;
  WRITE_ONCE(armed, requested);
  return 0;
}

static int mba_get_armed(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", READ_ONCE(armed));
}

static const struct kernel_param_ops armed_ops = {
  .set = mba_set_armed,
  .get = mba_get_armed,
};
module_param_cb(armed, &armed_ops, NULL, 0600);
MODULE_PARM_DESC(armed, "One-use abort after image readback, never on module insertion");

static int __init mba_readback_init(void)
{
  int error;

  if (READ_ONCE(armed))
    return -EPERM;
  error = ftrace_set_filter(&readback_ops,
                            (unsigned char *)TARGET_FUNCTION,
                            sizeof(TARGET_FUNCTION) - 1, 0);
  if (error)
    return error;

  error = register_ftrace_function(&readback_ops);
  if (error) {
    ftrace_free_filter(&readback_ops);
    return error;
  }

  WRITE_ONCE(registered, true);
  pr_info("mba-hibernate-readback: loaded disarmed\n");
  return 0;
}

static void __exit mba_readback_exit(void)
{
  WRITE_ONCE(armed, false);
  WRITE_ONCE(registered, false);
  unregister_ftrace_function(&readback_ops);
  ftrace_free_filter(&readback_ops);
  pr_info("mba-hibernate-readback: unloaded\n");
}

module_init(mba_readback_init);
module_exit(mba_readback_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("One-use abort after in-place hibernation image readback");
MODULE_LICENSE("GPL");
