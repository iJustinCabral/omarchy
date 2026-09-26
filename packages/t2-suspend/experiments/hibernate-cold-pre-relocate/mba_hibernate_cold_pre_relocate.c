// SPDX-License-Identifier: GPL-2.0
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/irqflags.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

#define TARGET_FUNCTION "relocate_restore_code"
static bool registered;
static bool armed;
static bool arm_consumed;
static unsigned int interceptions;
static char vector_prefix[25];
static bool observed_irqs_disabled;
static unsigned int observed_online_cpus;
static bool observed_boundary_valid;
module_param(arm_consumed, bool, 0400);
module_param(interceptions, uint, 0400);
module_param_string(vector_prefix, vector_prefix, sizeof(vector_prefix), 0400);
module_param(observed_irqs_disabled, bool, 0400);
module_param(observed_online_cpus, uint, 0400);
module_param(observed_boundary_valid, bool, 0400);

static int notrace mba_pre_relocate_abort(void)
{
  return -ECANCELED;
}

static void notrace mba_pre_relocate_hook(unsigned long ip, unsigned long parent_ip,
                                        struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
  (void)ip;
  (void)parent_ip;
  (void)ops;
  if (!READ_ONCE(armed)) {
    if (READ_ONCE(arm_consumed) || READ_ONCE(interceptions))
      goto Abort;
    return;
  }
  if (cmpxchg(&interceptions, 0, 1) == 0) {
    WRITE_ONCE(observed_irqs_disabled, irqs_disabled());
    WRITE_ONCE(observed_online_cpus, num_online_cpus());
    WRITE_ONCE(observed_boundary_valid,
               READ_ONCE(observed_irqs_disabled) && READ_ONCE(observed_online_cpus) == 1);
    WRITE_ONCE(armed, false);
  }
Abort:
  // A mismatched observation invalidates proof, never the abort itself.
  ftrace_regs_set_instruction_pointer(fregs, (unsigned long)mba_pre_relocate_abort);
}

static int mba_set_arm_prefix(const char *value, const struct kernel_param *parameter)
{
  size_t length = strcspn(value, "\n");
  size_t index;

  (void)parameter;
  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) || READ_ONCE(armed))
    return -EPERM;
  if (length != 24 || (value[length] != '\0' && value[length + 1] != '\0'))
    return -EINVAL;
  for (index = 0; index < length; index++) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f')))
      return -EINVAL;
  }
  memcpy(vector_prefix, value, 24);
  vector_prefix[24] = '\0';
  WRITE_ONCE(arm_consumed, true);
  smp_wmb();
  WRITE_ONCE(armed, true);
  return 0;
}

static int mba_get_arm_prefix(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", READ_ONCE(armed));
}
static const struct kernel_param_ops arm_prefix_ops = {
  .set = mba_set_arm_prefix,
  .get = mba_get_arm_prefix,
};
module_param_cb(arm_prefix, &arm_prefix_ops, NULL, 0600);

static struct ftrace_ops pre_relocate_ops = {
  .func = mba_pre_relocate_hook,
  .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY |
           FTRACE_OPS_FL_PERMANENT,
};

static int __init mba_pre_relocate_init(void)
{
  int error;

  if (READ_ONCE(armed) || READ_ONCE(arm_consumed) || interceptions || vector_prefix[0] ||
      observed_irqs_disabled || observed_online_cpus || observed_boundary_valid)
    return -EPERM;
  error = ftrace_set_filter(&pre_relocate_ops, (unsigned char *)TARGET_FUNCTION,
                            sizeof(TARGET_FUNCTION) - 1, 0);
  if (error)
    return error;
  error = register_ftrace_function(&pre_relocate_ops);
  if (error) {
    ftrace_free_filter(&pre_relocate_ops);
    return error;
  }
  WRITE_ONCE(registered, true);
  return 0;
}

static void __exit mba_pre_relocate_exit(void)
{
  WRITE_ONCE(armed, false);
  WRITE_ONCE(registered, false);
  unregister_ftrace_function(&pre_relocate_ops);
  ftrace_free_filter(&pre_relocate_ops);
}
module_init(mba_pre_relocate_init);
module_exit(mba_pre_relocate_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(mba_cold_boundary, "pre-relocate-v1");
MODULE_INFO(mba_cold_permanent, "v1");
MODULE_DESCRIPTION("Cold restore abort after temporary mapping setup, before restore-code relocation; RAM observations only");
