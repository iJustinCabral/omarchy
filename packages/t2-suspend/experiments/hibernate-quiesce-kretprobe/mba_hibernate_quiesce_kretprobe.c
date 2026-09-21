// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/ptrace.h>

struct quiesce_probe_state {
  bool intercept;
};

static bool armed;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Convert successful PMSG_QUIESCE completion to ECANCELED");
MODULE_PARM_DESC(interceptions, "Number of successful quiesce calls intercepted");

static int dpm_suspend_start_entry(struct kretprobe_instance *instance,
                                   struct pt_regs *regs)
{
  struct quiesce_probe_state *state = (void *)instance->data;
  unsigned long event = regs_get_kernel_argument(regs, 0);

  state->intercept = READ_ONCE(armed) && event == PM_EVENT_QUIESCE;
  return 0;
}

static int dpm_suspend_start_return(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
  struct quiesce_probe_state *state = (void *)instance->data;
  long error;

  if (!state->intercept)
    return 0;

  error = regs_return_value(regs);
  if (error) {
    pr_notice("mba-hibernate-quiesce: device quiesce failed with %ld; preserving error\n",
              error);
  } else {
    regs_set_return_value(regs, -ECANCELED);
    WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
    pr_notice("mba-hibernate-quiesce: device quiesce complete; aborting before memory restore\n");
  }

  return 0;
}

static struct kretprobe dpm_suspend_start_probe = {
  .kp.symbol_name = "dpm_suspend_start",
  .entry_handler = dpm_suspend_start_entry,
  .handler = dpm_suspend_start_return,
  .data_size = sizeof(struct quiesce_probe_state),
  .maxactive = 1,
};

static int __init mba_hibernate_quiesce_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = register_kretprobe(&dpm_suspend_start_probe);
  if (error)
    return error;

  pr_info("mba-hibernate-quiesce: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_quiesce_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_kretprobe(&dpm_suspend_start_probe);
  pr_info("mba-hibernate-quiesce: unloaded; missed %d instances\n",
          dpm_suspend_start_probe.nmissed);
}

module_init(mba_hibernate_quiesce_init);
module_exit(mba_hibernate_quiesce_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore after stock-kernel device quiesce");
MODULE_LICENSE("GPL");
