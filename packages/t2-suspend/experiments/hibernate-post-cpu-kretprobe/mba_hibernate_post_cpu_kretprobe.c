// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

struct post_cpu_probe_state {
  bool intercept;
};

static bool armed;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Convert successful restore CPU disable to ECANCELED");
MODULE_PARM_DESC(interceptions, "Number of successful CPU-disable calls intercepted");

static int cpu_disable_entry(struct kretprobe_instance *instance,
                             struct pt_regs *regs)
{
  struct post_cpu_probe_state *state = (void *)instance->data;

  (void)regs;
  state->intercept = READ_ONCE(armed);
  return 0;
}

static int cpu_disable_return(struct kretprobe_instance *instance,
                              struct pt_regs *regs)
{
  struct post_cpu_probe_state *state = (void *)instance->data;
  long error;

  if (!state->intercept)
    return 0;

  error = regs_return_value(regs);
  if (error) {
    pr_notice("mba-hibernate-post-cpu: CPU disable failed with %ld; preserving error\n",
              error);
  } else {
    regs_set_return_value(regs, -ECANCELED);
    WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
    pr_notice("mba-hibernate-post-cpu: secondary CPU disable complete; aborting before IRQ and syscore suspend\n");
  }

  return 0;
}

static struct kretprobe cpu_disable_probe = {
  .kp.symbol_name = "hibernate_resume_nonboot_cpu_disable",
  .entry_handler = cpu_disable_entry,
  .handler = cpu_disable_return,
  .data_size = sizeof(struct post_cpu_probe_state),
  .maxactive = 1,
};

static int __init mba_hibernate_post_cpu_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = register_kretprobe(&cpu_disable_probe);
  if (error)
    return error;

  pr_info("mba-hibernate-post-cpu: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_post_cpu_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_kretprobe(&cpu_disable_probe);
  pr_info("mba-hibernate-post-cpu: unloaded; missed %d instances\n",
          cpu_disable_probe.nmissed);
}

module_init(mba_hibernate_post_cpu_init);
module_exit(mba_hibernate_post_cpu_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore after secondary CPU disable");
MODULE_LICENSE("GPL");
