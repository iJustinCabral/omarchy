// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

struct post_relocate_probe_state {
  bool intercept;
};

static bool armed;
static unsigned int interceptions;
module_param(armed, bool, 0600);
module_param(interceptions, uint, 0400);
MODULE_PARM_DESC(armed, "Convert successful restore-code relocation to ECANCELED");
MODULE_PARM_DESC(interceptions, "Number of successful relocation calls intercepted");

static int relocate_entry(struct kretprobe_instance *instance,
                          struct pt_regs *regs)
{
  struct post_relocate_probe_state *state = (void *)instance->data;

  (void)regs;
  state->intercept = READ_ONCE(armed);
  return 0;
}

static int relocate_return(struct kretprobe_instance *instance,
                           struct pt_regs *regs)
{
  struct post_relocate_probe_state *state = (void *)instance->data;
  long error;

  if (!state->intercept)
    return 0;

  error = regs_return_value(regs);
  if (error) {
    pr_notice("mba-hibernate-post-relocate: restore-code relocation failed with %ld; preserving error\n",
              error);
  } else {
    regs_set_return_value(regs, -ECANCELED);
    WRITE_ONCE(interceptions, READ_ONCE(interceptions) + 1);
    pr_notice("mba-hibernate-post-relocate: temporary mappings and restore-code relocation complete; aborting before restore_image\n");
  }

  return 0;
}

static struct kretprobe relocate_probe = {
  .kp.symbol_name = "relocate_restore_code",
  .entry_handler = relocate_entry,
  .handler = relocate_return,
  .data_size = sizeof(struct post_relocate_probe_state),
  .maxactive = 1,
};

static int __init mba_hibernate_post_relocate_init(void)
{
  int error;

  if (armed)
    return -EPERM;

  error = register_kretprobe(&relocate_probe);
  if (error)
    return error;

  pr_info("mba-hibernate-post-relocate: loaded disarmed\n");
  return 0;
}

static void __exit mba_hibernate_post_relocate_exit(void)
{
  WRITE_ONCE(armed, false);
  unregister_kretprobe(&relocate_probe);
  pr_info("mba-hibernate-post-relocate: unloaded; missed %d instances\n",
          relocate_probe.nmissed);
}

module_init(mba_hibernate_post_relocate_init);
module_exit(mba_hibernate_post_relocate_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Abort image restore after restore-code relocation");
MODULE_LICENSE("GPL");
