// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/ftrace.h>
#include <linux/hex.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

#define MARKER_SIZE 17
#define MARKER_ATTRS (EFI_VARIABLE_NON_VOLATILE | \
                      EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                      EFI_VARIABLE_RUNTIME_ACCESS)

#ifdef MBA_RESTORE_MARKER_V2
static efi_char16_t marker_name[] = L"OmarchyT2RestoreStageV2";
#else
static efi_char16_t marker_name[] = L"OmarchyT2RestoreStage";
#endif
static efi_guid_t marker_guid =
  EFI_GUID(0x5e17d2ad, 0x021f, 0x4d45, 0xa8, 0xe5, 0xf4, 0xc1, 0x91, 0x98, 0x3e, 0x27);
static u8 marker[MARKER_SIZE];
static bool armed;
static bool arm_consumed;
static bool registered;
static unsigned int stage;
static unsigned long last_efi_status;
module_param(stage, uint, 0400);
module_param(last_efi_status, ulong, 0400);
MODULE_PARM_DESC(stage, "Last monotonic cold-restore boundary observed");
MODULE_PARM_DESC(last_efi_status, "Status of the last nonblocking EFI write");

struct mba_stage_hook {
  const char *function;
  unsigned int value;
  struct ftrace_ops ops;
};

static efi_status_t notrace mba_write_stage(unsigned int next)
{
  u8 value[MARKER_SIZE];
  efi_status_t status;

  memcpy(value, marker, sizeof(value));
  value[16] = next;
  if (efivar_trylock())
    return EFI_NOT_READY;
  status = efivar_set_variable_locked(marker_name, &marker_guid,
                                     MARKER_ATTRS, MARKER_SIZE, value, true);
  efivar_unlock();
  return status;
}

static void notrace mba_advance(unsigned int previous, unsigned int next)
{
  efi_status_t status;

  if (!READ_ONCE(armed) || cmpxchg(&stage, previous, next) != previous)
    return;
  status = mba_write_stage(next);
  WRITE_ONCE(last_efi_status, status);
  if (status != EFI_SUCCESS)
    WRITE_ONCE(armed, false);
}

static void notrace mba_stage_callback(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops,
                                       struct ftrace_regs *fregs)
{
  struct mba_stage_hook *hook = container_of(ops, struct mba_stage_hook, ops);

  (void)ip;
  (void)parent_ip;
  (void)fregs;
  mba_advance(hook->value - 1, hook->value);
}

static struct mba_stage_hook hooks[] = {
  { .function = "swsusp_check", .value = 1 },
  { .function = "swsusp_read", .value = 3 },
  { .function = "hibernation_restore", .value = 5 },
  { .function = "dpm_suspend_start", .value = 6 },
  { .function = "dpm_suspend_end", .value = 7 },
};

static int notrace mba_check_return(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
  (void)instance;
  if (regs_return_value(regs) == 0)
    mba_advance(1, 2);
  else
    WRITE_ONCE(armed, false);
  return 0;
}

static int notrace mba_read_return(struct kretprobe_instance *instance,
                                   struct pt_regs *regs)
{
  (void)instance;
  if (regs_return_value(regs) == 0)
    mba_advance(3, 4);
  else
    WRITE_ONCE(armed, false);
  return 0;
}

static struct kretprobe check_return_probe = {
  .kp.symbol_name = "swsusp_check",
  .handler = mba_check_return,
  .maxactive = 1,
};

static struct kretprobe read_return_probe = {
  .kp.symbol_name = "swsusp_read",
  .handler = mba_read_return,
  .maxactive = 1,
};

static int mba_set_arm_prefix(const char *value, const struct kernel_param *parameter)
{
  u8 expected[MARKER_SIZE] = { 'M', 'B', 'R', 'S' };
  u8 actual[MARKER_SIZE];
  unsigned long size = sizeof(actual);
  u32 attrs = 0;
  efi_status_t status;
  size_t length;
  size_t index;
  int error;

  (void)parameter;
  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) || READ_ONCE(armed))
    return -EPERM;
  length = strcspn(value, "\n");
  if (length != 24 || (value[length] != '\0' && value[length + 1] != '\0'))
    return -EINVAL;
  for (index = 0; index < length; index++) {
    if (!((value[index] >= '0' && value[index] <= '9') ||
          (value[index] >= 'a' && value[index] <= 'f')))
      return -EINVAL;
  }
  error = hex2bin(expected + 4, value, 12);
  if (error)
    return error;
  if (!efi_rt_services_supported(EFI_RT_SUPPORTED_GET_VARIABLE |
                                 EFI_RT_SUPPORTED_SET_VARIABLE |
                                 EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO) ||
      !efi.set_variable_nonblocking || !efi.query_variable_info_nonblocking ||
      !efivar_is_available() || !efivar_supports_writes())
    return -EOPNOTSUPP;

  error = efivar_lock();
  if (error)
    return error;
  status = efivar_get_variable(marker_name, &marker_guid, &attrs, &size, actual);
  efivar_unlock();
  if (status != EFI_SUCCESS)
    return efi_status_to_err(status);
  if (size != sizeof(actual) || attrs != MARKER_ATTRS ||
      memcmp(actual, expected, sizeof(actual)))
    return -EINVAL;

  memcpy(marker, expected, sizeof(marker));
  WRITE_ONCE(last_efi_status, EFI_SUCCESS);
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
MODULE_PARM_DESC(arm_prefix, "Arm one exact prewritten 12-byte vector prefix; never on insertion");

static int __init mba_restore_marker_init(void)
{
  unsigned int index;
  int error;

  if (READ_ONCE(armed))
    return -EPERM;
  error = register_kretprobe(&check_return_probe);
  if (error)
    return error;
  error = register_kretprobe(&read_return_probe);
  if (error)
    goto unregister_check_return;
  for (index = 0; index < ARRAY_SIZE(hooks); index++) {
    struct mba_stage_hook *hook = &hooks[index];

    hook->ops.func = mba_stage_callback;
    hook->ops.flags = FTRACE_OPS_FL_RECURSION;
    error = ftrace_set_filter(&hook->ops, (unsigned char *)hook->function,
                              strlen(hook->function), 0);
    if (error)
      goto unregister_previous;
    error = register_ftrace_function(&hook->ops);
    if (error) {
      ftrace_free_filter(&hook->ops);
      goto unregister_previous;
    }
  }
  WRITE_ONCE(registered, true);
  pr_info("mba-hibernate-restore-marker: loaded disarmed\n");
  return 0;

unregister_previous:
  while (index--) {
    unregister_ftrace_function(&hooks[index].ops);
    ftrace_free_filter(&hooks[index].ops);
  }
  unregister_kretprobe(&read_return_probe);
unregister_check_return:
  unregister_kretprobe(&check_return_probe);
  return error;
}

static void __exit mba_restore_marker_exit(void)
{
  unsigned int index;

  WRITE_ONCE(armed, false);
  WRITE_ONCE(registered, false);
  for (index = ARRAY_SIZE(hooks); index > 0; index--) {
    unregister_ftrace_function(&hooks[index - 1].ops);
    ftrace_free_filter(&hooks[index - 1].ops);
  }
  unregister_kretprobe(&read_return_probe);
  unregister_kretprobe(&check_return_probe);
  pr_info("mba-hibernate-restore-marker: unloaded\n");
}

module_init(mba_restore_marker_init);
module_exit(mba_restore_marker_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("One-use EFI stages at cold hibernation restore boundaries");
#ifdef MBA_RESTORE_MARKER_V2
MODULE_INFO(mba_restore_variable, "v2");
#endif
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EFIVAR");
