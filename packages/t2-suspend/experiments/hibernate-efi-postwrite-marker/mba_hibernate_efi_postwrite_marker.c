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

#ifdef MBA_POSTWRITE_SOURCE_MARKER_V3
static efi_char16_t marker_name[] = L"OmarchyT2PostwriteStageV3";
#elif defined(MBA_POSTWRITE_SOURCE_MARKER_V2)
static efi_char16_t marker_name[] = L"OmarchyT2PostwriteStageV2";
#else
static efi_char16_t marker_name[] = L"OmarchyT2PostwriteStage";
#endif
static efi_guid_t marker_guid =
  EFI_GUID(0x47a2fceb, 0x87bc, 0x4e58, 0x8d, 0x83, 0x23, 0xf6, 0x2f, 0xfb, 0x33, 0x93);
static u8 marker[MARKER_SIZE];
static bool armed;
static bool arm_consumed;
static bool registered;
static bool write_succeeded;
static unsigned int stage;
static unsigned long last_efi_status;
module_param(stage, uint, 0400);
module_param(last_efi_status, ulong, 0400);
MODULE_PARM_DESC(stage, "Last monotonic hibernation source boundary reached");
MODULE_PARM_DESC(last_efi_status, "Status of the most recent nonblocking EFI write");

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

static void notrace mba_stage_callback(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops,
                                       struct ftrace_regs *fregs)
{
  struct mba_stage_hook *hook = container_of(ops, struct mba_stage_hook, ops);
  unsigned int previous = hook->value - 1;
  efi_status_t status;

  (void)ip;
  (void)parent_ip;
  (void)fregs;
  if (!READ_ONCE(armed) ||
      (hook->value >= 3 && !READ_ONCE(write_succeeded)) ||
      cmpxchg(&stage, previous, hook->value) != previous)
    return;
  status = mba_write_stage(hook->value);
  WRITE_ONCE(last_efi_status, status);
  if (status != EFI_SUCCESS)
    WRITE_ONCE(armed, false);
}

static struct mba_stage_hook hooks[] = {
  { .function = "hibernate", .value = 1 },
  { .function = "swsusp_write", .value = 2 },
  { .function = "hibernation_platform_enter", .value = 3 },
  { .function = "kernel_power_off", .value = 3 },
  { .function = "acpi_hibernation_enter", .value = 4 },
};

static int notrace mba_write_return(struct kretprobe_instance *instance,
                                    struct pt_regs *regs)
{
  (void)instance;
  if (READ_ONCE(armed) && READ_ONCE(stage) == 2) {
    if (regs_return_value(regs) == 0)
      WRITE_ONCE(write_succeeded, true);
    else
      WRITE_ONCE(armed, false);
  }
  return 0;
}

static int notrace mba_hibernate_return(struct kretprobe_instance *instance,
                                        struct pt_regs *regs)
{
  (void)instance;
  (void)regs;
  WRITE_ONCE(armed, false);
  return 0;
}

static struct kretprobe write_return_probe = {
  .kp.symbol_name = "swsusp_write",
  .handler = mba_write_return,
  .maxactive = 1,
};

static struct kretprobe hibernate_return_probe = {
  .kp.symbol_name = "hibernate",
  .handler = mba_hibernate_return,
  .maxactive = 1,
};

static int mba_set_arm_vector(const char *value, const struct kernel_param *parameter)
{
  u8 expected[MARKER_SIZE] = { 'M', 'B', 'P', 'W' };
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
  if (length != 64 || (value[length] != '\0' && value[length + 1] != '\0'))
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
  WRITE_ONCE(write_succeeded, false);
  WRITE_ONCE(last_efi_status, EFI_SUCCESS);
  WRITE_ONCE(arm_consumed, true);
  smp_wmb();
  WRITE_ONCE(armed, true);
  return 0;
}

static int mba_get_arm_vector(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", READ_ONCE(armed));
}

static const struct kernel_param_ops arm_vector_ops = {
  .set = mba_set_arm_vector,
  .get = mba_get_arm_vector,
};
module_param_cb(arm_vector, &arm_vector_ops, NULL, 0600);
MODULE_PARM_DESC(arm_vector, "Arm one exact prewritten 64-character vector; never on insertion");

static int __init mba_postwrite_init(void)
{
  unsigned int index;
  int error;

  if (READ_ONCE(armed))
    return -EPERM;
  error = register_kretprobe(&hibernate_return_probe);
  if (error)
    return error;
  error = register_kretprobe(&write_return_probe);
  if (error)
    goto unregister_hibernate_return;
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
  pr_info("mba-hibernate-postwrite: loaded disarmed\n");
  return 0;

unregister_previous:
  while (index--) {
    unregister_ftrace_function(&hooks[index].ops);
    ftrace_free_filter(&hooks[index].ops);
  }
  unregister_kretprobe(&write_return_probe);
unregister_hibernate_return:
  unregister_kretprobe(&hibernate_return_probe);
  return error;
}

static void __exit mba_postwrite_exit(void)
{
  unsigned int index;

  WRITE_ONCE(armed, false);
  WRITE_ONCE(registered, false);
  for (index = ARRAY_SIZE(hooks); index > 0; index--) {
    unregister_ftrace_function(&hooks[index - 1].ops);
    ftrace_free_filter(&hooks[index - 1].ops);
  }
  unregister_kretprobe(&write_return_probe);
  unregister_kretprobe(&hibernate_return_probe);
  pr_info("mba-hibernate-postwrite: unloaded\n");
}

module_init(mba_postwrite_init);
module_exit(mba_postwrite_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("One-use EFI stages at hibernation image and power-off boundaries");
#ifdef MBA_POSTWRITE_SOURCE_MARKER_V3
MODULE_INFO(mba_postwrite_variable, "v3");
#elif defined(MBA_POSTWRITE_SOURCE_MARKER_V2)
MODULE_INFO(mba_postwrite_variable, "v2");
#endif
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("EFIVAR");
