// SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <linux/ftrace.h>
#include <linux/hex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>

/* Match the existing guarded EFI variable contract; never create or erase it. */
#define MARKER_SIZE 17
#define MARKER_ATTRS (EFI_VARIABLE_NON_VOLATILE | \
                      EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                      EFI_VARIABLE_RUNTIME_ACCESS)

static efi_char16_t marker_name[] = L"OmarchyT2HibernateStage";
static efi_guid_t marker_guid =
  EFI_GUID(0x96234839, 0x90c9, 0x4cd5, 0x97, 0xb2, 0x7b, 0xa6, 0x90, 0xf0, 0xaf, 0x02);
static efi_char16_t probe_name[] = L"OmarchyT2KernelEfiProbe";
static efi_guid_t probe_guid =
  EFI_GUID(0xd963eecc, 0x8654, 0x47d4, 0xbc, 0x1c, 0x45, 0x6d, 0x7b, 0x77, 0x6a, 0x86);
static efi_char16_t entry_name[] = L"OmarchyT2FtraceEntryProbe";
static efi_guid_t entry_guid =
  EFI_GUID(0x9f946df0, 0x1b9c, 0x4af5, 0x97, 0xe8, 0xbc, 0x32, 0x2a, 0x72, 0x82, 0x41);
static u8 marker[MARKER_SIZE];
static u8 entry_marker[MARKER_SIZE];
static bool armed;
static bool arm_consumed;
static bool probe_consumed;
static bool entry_armed;
static bool entry_consumed;
static bool registered;
static unsigned int stage;
static unsigned int entry_stage;
static unsigned long last_efi_status;
static unsigned long probe_efi_status;
static unsigned long entry_efi_status;
module_param(stage, uint, 0400);
module_param(entry_stage, uint, 0400);
module_param(last_efi_status, ulong, 0400);
module_param(probe_consumed, bool, 0400);
module_param(probe_efi_status, ulong, 0400);
module_param(entry_armed, bool, 0400);
module_param(entry_consumed, bool, 0400);
module_param(entry_efi_status, ulong, 0400);
MODULE_PARM_DESC(stage, "Last source-side hibernation boundary entered in this boot");
MODULE_PARM_DESC(entry_stage, "One-use hibernate-entry ftrace probe stage");
MODULE_PARM_DESC(last_efi_status, "Last nonblocking EFI marker write status; zero means success");
MODULE_PARM_DESC(probe_consumed, "One-use stock-boot EFI write probe has been consumed");
MODULE_PARM_DESC(probe_efi_status, "Last one-use stock-boot EFI write probe status");
MODULE_PARM_DESC(entry_armed, "One-use hibernate-entry ftrace probe is armed");
MODULE_PARM_DESC(entry_consumed, "One-use hibernate-entry ftrace probe has been consumed");
MODULE_PARM_DESC(entry_efi_status, "Last hibernate-entry ftrace probe EFI status");

struct mba_stage_hook {
  const char *function;
  unsigned int value;
  struct ftrace_ops ops;
};

static efi_status_t notrace mba_write_variable(efi_char16_t *name,
                                               efi_guid_t *guid, u8 *value)
{
  efi_status_t status;

  if (efivar_trylock())
    return EFI_NOT_READY;
  status = efivar_set_variable_locked(name, guid, MARKER_ATTRS,
                                       MARKER_SIZE, value, true);
  efivar_unlock();
  return status;
}

static efi_status_t notrace mba_write_stage(unsigned int next)
{
  u8 value[MARKER_SIZE];

  memcpy(value, marker, sizeof(value));
  value[16] = next;
  return mba_write_variable(marker_name, &marker_guid, value);
}

static efi_status_t notrace mba_write_entry_stage(void)
{
  u8 value[MARKER_SIZE];

  memcpy(value, entry_marker, sizeof(value));
  value[16] = 1;
  return mba_write_variable(entry_name, &entry_guid, value);
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
  if (hook->value == 1 && READ_ONCE(entry_armed) &&
      cmpxchg(&entry_stage, 0, 1) == 0) {
    status = mba_write_entry_stage();
    WRITE_ONCE(entry_efi_status, status);
    WRITE_ONCE(entry_armed, false);
    return;
  }
  if (!READ_ONCE(armed) || cmpxchg(&stage, previous, hook->value) != previous)
    return;

  status = mba_write_stage(hook->value);
  WRITE_ONCE(last_efi_status, status);
  if (status != EFI_SUCCESS)
    WRITE_ONCE(armed, false);
}

static struct mba_stage_hook hooks[] = {
  { .function = "hibernate", .value = 1 },
  { .function = "swsusp_write", .value = 2 },
};

static int mba_set_arm_vector(const char *value, const struct kernel_param *parameter)
{
  u8 expected[MARKER_SIZE] = { 'M', 'B', 'A', '9' };
  u8 actual[MARKER_SIZE];
  unsigned long size = sizeof(actual);
  efi_status_t status;
  size_t length;
  u32 attrs = 0;
  int error;
  size_t index;

  (void)parameter;
  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) ||
      READ_ONCE(probe_consumed) || READ_ONCE(entry_consumed) ||
      READ_ONCE(armed))
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
MODULE_PARM_DESC(arm_vector, "Arm once with a guarded 64-character lowercase pair vector after EFI stage 0 is prewritten");

static int mba_set_probe_nonce(const char *value, const struct kernel_param *parameter)
{
  u8 expected[MARKER_SIZE] = { 'M', 'B', 'K', 'P' };
  u8 actual[MARKER_SIZE];
  unsigned long size = sizeof(actual);
  efi_status_t status;
  size_t length;
  u32 attrs = 0;
  int error;
  size_t index;

  (void)parameter;
  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) ||
      READ_ONCE(probe_consumed) || READ_ONCE(entry_consumed) ||
      READ_ONCE(armed))
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
  status = efivar_get_variable(probe_name, &probe_guid, &attrs, &size, actual);
  efivar_unlock();
  if (status != EFI_SUCCESS)
    return efi_status_to_err(status);
  if (size != sizeof(actual) || attrs != MARKER_ATTRS ||
      memcmp(actual, expected, sizeof(actual)))
    return -EINVAL;

  WRITE_ONCE(probe_consumed, true);
  expected[16] = 1;
  status = mba_write_variable(probe_name, &probe_guid, expected);
  WRITE_ONCE(probe_efi_status, status);
  if (status != EFI_SUCCESS)
    return efi_status_to_err(status);
  return 0;
}

static int mba_get_probe_nonce(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", READ_ONCE(probe_consumed));
}

static const struct kernel_param_ops probe_nonce_ops = {
  .set = mba_set_probe_nonce,
  .get = mba_get_probe_nonce,
};
module_param_cb(probe_nonce, &probe_nonce_ops, NULL, 0600);
MODULE_PARM_DESC(probe_nonce, "One-use stock-boot EFI write probe, mutually exclusive with hibernation arming");

static int mba_set_entry_nonce(const char *value, const struct kernel_param *parameter)
{
  u8 expected[MARKER_SIZE] = { 'M', 'B', 'F', 'E' };
  u8 actual[MARKER_SIZE];
  unsigned long size = sizeof(actual);
  efi_status_t status;
  size_t length;
  u32 attrs = 0;
  int error;
  size_t index;

  (void)parameter;
  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) ||
      READ_ONCE(probe_consumed) || READ_ONCE(entry_consumed) ||
      READ_ONCE(armed))
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
  status = efivar_get_variable(entry_name, &entry_guid, &attrs, &size, actual);
  efivar_unlock();
  if (status != EFI_SUCCESS)
    return efi_status_to_err(status);
  if (size != sizeof(actual) || attrs != MARKER_ATTRS ||
      memcmp(actual, expected, sizeof(actual)))
    return -EINVAL;

  memcpy(entry_marker, expected, sizeof(entry_marker));
  WRITE_ONCE(entry_efi_status, EFI_SUCCESS);
  WRITE_ONCE(entry_consumed, true);
  smp_wmb();
  WRITE_ONCE(entry_armed, true);
  return 0;
}

static int mba_get_entry_nonce(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", READ_ONCE(entry_armed));
}

static const struct kernel_param_ops entry_nonce_ops = {
  .set = mba_set_entry_nonce,
  .get = mba_get_entry_nonce,
};
module_param_cb(entry_nonce, &entry_nonce_ops, NULL, 0600);
MODULE_PARM_DESC(entry_nonce, "One-use hibernate-entry ftrace probe, mutually exclusive with S4 arming");

static int __init mba_marker_init(void)
{
  unsigned int index;
  int error;

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
  pr_info("mba-hibernate-efi-ftrace: loaded disarmed\n");
  return 0;

unregister_previous:
  while (index--) {
    unregister_ftrace_function(&hooks[index].ops);
    ftrace_free_filter(&hooks[index].ops);
  }
  return error;
}

static void __exit mba_marker_exit(void)
{
  unsigned int index;

  WRITE_ONCE(armed, false);
  WRITE_ONCE(entry_armed, false);
  for (index = ARRAY_SIZE(hooks); index > 0; index--) {
    unregister_ftrace_function(&hooks[index - 1].ops);
    ftrace_free_filter(&hooks[index - 1].ops);
  }
}

module_init(mba_marker_init);
module_exit(mba_marker_exit);
MODULE_IMPORT_NS("EFIVAR");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Offline-only experimental EFI hibernation stage recorder for stock T2 kernels");
