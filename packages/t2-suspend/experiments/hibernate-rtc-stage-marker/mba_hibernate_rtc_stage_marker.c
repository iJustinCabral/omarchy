// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/mc146818rtc.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pm-trace.h>
#include <linux/rtc.h>
#include <linux/timekeeping.h>

/* The PM trace writer hashes this packed line/file record into the RTC. */
struct mba_trace_data {
  u16 line;
  const char *file;
} __packed;

static const struct mba_trace_data trace_data = {
  .line = 1,
  .file = "mba-t2-hibernate-rtc-stage-v1",
};

struct mba_stage_hook {
  const char *function;
  unsigned int value;
  struct ftrace_ops ops;
};

static bool armed;
static bool arm_consumed;
static bool registered;
static bool rtc_repaired;
static unsigned int stage;
module_param(stage, uint, 0400);
MODULE_PARM_DESC(stage, "Last hibernation source stage observed by the hooks");

static void notrace mba_mark_stage(unsigned int next)
{
  unsigned int previous;

  if (!READ_ONCE(armed))
    return;

  previous = READ_ONCE(stage);
  if (next != previous + 1)
    return;

  if (cmpxchg(&stage, previous, next) == previous)
    generate_pm_trace(&trace_data, next);
}

static void notrace mba_stage_callback(unsigned long ip, unsigned long parent_ip,
                                       struct ftrace_ops *ops,
                                       struct ftrace_regs *fregs)
{
  struct mba_stage_hook *hook = container_of(ops, struct mba_stage_hook, ops);

  (void)ip;
  (void)parent_ip;
  (void)fregs;
  mba_mark_stage(hook->value);
}

static struct mba_stage_hook hooks[] = {
  { .function = "hibernate", .value = 1 },
  { .function = "swsusp_write", .value = 2 },
  { .function = "hibernation_platform_enter", .value = 3 },
  { .function = "acpi_hibernation_enter", .value = 4 },
};

static int mba_set_armed(const char *value, const struct kernel_param *parameter)
{
  bool enable;
  int error;

  (void)parameter;
  error = kstrtobool(value, &enable);
  if (error)
    return error;

  if (!enable) {
    WRITE_ONCE(armed, false);
    return 0;
  }

  if (!READ_ONCE(registered) || READ_ONCE(arm_consumed) || READ_ONCE(stage))
    return -EPERM;

  WRITE_ONCE(arm_consumed, true);
  generate_pm_trace(&trace_data, 0);
  WRITE_ONCE(armed, true);
  return 0;
}

static const struct kernel_param_ops armed_ops = {
  .set = mba_set_armed,
  .get = param_get_bool,
};
module_param_cb(armed, &armed_ops, &armed, 0600);
MODULE_PARM_DESC(armed, "One-shot RTC stage marking; cannot arm during module insertion");

static int mba_set_rtc_repaired(const char *value, const struct kernel_param *parameter)
{
  struct rtc_time rtc_time;
  time64_t rtc_seconds;
  time64_t system_seconds;
  bool confirmed;
  int error;

  (void)parameter;
  error = kstrtobool(value, &confirmed);
  if (error)
    return error;
  if (!confirmed || !READ_ONCE(registered) || READ_ONCE(armed) ||
      READ_ONCE(rtc_repaired) || !READ_ONCE(pm_trace_rtc_abused))
    return -EPERM;

  error = mc146818_get_time(&rtc_time, 1000);
  if (error)
    return error;
  error = rtc_valid_tm(&rtc_time);
  if (error)
    return error;

  rtc_seconds = rtc_tm_to_time64(&rtc_time);
  system_seconds = ktime_get_real_seconds();
  if (rtc_seconds < system_seconds - 120 || rtc_seconds > system_seconds + 120)
    return -ERANGE;

  WRITE_ONCE(pm_trace_rtc_abused, false);
  WRITE_ONCE(rtc_repaired, true);
  pr_info("mba-hibernate-rtc-stage: verified repaired RTC; normal RTC reads restored\n");
  return 0;
}

static const struct kernel_param_ops rtc_repaired_ops = {
  .set = mba_set_rtc_repaired,
  .get = param_get_bool,
};
module_param_cb(rtc_repaired, &rtc_repaired_ops, &rtc_repaired, 0600);
MODULE_PARM_DESC(rtc_repaired, "Clear PM-trace RTC guard only when raw RTC matches the current system clock");

static int __init mba_stage_init(void)
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
  pr_info("mba-hibernate-rtc-stage: loaded disarmed\n");
  return 0;

unregister_previous:
  while (index--) {
    unregister_ftrace_function(&hooks[index].ops);
    ftrace_free_filter(&hooks[index].ops);
  }
  return error;
}

static void __exit mba_stage_exit(void)
{
  unsigned int index;

  WRITE_ONCE(registered, false);
  WRITE_ONCE(armed, false);
  for (index = ARRAY_SIZE(hooks); index > 0; index--) {
    unregister_ftrace_function(&hooks[index - 1].ops);
    ftrace_free_filter(&hooks[index - 1].ops);
  }
  pr_info("mba-hibernate-rtc-stage: unloaded\n");
}

module_init(mba_stage_init);
module_exit(mba_stage_exit);

MODULE_AUTHOR("Omarchy T2 suspend experiment");
MODULE_DESCRIPTION("Opt-in RTC breadcrumbs for stock-kernel hibernation source stages");
MODULE_LICENSE("GPL");
