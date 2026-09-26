#!/usr/bin/python3
"""Actual module and pinned kernel caller bodies with mocked PM effects only."""
from pathlib import Path
import hashlib
import re
import subprocess
import sys
import tempfile

project = Path(__file__).resolve().parents[3]
experiment = project / "packages/t2-suspend/experiments/hibernate-cold-pre-syscore"
source = (experiment / "mba_hibernate_cold_pre_syscore.c").read_text()
pre_cpu_source = (experiment.parent / "hibernate-cold-pre-cpu/mba_hibernate_cold_pre_cpu.c").read_text()
assert "FTRACE_OPS_FL_PERMANENT" in pre_cpu_source
assert 'MODULE_INFO(mba_cold_permanent, "v1")' in pre_cpu_source
kernel_path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("/home/jjc/.local/state/codex-mba-autonomous/kernel-readback-input/linux-7.2.6/kernel/power/hibernate.c")
if len(sys.argv) > 2:
  raise SystemExit("Usage: test-cold-pre-syscore.py [pinned-kernel/power/hibernate.c]")
kernel_bytes = kernel_path.read_bytes()
if hashlib.sha256(kernel_bytes).hexdigest() != "989a5fef5d7843518d31815c88bf1a1f35a51a176f6fb8fe1d3e6e0f1dbc9bf3":
  raise SystemExit("Refusing changed kernel caller source")
kernel = kernel_bytes.decode()
kernel_root = kernel_path.parents[2]
ftrace_bytes = (kernel_root / "kernel/trace/ftrace.c").read_bytes()
ftrace_header_bytes = (kernel_root / "include/linux/ftrace.h").read_bytes()
if hashlib.sha256(ftrace_bytes).hexdigest() != "b465ec022f67f3367a758bcc915dafed843c22e04e098a1dba3648aea07f85e3":
  raise SystemExit("Refusing changed kernel ftrace source")
if hashlib.sha256(ftrace_header_bytes).hexdigest() != "fbe362770824c729f496b8fe22c68d68d07bd5afb2eb0d2561198c3f9d910927":
  raise SystemExit("Refusing changed kernel ftrace flag definitions")
ftrace = ftrace_bytes.decode()
assert '#define TARGET_FUNCTION "syscore_suspend"' in source
assert 'MODULE_INFO(mba_cold_boundary, "pre-syscore-v1")' in source
assert 'MODULE_INFO(mba_cold_permanent, "v1")' in source
assert 'module_param_cb(arm_prefix, &arm_prefix_ops, NULL, 0600)' in source
assert "efivar" not in source and "kretprobe" not in source and "pr_" not in source
assert "FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY" in source
assert "FTRACE_OPS_FL_PERMANENT" in source

def extract(text, name):
  match = re.search(r"(?:static )?(?:int|void|bool)(?: notrace| __init| __exit)?\s+" + name + r"\([^;]+?\)\n\{", text)
  assert match, name
  index, depth = match.end(), 1
  while depth:
    depth += (text[index] == "{") - (text[index] == "}")
    index += 1
  return text[match.start():index] + "\n"

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define notrace
#define __init
#define __exit
#define READ_ONCE(x) ((__typeof__(x))mock_read(&(x),(x)))
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_wmb() ((void)0)
#define TARGET_FUNCTION "syscore_suspend"
#define pr_err(...) ((void)0)
#define pr_notice(...) ((void)0)
#define BUG_ON(x) assert(!(x))
#define PMSG_QUIESCE 2
#define PMSG_RECOVER 3
#define HIBERNATION_TEST_RESUME 9
#define SYSTEM_RUNNING 1
#define SYSTEM_SUSPEND 2
static int hibernation_mode;
static bool hibernate_quiesce_probe;
struct kernel_param {int unused;};
struct ftrace_ops {int unused;};
struct ftrace_regs {unsigned long ip;};
static struct ftrace_ops pre_syscore_ops;
static bool registered,armed,arm_consumed;
static unsigned int interceptions;
static char vector_prefix[25];
static bool observed_irqs_disabled, observed_boundary_valid;
static unsigned int observed_online_cpus;
static bool race_cmpxchg, race_unarmed;
static bool irq_off;
static unsigned int online_cpus=4;
static int filter_error, register_error;
static unsigned int filters, registrations, frees, unregistrations;
static unsigned long mock_read(const void *address,unsigned long value) {
  if(address==&armed && race_unarmed) {
    race_unarmed=false;armed=false;arm_consumed=true;interceptions=1;
    return false;
  }
  return value;
}
static unsigned int cmpxchg(unsigned int *p,unsigned int old,unsigned int next) {
  if(race_cmpxchg) {race_cmpxchg=false;*p=1;armed=false;return 1;}
  unsigned int prior=*p; if(prior==old) *p=next; return prior;
}
static bool irqs_disabled(void) {return irq_off;}
static unsigned int num_online_cpus(void) {return online_cpus;}
static void ftrace_regs_set_instruction_pointer(struct ftrace_regs *r,unsigned long ip) {r->ip=ip;}
static int ftrace_set_filter(struct ftrace_ops *ops,unsigned char *name,unsigned int size,int reset) {
  assert(ops==&pre_syscore_ops && !strcmp((char *)name,TARGET_FUNCTION));
  assert(size==strlen(TARGET_FUNCTION) && !reset); filters++; return filter_error;
}
static int register_ftrace_function(struct ftrace_ops *ops) {
  assert(ops==&pre_syscore_ops); registrations++; return register_error;
}
static void ftrace_free_filter(struct ftrace_ops *ops) {assert(ops==&pre_syscore_ops);frees++;}
static void unregister_ftrace_function(struct ftrace_ops *ops) {
  assert(ops==&pre_syscore_ops && !registered && !armed);unregistrations++;
}
'''
harness += ''.join(extract(source, name) for name in ("mba_pre_syscore_abort", "mba_pre_syscore_hook", "mba_set_arm_prefix", "mba_get_arm_prefix", "mba_pre_syscore_init", "mba_pre_syscore_exit"))
harness += r'''
enum event {PREPARE,CONSOLE_OFF,MAIN_OFF,NOIRQ_OFF,PLATFORM_PRE,IDLE_PAUSE,CPU_OFF,
  IRQ_OFF,SYSCORE_ENTRY,SYSCORE_BODY,SAVE_PROCESSOR,HIGHMEM,ARCH_RESTORE,FREE_IMAGE,
  RESTORE_PROCESSOR,WATCHDOG,SYSCORE_RESUME,IRQ_ON,CPU_ON,PLATFORM_CLEANUP,
  NOIRQ_ON,MAIN_ON,CONSOLE_ON,CONSOLE_RESTORE};
static enum event events[64];
static unsigned int count;
static int system_state=SYSTEM_RUNNING;
static int main_error,noirq_error,platform_error,cpu_error;
static bool bad_irq,bad_cpu,idle_paused,hotplug_disabled,main_off,noirq_off;
static unsigned int syscore_bodies,syscore_resumes,architecture_calls,cpu_reenables;
static void event(enum event item) {assert(count<64);events[count++]=item;}
static void pm_prepare_console(void) {event(PREPARE);}
static void console_suspend_all(void) {event(CONSOLE_OFF);}
static int dpm_suspend_start(int state) {
  assert(state==PMSG_QUIESCE);event(MAIN_OFF);main_off=true;return main_error;
}
static int dpm_suspend_end(int state) {
  assert(state==PMSG_QUIESCE);event(NOIRQ_OFF);noirq_off=!noirq_error;return noirq_error;
}
static int platform_pre_restore(bool mode) {(void)mode;event(PLATFORM_PRE);return platform_error;}
static void cpuidle_pause(void) {event(IDLE_PAUSE);idle_paused=true;}
static int hibernate_resume_nonboot_cpu_disable(void) {
  event(CPU_OFF);hotplug_disabled=true;online_cpus=cpu_error ? 2 : bad_cpu ? 2 : 1;return cpu_error;
}
static void local_irq_disable(void) {event(IRQ_OFF);irq_off=!bad_irq;}
static int syscore_suspend(void) {
  struct ftrace_regs regs={0};event(SYSCORE_ENTRY);
  mba_pre_syscore_hook(0,0,&pre_syscore_ops,&regs);
  if(regs.ip) {
    assert(regs.ip==(unsigned long)mba_pre_syscore_abort);
    return ((int (*)(void))regs.ip)();
  }
  event(SYSCORE_BODY);syscore_bodies++;return 0;
}
static void save_processor_state(void) {event(SAVE_PROCESSOR);}
static int restore_highmem(void) {event(HIGHMEM);return 0;}
static int swsusp_arch_resume(void) {event(ARCH_RESTORE);architecture_calls++;return -EIO;}
static void swsusp_free(void) {event(FREE_IMAGE);}
static void restore_processor_state(void) {event(RESTORE_PROCESSOR);}
static void touch_softlockup_watchdog(void) {event(WATCHDOG);}
static void syscore_resume(void) {event(SYSCORE_RESUME);syscore_resumes++;}
static void local_irq_enable(void) {assert(system_state==SYSTEM_RUNNING);event(IRQ_ON);irq_off=false;}
static void pm_sleep_enable_secondary_cpus(void) {
  assert(!irq_off && hotplug_disabled);event(CPU_ON);cpu_reenables++;
  hotplug_disabled=false;online_cpus=4;idle_paused=false;
}
static void platform_restore_cleanup(bool mode) {(void)mode;event(PLATFORM_CLEANUP);}
static void dpm_resume_start(int state) {
  assert(state==PMSG_RECOVER && noirq_off && !irq_off);
  event(NOIRQ_ON);noirq_off=false;
}
static void dpm_resume_end(int state) {assert(state==PMSG_RECOVER && main_off);event(MAIN_ON);main_off=false;}
static void console_resume_all(void) {event(CONSOLE_ON);}
static void pm_restore_console(void) {event(CONSOLE_RESTORE);}
'''
harness += extract(kernel, "resume_target_kernel") + extract(kernel, "hibernation_restore")
harness += r'''
static void reset(void) {
  registered=armed=arm_consumed=false;interceptions=0;vector_prefix[0]='\0';
  observed_irqs_disabled=observed_boundary_valid=false;observed_online_cpus=0;
  race_cmpxchg=race_unarmed=false;
  filter_error=register_error=0;filters=registrations=frees=unregistrations=0;
  irq_off=false;online_cpus=4;count=0;system_state=SYSTEM_RUNNING;
  main_error=noirq_error=platform_error=cpu_error=0;
  bad_irq=bad_cpu=idle_paused=hotplug_disabled=main_off=noirq_off=false;
  syscore_bodies=syscore_resumes=architecture_calls=cpu_reenables=0;
}
static void arm(void) {
  assert(mba_pre_syscore_init()==0 && registered && !armed);
  assert(mba_set_arm_prefix("0123456789abcdef01234567\n",NULL)==0);
}
static void assert_events(const enum event *expected,unsigned int length) {
  assert(count==length);
  for(unsigned int i=0;i<length;i++) assert(events[i]==expected[i]);
}
int main(void) {
  struct ftrace_regs regs={0};char getter[8];
  reset();mba_pre_syscore_hook(0,0,NULL,&regs);assert(!regs.ip);
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==-EPERM);
  armed=true;assert(mba_pre_syscore_init()==-EPERM);armed=false;
  arm_consumed=true;assert(mba_pre_syscore_init()==-EPERM);arm_consumed=false;
  interceptions=1;assert(mba_pre_syscore_init()==-EPERM);interceptions=0;
  strcpy(vector_prefix,"0123456789abcdef01234567");assert(mba_pre_syscore_init()==-EPERM);vector_prefix[0]=0;
  observed_irqs_disabled=true;assert(mba_pre_syscore_init()==-EPERM);observed_irqs_disabled=false;
  observed_online_cpus=1;assert(mba_pre_syscore_init()==-EPERM);observed_online_cpus=0;
  observed_boundary_valid=true;assert(mba_pre_syscore_init()==-EPERM);observed_boundary_valid=false;
  assert(!filters && !registrations && !frees);
  filter_error=-EINVAL;assert(mba_pre_syscore_init()==-EINVAL && !registered);
  assert(filters==1 && !registrations && !frees);
  filter_error=0;register_error=-EBUSY;assert(mba_pre_syscore_init()==-EBUSY && !registered);
  assert(filters==2 && registrations==1 && frees==1);
  register_error=0;assert(mba_pre_syscore_init()==0 && registered && !armed);
  assert(mba_set_arm_prefix("ABCDEF012345678901234567",NULL)==-EINVAL);
  assert(mba_set_arm_prefix("short",NULL)==-EINVAL);
  assert(mba_set_arm_prefix("0123456789abcdef01234567\nx",NULL)==-EINVAL);
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==0);
  assert(mba_get_arm_prefix(getter,NULL)==2 && !strcmp(getter,"1\n"));
  irq_off=true;online_cpus=1;mba_pre_syscore_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_pre_syscore_abort && mba_pre_syscore_abort()==-ECANCELED);
  assert(interceptions==1 && !armed && arm_consumed && observed_boundary_valid);
  assert(observed_irqs_disabled && observed_online_cpus==1);
  assert(mba_get_arm_prefix(getter,NULL)==2 && !strcmp(getter,"0\n"));
  assert(mba_set_arm_prefix("0123456789abcdef01234567",NULL)==-EPERM);
  irq_off=false;online_cpus=4;regs.ip=0;mba_pre_syscore_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_pre_syscore_abort && interceptions==1);
  assert(observed_boundary_valid && observed_irqs_disabled && observed_online_cpus==1);
  mba_pre_syscore_exit();assert(!registered && !armed && unregistrations==1 && frees==2);

  // A concurrent winner must not let the losing caller execute syscore.
  reset();arm();observed_online_cpus=77;race_cmpxchg=true;regs.ip=0;
  mba_pre_syscore_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_pre_syscore_abort && interceptions==1);
  assert(observed_online_cpus==77 && !observed_boundary_valid);
  mba_pre_syscore_exit();
  // The other caller may disarm between our initial arm read and latch check.
  reset();arm();observed_online_cpus=88;race_unarmed=true;regs.ip=0;
  mba_pre_syscore_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_pre_syscore_abort && interceptions==1);
  assert(observed_online_cpus==88 && !observed_boundary_valid);
  mba_pre_syscore_exit();
  // Even the consumed-before-armed window aborts without inventing proof.
  reset();arm_consumed=true;regs.ip=0;
  mba_pre_syscore_hook(0,0,NULL,&regs);
  assert(regs.ip==(unsigned long)mba_pre_syscore_abort && !interceptions);

  const enum event recovered[]={PREPARE,CONSOLE_OFF,MAIN_OFF,NOIRQ_OFF,PLATFORM_PRE,
    IDLE_PAUSE,CPU_OFF,IRQ_OFF,SYSCORE_ENTRY,IRQ_ON,CPU_ON,PLATFORM_CLEANUP,
    NOIRQ_ON,MAIN_ON,CONSOLE_ON,CONSOLE_RESTORE};
  for(int fault=0;fault<3;fault++) {
    reset();arm();bad_irq=fault==1;bad_cpu=fault==2;
    assert(hibernation_restore(1)==-ECANCELED);
    assert_events(recovered,sizeof(recovered)/sizeof(*recovered));
    assert(interceptions==1 && arm_consumed && !armed);
    assert(observed_boundary_valid==(fault==0));
    assert(observed_irqs_disabled==(fault!=1));
    assert(observed_online_cpus==(fault==2 ? 2U : 1U));
    assert(!syscore_bodies && !syscore_resumes && !architecture_calls);
    assert(cpu_reenables==1 && !hotplug_disabled && !idle_paused);
    assert(online_cpus==4 && !irq_off && system_state==SYSTEM_RUNNING && !main_off && !noirq_off);
    mba_pre_syscore_exit();
  }
  reset();arm();cpu_error=-EBUSY;
  assert(hibernation_restore(1)==-EBUSY && !interceptions);
  const enum event cpu_failure[]={PREPARE,CONSOLE_OFF,MAIN_OFF,NOIRQ_OFF,PLATFORM_PRE,
    IDLE_PAUSE,CPU_OFF,CPU_ON,PLATFORM_CLEANUP,NOIRQ_ON,MAIN_ON,CONSOLE_ON,CONSOLE_RESTORE};
  assert_events(cpu_failure,sizeof(cpu_failure)/sizeof(*cpu_failure));
  assert(!syscore_bodies && !architecture_calls && !observed_boundary_valid);
  assert(cpu_reenables==1 && !hotplug_disabled && !idle_paused);mba_pre_syscore_exit();
  reset();arm();platform_error=-EIO;
  assert(hibernation_restore(1)==-EIO && !interceptions);
  assert(!cpu_reenables && !syscore_bodies && !architecture_calls && !noirq_off);mba_pre_syscore_exit();
  reset();arm();noirq_error=-EIO;
  assert(hibernation_restore(1)==-EIO && !interceptions);
  assert(!cpu_reenables && !syscore_bodies && !architecture_calls);mba_pre_syscore_exit();
  reset();arm();main_error=-EIO;
  assert(hibernation_restore(1)==-EIO && !interceptions);
  assert(!cpu_reenables && !syscore_bodies && !architecture_calls);mba_pre_syscore_exit();
  // Disarmed control proves mocks do not simply suppress the tested suffix.
  reset();assert(mba_pre_syscore_init()==0);
  assert(hibernation_restore(1)==-EIO && !interceptions);
  assert(syscore_bodies==1 && syscore_resumes==1 && architecture_calls==1 && cpu_reenables==1);
  mba_pre_syscore_exit();
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="cold-pre-syscore-control-") as tmp:
  root = Path(tmp)
  (root / "test.c").write_text(harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)

flags = re.search(r"enum \{\n\s*FTRACE_OPS_FL_ENABLED.*?\n\};", ftrace_header_bytes.decode(), re.S).group(0)
ops = re.search(r"static struct ftrace_ops pre_syscore_ops = \{.*?\n\};", source, re.S).group(0)
trace_harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define __init
#define __exit
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define TARGET_FUNCTION "syscore_suspend"
#define CONFIG_DYNAMIC_FTRACE_WITH_REGS 1
#define BIT(x) (1UL << (x))
#define WARN_ON(x) (!!(x))
#define unlikely(x) (x)
#define guard(kind) mock_guard
#define rcu_dereference_protected(pointer,condition) (pointer)
#define lockdep_is_held(lock) 1
typedef long long loff_t;
struct ctl_table {int unused;};
struct ftrace_regs {int unused;};
'''
trace_harness += flags + "\n"
trace_harness += r'''
struct ftrace_ops {
  unsigned long flags;
  void (*func)(unsigned long,unsigned long,struct ftrace_ops *,struct ftrace_regs *);
  void (*saved_func)(unsigned long,unsigned long,struct ftrace_ops *,struct ftrace_regs *);
  struct ftrace_ops *next;
};
static struct ftrace_ops ftrace_list_end;
static struct ftrace_ops *ftrace_ops_list=&ftrace_list_end;
static int ftrace_enabled=1,last_ftrace_enabled=1,ftrace_lock;
static bool ftrace_disabled;
static unsigned int startups,shutdowns,updates,filters,frees;
static bool registered,armed,arm_consumed;
static unsigned int interceptions,observed_online_cpus;
static char vector_prefix[25];
static bool observed_irqs_disabled,observed_boundary_valid;
static void mba_pre_syscore_hook(unsigned long ip,unsigned long parent,struct ftrace_ops *ops,struct ftrace_regs *regs) {
  (void)ip;(void)parent;(void)ops;(void)regs;
}
static void ftrace_pid_func(unsigned long ip,unsigned long parent,struct ftrace_ops *ops,struct ftrace_regs *regs) {
  (void)ip;(void)parent;(void)ops;(void)regs;
}
static void ftrace_stub(void) {}
static void (*ftrace_trace_function)(void);
static void mock_guard(int *lock) {assert(lock==&ftrace_lock);}
static bool is_kernel_core_data(unsigned long address) {(void)address;return false;}
static void add_ftrace_ops(struct ftrace_ops **list,struct ftrace_ops *ops) {ops->next=*list;*list=ops;}
static bool ftrace_pids_enabled(struct ftrace_ops *ops) {(void)ops;return false;}
static void ftrace_update_trampoline(struct ftrace_ops *ops) {(void)ops;}
static void update_ftrace_function(void) {updates++;}
static void ftrace_startup_sysctl(void) {startups++;}
static void ftrace_shutdown_sysctl(void) {shutdowns++;}
static int proc_dointvec(const struct ctl_table *table,int write,void *buffer,size_t *length,loff_t *position) {
  (void)table;(void)length;(void)position;if(write) ftrace_enabled=*(int *)buffer;return 0;
}
#define do_for_each_ftrace_op(op,list) for((op)=(list);(op)!=&ftrace_list_end;(op)=(op)->next)
#define while_for_each_ftrace_op(op)
'''
trace_harness += extract(ftrace, "__register_ftrace_function")
trace_harness += extract(ftrace, "is_permanent_ops_registered")
trace_harness += extract(ftrace, "ftrace_enable_sysctl")
trace_harness += ops + "\n"
trace_harness += r'''
static int ftrace_set_filter(struct ftrace_ops *ops,unsigned char *target,unsigned int length,int reset) {
  assert(ops==&pre_syscore_ops && !strcmp((char *)target,TARGET_FUNCTION));
  assert(length==strlen(TARGET_FUNCTION) && !reset);filters++;return 0;
}
static int register_ftrace_function(struct ftrace_ops *ops) {return __register_ftrace_function(ops);}
static void ftrace_free_filter(struct ftrace_ops *ops) {assert(ops==&pre_syscore_ops);frees++;}
static void unregister_ftrace_function(struct ftrace_ops *ops) {
  assert(!registered && !armed && ftrace_ops_list==ops);ftrace_ops_list=ops->next;
}
'''
trace_harness += extract(source, "mba_pre_syscore_init") + extract(source, "mba_pre_syscore_exit")
trace_harness += r'''
int main(void) {
  struct ctl_table table={0};size_t length=sizeof(int);loff_t position=0;int value=0;
  assert(pre_syscore_ops.flags & FTRACE_OPS_FL_PERMANENT);
  ftrace_enabled=last_ftrace_enabled=0;
  assert(mba_pre_syscore_init()==-EBUSY && !registered && !armed);
  assert(filters==1 && frees==1 && ftrace_ops_list==&ftrace_list_end);
  ftrace_enabled=last_ftrace_enabled=1;
  assert(mba_pre_syscore_init()==0 && registered);
  assert(is_permanent_ops_registered());
  assert(ftrace_enable_sysctl(&table,1,&value,&length,&position)==-EBUSY);
  assert(ftrace_enabled==1 && last_ftrace_enabled==1 && !shutdowns);
  assert(ftrace_enable_sysctl(&table,0,&value,&length,&position)==0);
  assert(ftrace_enabled==1 && !shutdowns);
  ftrace_disabled=true;
  assert(ftrace_enable_sysctl(&table,1,&value,&length,&position)==-ENODEV);
  assert(ftrace_enabled==1);ftrace_disabled=false;
  mba_pre_syscore_exit();assert(!is_permanent_ops_registered());
  assert(ftrace_enable_sysctl(&table,1,&value,&length,&position)==0);
  assert(!ftrace_enabled && !last_ftrace_enabled && shutdowns==1 && ftrace_trace_function==ftrace_stub);
  // Actual registration of an ordinary op while disabled demonstrates the old bypass.
  struct ftrace_ops ordinary={.flags=FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,.func=mba_pre_syscore_hook};
  assert(__register_ftrace_function(&ordinary)==0);
  assert(!is_permanent_ops_registered() && !ftrace_enabled);
  value=1;
  assert(ftrace_enable_sysctl(&table,1,&value,&length,&position)==0 && startups==1);
  assert(ftrace_enabled==1 && last_ftrace_enabled==1);
  assert(updates>=1);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="cold-pre-syscore-permanent-") as tmp:
  root = Path(tmp)
  (root / "test.c").write_text(trace_harness)
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)
# Reuse actual registration/sysctl guards with the other profile's real flags.
# Only local initializer symbol names are adapted to the same harness interface.
pre_cpu_ops = re.search(r"static struct ftrace_ops cold_ops = \{.*?\n\};", pre_cpu_source, re.S).group(0)
pre_cpu_ops = pre_cpu_ops.replace("cold_ops", "pre_syscore_ops").replace("mba_cold_hook", "mba_pre_syscore_hook")
with tempfile.TemporaryDirectory(prefix="cold-pre-cpu-permanent-") as tmp:
  root = Path(tmp)
  (root / "test.c").write_text(trace_harness.replace(ops, pre_cpu_ops))
  subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(root / "test.c"), "-o", str(root / "test")], check=True)
  subprocess.run([str(root / "test")], check=True)
print("PASS: actual pre-syscore module and kernel caller preserve IRQ/CPU/device recovery and abort on invalid observations")
print("PASS: actual pinned ftrace registration/sysctl guards refuse disabled registration and later hook disabling")
print("PASS: both cold profiles' actual permanent flags enforce the same pinned registration/sysctl guards")
