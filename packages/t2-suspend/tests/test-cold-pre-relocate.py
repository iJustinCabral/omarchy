#!/usr/bin/python3
"""Reuse cold-abort contracts; execute actual pinned architecture/mapping bodies.

The pre-arch runner supplies comprehensive one-use and balanced-recovery fixtures.
Checked substitutions replace its extracted module bodies with this module, and
its architecture mock with pinned C bodies. Nothing patches the kernel or loads
a module. Page tables, allocations, mapping helpers and all PM effects are mocks.
"""
from pathlib import Path
import hashlib
import re
import runpy
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent / "experiments/hibernate-cold-pre-relocate"
DEFAULT_KERNEL = Path("/home/jjc/.local/state/codex-mba-autonomous/kernel-readback-input/linux-7.2.6/kernel/power/hibernate.c")
if len(sys.argv) > 2:
  raise SystemExit("Usage: test-cold-pre-relocate.py [pinned-kernel/power/hibernate.c]")
kernel_path = Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_KERNEL
kernel_root = kernel_path.parents[2]
arch_path = kernel_root / "arch/x86/power/hibernate_64.c"
arch_bytes = arch_path.read_bytes()
if hashlib.sha256(arch_bytes).hexdigest() != "615083b225388dc517a7c4d25f85e051b920d27bb992b33778a730c7b7fe5afd":
  raise SystemExit("Refusing changed architecture mapping source")
common_arch = kernel_root / "arch/x86/power/hibernate.c"
if hashlib.sha256(common_arch.read_bytes()).hexdigest() != "550ce004ac844ccc1027b7e1a92d1fd805189405f573fe0973f052238fa0df1b":
  raise SystemExit("Refusing changed relocation source")
source = (EXPERIMENT / "mba_hibernate_cold_pre_relocate.c").read_text()
assert '#define TARGET_FUNCTION "relocate_restore_code"' in source
assert 'MODULE_INFO(mba_cold_boundary, "pre-relocate-v1")' in source
assert 'MODULE_INFO(mba_cold_permanent, "v1")' in source
assert 'module_param_cb(arm_prefix, &arm_prefix_ops, NULL, 0600)' in source
assert "efivar" not in source and "kretprobe" not in source and "pr_" not in source

# Run the pinned shared fixture first; this also checks caller/FPU/config/ftrace
# hashes. Its generated C fixtures are reused, not copied into a second test.
baseline = runpy.run_path(str(HERE / "test-cold-pre-arch.py"), run_name="cold_pre_arch_fixture")
extract = baseline["extract"]

def replace_once(text, old, new):
  assert text.count(old) == 1, f"Fixture changed: {old[:80]!r}"
  return text.replace(old, new, 1)

def use_module(fixture, names):
  for name in names:
    old_body = extract(baseline["source"], name)
    new_name = name.replace("pre_arch", "pre_relocate")
    fixture = replace_once(fixture, old_body, extract(source, new_name))
  # Rename fixture state/calls only after replacing actual extracted bodies.
  return fixture.replace("pre_arch", "pre_relocate").replace('"swsusp_arch_resume"', '"relocate_restore_code"')

names = ("mba_pre_arch_abort", "mba_pre_arch_hook", "mba_set_arm_prefix", "mba_get_arm_prefix", "mba_pre_arch_init", "mba_pre_arch_exit")
harness = use_module(baseline["harness"], names)
architecture_mock = re.search(r"static int swsusp_arch_resume\(void\) \{.*?\n\}\n", baseline["harness"], re.S).group(0)
architecture_mock = architecture_mock.replace("pre_arch", "pre_relocate")
mapping_fixture = r'''
#define asmlinkage
#define GFP_ATOMIC 0x820
#define PAGE_SHIFT 12
#define PMD_MASK (~((1UL << 21)-1))
#define _KERNPG_TABLE 0x63UL
#define __PAGE_KERNEL_LARGE_EXEC 0x1e3UL
#define __PAGE_OFFSET 0UL
#define __pgprot(x) (x)
#define pgprot_val(x) (x)
#define __pmd(x) (x)
#define __pud(x) (x)
#define __p4d(x) (x)
#define __pgd(x) (x)
#define __pa(x) ((unsigned long)(x))
#define pmd_index(x) (((x) >> 21) & 511UL)
#define pud_index(x) (((x) >> 30) & 511UL)
#define p4d_index(x) (((x) >> 39) & 511UL)
#define pgd_index(x) (((x) >> (five_level ? 48 : 39)) & 511UL)
typedef unsigned long pmd_t,pud_t,p4d_t,pgd_t,pgprot_t;
struct x86_mapping_info {
  void *(*alloc_pgt_page)(void *);
  unsigned long page_flag,offset;
};
static unsigned long __default_kernel_pte_mask=~0UL;
static unsigned long jump_address_phys=0x400000UL,restore_jump_address=0x600000UL,temp_pgt;
static struct {unsigned long start,end;} pfn_mapped[]={{1,2},{4,6}};
static int nr_pfn_mapped=2;
static bool five_level;
static unsigned int allocations,fail_allocation,mapping_calls,fail_mapping,image_calls;
static int relocation_error;
static unsigned long pages[32][512];
static bool pgtable_l5_enabled(void) {return five_level;}
static unsigned long get_safe_page(int flags) {
  assert(flags==GFP_ATOMIC);allocations++;
  if(allocations==fail_allocation) return 0;
  assert(allocations<=32);memset(pages[allocations-1],0,sizeof(pages[0]));
  return (unsigned long)pages[allocations-1];
}
static void set_pmd(pmd_t *entry,pmd_t value) {*entry=value;}
static void set_pud(pud_t *entry,pud_t value) {*entry=value;}
static void set_p4d(p4d_t *entry,p4d_t value) {*entry=value;}
static void set_pgd(pgd_t *entry,pgd_t value) {*entry=value;}
static int kernel_ident_mapping_init(struct x86_mapping_info *info,pgd_t *pgd,
                                     unsigned long start,unsigned long end) {
  assert(pgd && start<end && info->page_flag==__PAGE_KERNEL_LARGE_EXEC && !info->offset);
  mapping_calls++;
  if(mapping_calls==fail_mapping) return -EINVAL;
  return info->alloc_pgt_page(NULL) ? 0 : -ENOMEM;
}
static int relocate_restore_code(void) {
  struct ftrace_regs regs={0};
  mba_pre_relocate_hook(0,0,&pre_relocate_ops,&regs);
  if(regs.ip) {
    assert(regs.ip==(unsigned long)mba_pre_relocate_abort);
    return ((int (*)(void))regs.ip)();
  }
  event(ARCH_RESTORE);architecture_calls++;return relocation_error;
}
static void restore_image(void) {image_calls++;}
'''
arch = arch_bytes.decode()
for name in ("set_up_temporary_text_mapping", "set_up_temporary_mappings"):
  mapping_fixture += extract(arch, name)
# The shared extractor covers int/void functions, but not this pointer-return
# helper. Keep its exact source body (including the actual GFP_ATOMIC call).
helper = re.search(r"static void \*alloc_pgt_page\(void \*context\)\n\{.*?\n\}", arch, re.S).group(0)
# Put this helper before mapping setup, and silence only its unused parameter.
mapping_fixture = replace_once(mapping_fixture, extract(arch, "set_up_temporary_mappings"),
                              helper + "\n" + extract(arch, "set_up_temporary_mappings"))
arch_body = extract(arch.replace("asmlinkage int swsusp_arch_resume", "int swsusp_arch_resume"), "swsusp_arch_resume")
mapping_fixture += "static " + arch_body
mapping_fixture += '''
static int observed_arch_resume(void) {
  event(ARCH_ENTRY);return swsusp_arch_resume();
}
'''
harness = replace_once(harness, architecture_mock, mapping_fixture)
# Only the actual caller's call is routed through the event recorder.
harness = replace_once(harness, "error = swsusp_arch_resume();", "error = observed_arch_resume();")
harness = replace_once(harness, "irq_off=false;online_cpus=4;count=0;system_state=SYSTEM_RUNNING;",
                      "irq_off=false;online_cpus=4;count=0;system_state=SYSTEM_RUNNING;\n"
                      "  five_level=false;allocations=fail_allocation=mapping_calls=fail_mapping=image_calls=0;\n"
                      "  relocation_error=0;temp_pgt=0;")
# Disarmed caller control must encounter a real nonzero relocation return;
# real swsusp_arch_resume returns zero if our assembly mock returns, which the
# actual caller correctly BUG_ONs. No mock may invent a recoverable assembly exit.
harness = replace_once(harness, "reset();assert(mba_pre_relocate_init()==0);\n  assert(hibernation_restore(1)==-EIO",
                      "reset();assert(mba_pre_relocate_init()==0);relocation_error=-EIO;\n  assert(hibernation_restore(1)==-EIO")
extra_cases = r'''
  // Every temporary text-map allocation and direct-map allocation failure must
  // return through the actual caller without hitting relocation or its hook.
  for(int level=0;level<2;level++) {
    unsigned int maximum=level ? 6 : 5;
    for(unsigned int failure=1;failure<=maximum;failure++) {
      reset();arm();five_level=level;fail_allocation=failure;
      assert(hibernation_restore(1)==-ENOMEM);
      assert(!interceptions && armed && arm_consumed && !observed_boundary_valid);
      assert(!architecture_calls && !image_calls && !temp_pgt);
      assert(processor_saves==1 && processor_restores==1 && syscore_resumes==1);
      assert(image_frees==1 && watchdogs==1 && cpu_reenables==1);
      assert_events(recovered,sizeof(recovered)/sizeof(*recovered));
      assert(!irq_off && online_cpus==4 && !idle_paused && !hotplug_disabled);
      mba_pre_relocate_exit();
    }
    for(unsigned int failure=1;failure<=2;failure++) {
      reset();arm();five_level=level;fail_mapping=failure;
      assert(hibernation_restore(1)==-EINVAL);
      assert(!interceptions && armed && arm_consumed && !observed_boundary_valid);
      assert(!architecture_calls && !image_calls && !temp_pgt);
      assert_events(recovered,sizeof(recovered)/sizeof(*recovered));
      mba_pre_relocate_exit();
    }
    reset();arm();five_level=level;
    assert(hibernation_restore(1)==-ECANCELED);
    assert(interceptions==1 && observed_boundary_valid && !armed && temp_pgt);
    assert(mapping_calls==2 && allocations==maximum && !architecture_calls && !image_calls);
    assert_events(recovered,sizeof(recovered)/sizeof(*recovered));
    mba_pre_relocate_exit();
  }
  // Direct architecture-body control reaches the assembly mock only when
  // disarmed and successful; never run this zero return through the PM caller.
  reset();assert(mba_pre_relocate_init()==0);
  assert(swsusp_arch_resume()==0 && architecture_calls==1 && image_calls==1);
  assert(!interceptions && mapping_calls==2 && temp_pgt);mba_pre_relocate_exit();
'''
harness = replace_once(harness, "  mba_pre_relocate_exit();\n  return 0;\n}\n",
                       "  mba_pre_relocate_exit();\n" + extra_cases + "  return 0;\n}\n")

# Reuse the actual pinned registration/permanent/sysctl bodies with this
# module's actual flags, init and exit rather than a flags-only assertion.
trace_harness = baseline["trace_harness"]
for name in ("mba_pre_arch_init", "mba_pre_arch_exit"):
  trace_harness = replace_once(trace_harness, extract(baseline["source"], name),
                              extract(source, name.replace("pre_arch", "pre_relocate")))
old_ops = re.search(r"static struct ftrace_ops pre_arch_ops = \{.*?\n\};", baseline["source"], re.S).group(0)
new_ops = re.search(r"static struct ftrace_ops pre_relocate_ops = \{.*?\n\};", source, re.S).group(0)
trace_harness = replace_once(trace_harness, old_ops, new_ops)
trace_harness = trace_harness.replace("pre_arch", "pre_relocate").replace('"swsusp_arch_resume"', '"relocate_restore_code"')
for label, fixture in (("mapping-control", harness), ("permanent", trace_harness)):
  with tempfile.TemporaryDirectory(prefix="cold-pre-relocate-" + label + "-") as tmp:
    root = Path(tmp)
    (root / "test.c").write_text(fixture)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                    str(root / "test.c"), "-o", str(root / "test")], check=True)
    subprocess.run([str(root / "test")], check=True)
print("PASS: actual pre-relocate module, pinned architecture/mapping bodies and balanced caller recovery")
print("PASS: four/five-level text/direct mapping failures never reach relocation or invent observations")
print("PASS: actual permanent ftrace guards; no module load, kernel build, image, EFI or PM operation")
