"""Closed constants for the two supported cold-restore abort boundaries."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE / "hibernate-cold-common"
COMMON_DIRECTORY = "usr/lib/omarchy-t2-cold-common/"
PROFILES = {
  "cold_pre_cpu": {
    "version": "cold-pre-cpu-abort-v1", "target": "hibernate_resume_nonboot_cpu_disable",
    "module": "mba_hibernate_cold_pre_cpu", "boundary": None, "observations": None,
    "directory": "usr/lib/omarchy-t2-cold-pre-cpu/", "hook": "omarchy-t2-cold-pre-cpu",
    "source": HERE / "hibernate-cold-pre-cpu", "magic": b"MBCP", "returned": "OmarchyT2ColdPreCpuReturned",
  },
  "cold_pre_syscore": {
    "version": "cold-pre-syscore-abort-v1", "target": "syscore_suspend",
    "module": "mba_hibernate_cold_pre_syscore", "boundary": "pre-syscore-v1",
    "observations": {"observed_irqs_disabled": "Y", "observed_online_cpus": 1, "observed_boundary_valid": "Y"},
    "directory": "usr/lib/omarchy-t2-cold-pre-syscore/", "hook": "omarchy-t2-cold-pre-syscore",
    "source": HERE / "hibernate-cold-pre-syscore", "magic": b"MBSC", "returned": "OmarchyT2ColdPreSyscoreReturned",
  },
}


def select(provenance):
  keys = [key for key in PROFILES if key in provenance]
  if len(keys) > 1:
    raise ValueError("Cold abort protocols are mutually exclusive")
  return keys[0] if keys else None


def hooks(key):
  hook = PROFILES[key]["hook"]
  return (hook, hook + "-return", "resume")


def sources(key):
  profile = PROFILES[key]
  directory = profile["source"]
  result = {
    "cold-abort-protocols.py": HERE / "cold-abort-protocols.py",
    profile["module"] + ".c": directory / (profile["module"] + ".c"),
    "read-swap-header.c": HERE / "hibernate-cold-pre-cpu/read-swap-header.c",
    "common/functions": COMMON / "functions",
    "common/hooks/resume": COMMON / "hooks/resume",
    "common/install/resume": COMMON / "install/resume",
    "common/install/bundle": COMMON / "install/bundle",
    "functions": directory / "functions",
  }
  for hook in hooks(key)[:2]:
    result["hooks/" + hook] = directory / "hooks" / hook
    result["install/" + hook] = directory / "install" / hook
  return result
