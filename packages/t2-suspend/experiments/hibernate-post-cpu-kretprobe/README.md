# Post-CPU-disable restore probe

This external module attaches a return probe to `hibernate_resume_nonboot_cpu_disable()`. While armed, it changes only a successful return to `-ECANCELED`. The stock restore path consequently re-enables the CPUs it just disabled, performs platform and noirq/early device recovery, and aborts before local IRQ disable, syscore suspend, high-memory restoration or `swsusp_arch_resume()`.

The module loads disarmed, refuses insertion with `armed=1`, and does not initiate a PM transition. The runner requires both earlier guarded boundary results, validates the production boot and exact artifact, uses a separate no-repeat guard and reboots after evidence capture.
