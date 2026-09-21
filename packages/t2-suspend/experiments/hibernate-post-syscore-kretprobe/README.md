# Post-syscore restore probe

This external module attaches a return probe to `syscore_suspend()`. While armed, it permits the first successful call from image creation, then explicitly runs `syscore_resume()` after the second successful call from image restoration before changing that return to `-ECANCELED`. The explicit resume is required because the caller's error path assumes that a failed `syscore_suspend()` already unwound its completed callbacks. The stock restore path then re-enables local IRQs and secondary CPUs, performs platform and device recovery, and aborts before processor-state save, high-memory restoration or `swsusp_arch_resume()`.

The module loads disarmed, refuses insertion with `armed=1`, and does not initiate a PM transition. The runner requires all three earlier guarded boundary results, validates the production boot and exact artifact, uses a separate no-repeat guard and reboots after evidence capture.
