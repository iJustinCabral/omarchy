# Pre-architecture-resume probe

This external module redirects `swsusp_arch_resume()` at entry only while armed and returns `-ECANCELED` without entering atomic memory restoration. Reaching that function proves that processor-state save completed after device, CPU and syscore quiesce. Its nonzero return makes the stock caller release the image, restore processor state, resume syscore callbacks, re-enable IRQs and CPUs, and perform platform and device recovery.

The module loads disarmed, refuses insertion with `armed=1`, and does not initiate a PM transition. The runner requires all earlier guarded boundary results, validates the production boot and exact artifact, uses a separate no-repeat guard and reboots after evidence capture.
