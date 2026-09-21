# Post-restore-code-relocation probe

This external module attaches a return probe to `relocate_restore_code()`. While armed, it preserves a real relocation failure and changes only successful relocation to `-ECANCELED`. By that return, `swsusp_arch_resume()` has constructed its temporary page tables, allocated and copied the restore code, and made the relocated page executable, but has not entered `restore_image()` or replaced memory. The stock nonzero-return path releases the image, restores processor and syscore state, re-enables IRQs and CPUs, and performs platform and device recovery.

The module loads disarmed, refuses insertion with `armed=1`, and does not initiate a PM transition. The runner requires all earlier guarded boundary results, validates the production boot and exact artifact, uses a separate no-repeat guard and reboots after evidence capture.
