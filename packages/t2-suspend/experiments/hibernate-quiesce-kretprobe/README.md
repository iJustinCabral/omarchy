# Running-kernel device-quiesce probe

This external diagnostic module attaches a return probe to the production kernel's `dpm_suspend_start()`. While its root-only `armed` parameter is set, a successful `PMSG_QUIESCE` call is changed to `-ECANCELED` after every device's main quiesce callback has completed. The stock `hibernation_restore()` consequently skips `resume_target_kernel()` and performs its own `dpm_resume_end(PMSG_RECOVER)` and console recovery.

Loading the module leaves it disarmed and does not initiate a power-management transition. The eventual hardware runner must verify the exact running kernel and module hash, set `armed=1` only immediately before one guarded `test_resume` invocation, clear it immediately after return, and unload the module. Never leave the module armed for an ordinary hibernation request.

This approach runs on the already booted production kernel and avoids the two quiesce diagnostic UKIs that failed to mount the physical encrypted root. It does not make hibernation usable and must not be run until its source, compiled imports, probe target, load/disarm behavior and supervising recovery path have all been validated.

`run-quiesce-kretprobe --validate-only` performs those deployment checks, attaches and detaches the disarmed probe, and does not initiate a PM transition. With no argument, the runner creates an atomic hardware-attempt guard, arms a five-minute recovery reboot, enables the probe immediately before the single `test_resume` call, and reboots after evidence capture to clear the deliberately aborted test image's in-memory swap allocations.
