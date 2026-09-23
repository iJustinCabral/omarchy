# Pre-image-write boundary probe

This experimental external module redirects `swsusp_write()` at entry only while root explicitly arms it, returning `-ECANCELED` before it allocates swap pages or writes an image. Reaching the replacement means the stock `hibernate()` path has completed `hibernation_snapshot()` and returned to the source kernel. The stock error path then calls `swsusp_free()`, resumes tasks and returns a deliberate error instead of powering off. It does not test image writing, swap-header finalization or cold restore.

The module loads disarmed and refuses `armed=1` at insertion. A disarmed load/unload may validate the ftrace attachment without a PM transition. Do not run an armed test directly: a separate single-use runner must first bind the boot, module hash, selected candidate runtime stack, radios, swap-header baseline and recovery path, then preserve the guard before entering PM. A passed boundary does not justify repeating any earlier failed S4 vector.
