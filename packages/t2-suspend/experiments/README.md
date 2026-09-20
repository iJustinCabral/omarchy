# Hibernation diagnostic candidates

These patches are not part of `manifest.json`, normal source preparation, DKMS installation, or any automatic migration. They are diagnostic candidates, not qualified fixes. Do not install them over managed modules or bypass the boot-image source-version guard.

## BCE restore-entry abort

`0001-bce-abort-image-restore-probe.patch` applies to the prepared 1.4 BCE core source. Its read-only load-time parameter `hibernate_restore_abort` defaults to false. With it enabled, only the image `.restore` callback returns `-ECANCELED` before invoking `t2bce_resume`; ordinary suspend/resume and freeze/thaw retain their original callbacks. The diagnostic intentionally does not restore BCE, so internal input and audio may fail until reboot. It must not be presented as usable hibernation.

The purpose is to distinguish a reset before the BCE restore callback from a reset requiring its firmware handshake. A surviving kernel journal containing the explicit abort marker would show that low-level image restoration reached this boundary. Absence of a marker after another reset would not prove the callback was never reached. No repeated image test is authorized by compiling this patch alone: deployment must preserve the verified normal boot image, provenance, the source-version guard, and an unattended recovery path.

The exact wrapper is exercised by `python3 packages/t2-suspend/tests/test-bce-restore-probe.py <patched-t2bce_main.c>`. It verifies that default behavior forwards the resume result, opt-in abortion never invokes the firmware resume path, and the ordinary PM callback mapping is unchanged. The experimental module compiled with `W=1` against `7.2.6-arch2-Watanare-T2-2-t2`, yielding source version `6C39F3A7AEBE0C064C19344`. The build warned that pahole 1.31 differed from the kernel's 1.32, but completed. No hardware validation or installation has occurred.
