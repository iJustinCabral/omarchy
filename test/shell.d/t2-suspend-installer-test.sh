#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
python3 "$ROOT/test/shell.d/t2-suspend-installer-unit.py"
python3 "$ROOT/packages/t2-suspend/tests/test-preparation.py"
python3 "$ROOT/packages/t2-suspend/tests/test-wifi-hibernate-isolation.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-uki.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-source-uki.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-modules.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-bluetooth.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-boot.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-boot-verifier.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-runner.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-candidate-s4.py"
python3 "$ROOT/packages/t2-suspend/tests/test-pre-write-ftrace.py" "$ROOT/packages/t2-suspend/experiments/hibernate-pre-write-ftrace/mba_hibernate_pre_write_ftrace.c"
python3 "$ROOT/packages/t2-suspend/tests/test-pre-write-runner.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-efi-pre-write-boundary.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-readback-ftrace.py" "$ROOT/packages/t2-suspend/experiments/hibernate-readback-ftrace/mba_hibernate_readback_abort.c" "" "" "" "$ROOT/packages/t2-suspend/experiments/hibernate-readback-ftrace/vm-readback-init.c" "$ROOT/packages/t2-suspend/experiments/hibernate-readback-ftrace/run-vm-readback"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-live-readback.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-readback-cleanup.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-efi-postwrite-marker.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-efi-postwrite-backend.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-efi-restore-marker.py"
python3 "$ROOT/packages/t2-suspend/tests/test-restore-marker-initcpio-hook.py"
python3 "$ROOT/packages/t2-suspend/tests/test-terminal-restore-witness-cleanup.py"
python3 "$ROOT/packages/t2-suspend/tests/test-uki-pair-audit.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-kernel-repack.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-uki-pair-stage.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-uki-pair-source-verifier.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-uki-pair-test-resume.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-efi-stage-marker.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-rtc-stage-marker.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernate-rtc-boot-recovery.py"
python3 "$ROOT/packages/t2-suspend/tests/test-hibernation-uki-pair-s4.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pre-cpu-return.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pre-cpu-uki.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pre-syscore-integration.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pre-arch-integration.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pci-pre-arch-runtime.py"
python3 "$ROOT/packages/t2-suspend/tests/test-cold-pci-pre-arch-tooling.py"
pass "T2 suspend source and installer transactions"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT
mkdir -p "$test_tmp/bin"
export TEST_CALLS="$test_tmp/calls" OMARCHY_PATH="$ROOT" OMARCHY_INSTALL="$ROOT/install"
cat > "$test_tmp/bin/python3" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "$TEST_CALLS"
if [[ ${2:-} == supported ]]; then exit "${TEST_SUPPORTED:-0}"; fi
exit "${TEST_INSTALL_STATUS:-0}"
MOCK
for command in omarchy-pkg-add omarchy-setup-t2-bluetooth sudo; do
  cat > "$test_tmp/bin/$command" <<'MOCK'
#!/bin/bash
printf '%s %s\n' "${0##*/}" "$*" >> "$TEST_CALLS"
exit "${TEST_INSTALL_STATUS:-0}"
MOCK
 done
cat > "$test_tmp/bin/omarchy-setup-t2-suspend" <<'MOCK'
#!/bin/bash
printf 'setup\n' >> "$TEST_CALLS"
exit "${TEST_INSTALL_STATUS:-0}"
MOCK
chmod +x "$test_tmp/bin/"*
export PATH="$test_tmp/bin:$PATH"
leaf="$ROOT/install/hardware/apple/fix-t2-suspend.sh"
bash -euo pipefail "$leaf"
grep -q 'manage.py install$' "$TEST_CALLS" || fail "fresh setup installs drivers"
: > "$TEST_CALLS"
TEST_SUPPORTED=1 bash -euo pipefail "$leaf"
! grep -q 'omarchy-pkg-add\|manage.py install' "$TEST_CALLS" || fail "unsupported setup mutated system"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$leaf"; then fail "setup failure must propagate"; fi
: > "$TEST_CALLS"
"$ROOT/bin/omarchy-setup-t2-suspend" --verify
grep -q 'manage.py verify$' "$TEST_CALLS" || fail "verification routes correctly"
"$ROOT/bin/omarchy-setup-t2-suspend" --rollback
grep -q 'manage.py rollback$' "$TEST_CALLS" || fail "rollback routes correctly"
bash -euo pipefail "$ROOT/migrations/1789256882.sh"
grep -qx setup "$TEST_CALLS" || fail "migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789256882.sh"; then fail "migration failure must remain pending"; fi
: > "$TEST_CALLS"
bash -euo pipefail "$ROOT/migrations/1789872502.sh"
grep -qx setup "$TEST_CALLS" || fail "driver upgrade migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789872502.sh"; then fail "driver upgrade failure must remain pending"; fi
: > "$TEST_CALLS"
bash -euo pipefail "$ROOT/migrations/1789905053.sh"
grep -qx setup "$TEST_CALLS" || fail "BCE driver upgrade migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789905053.sh"; then fail "BCE driver upgrade failure must remain pending"; fi
: > "$TEST_CALLS"
bash -euo pipefail "$ROOT/migrations/1789909734.sh"
grep -qx setup "$TEST_CALLS" || fail "Wi-Fi hibernation upgrade migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789909734.sh"; then fail "Wi-Fi hibernation upgrade failure must remain pending"; fi
: >"$TEST_CALLS"
bash -euo pipefail "$ROOT/migrations/1789910828.sh"
grep -qx setup "$TEST_CALLS" || fail "unsafe restore removal migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789910828.sh"; then fail "unsafe restore removal failure must remain pending"; fi
: >"$TEST_CALLS"
bash -euo pipefail "$ROOT/migrations/1789941538.sh"
grep -qx setup "$TEST_CALLS" || fail "audio hibernation upgrade migration invokes setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789941538.sh"; then fail "audio hibernation upgrade failure must remain pending"; fi
pass "T2 suspend setup, CLI and migration routing; failure propagation"

# The initcpio hook must abort before image publication on a missing replacement.
mkdir -p "$test_tmp/root/usr/lib/firmware/brcm"
for suffix in .bin -SPPR-m.txt -SPPR-u.txt .clm_blob .txcap_blob; do
  echo fixture > "$test_tmp/root/usr/lib/firmware/brcm/brcmfmac4377b3-pcie.apple,formosa$suffix"
done
if bash -c 'source "$1"; _optmoduleroot=$2; KERNELVERSION=7.2.4-test-t2; add_file() { return 0; }; modinfo() { echo MODULE_LOOKUP >&2; return 1; }; build; echo UNSAFE_CONTINUATION' bash "$ROOT/packages/t2-suspend/installer/initcpio-install" "$test_tmp/root" > "$test_tmp/hook-output" 2>&1; then
  fail "missing replacement must abort mkinitcpio"
fi
! grep -q UNSAFE_CONTINUATION "$test_tmp/hook-output" || fail "hook continued after failure"
grep -q MODULE_LOOKUP "$test_tmp/hook-output" || fail "test did not reach module verification"
pass "boot-image guard stops generation before publishing incomplete images"
