#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
python3 "$ROOT/test/shell.d/t2-suspend-installer-unit.py"
python3 "$ROOT/packages/t2-suspend/tests/test-preparation.py"
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
pass "T2 suspend setup, CLI and migration routing; failure propagation"

# The initcpio hook must abort before image publication on a missing replacement.
if bash -c 'source "$1"; KERNELVERSION=7.2.4-test-t2; modinfo() { return 1; }; build; echo UNSAFE_CONTINUATION' bash "$ROOT/packages/t2-suspend/installer/initcpio-install" > "$test_tmp/hook-output"; then
  fail "missing replacement must abort mkinitcpio"
fi
! grep -q UNSAFE_CONTINUATION "$test_tmp/hook-output" || fail "hook continued after failure"
pass "boot-image guard stops generation before publishing incomplete images"
