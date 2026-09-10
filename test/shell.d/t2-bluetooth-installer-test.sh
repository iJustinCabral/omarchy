#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
require_command python3
python3 "$ROOT/test/shell.d/t2-bluetooth-installer-unit.py"
pass "Bluetooth installer transactions, image checks, and model scope"

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
cat > "$test_tmp/bin/sudo" <<'MOCK'
#!/bin/bash
printf 'sudo %s\n' "$*" >> "$TEST_CALLS"
exit "${TEST_INSTALL_STATUS:-0}"
MOCK
cat > "$test_tmp/bin/omarchy-setup-t2-bluetooth" <<'MOCK'
#!/bin/bash
printf 'setup\n' >> "$TEST_CALLS"
exit "${TEST_INSTALL_STATUS:-0}"
MOCK
chmod +x "$test_tmp/bin/"*
export PATH="$test_tmp/bin:$PATH"
leaf="$ROOT/install/hardware/apple/fix-t2-bluetooth.sh"
bash -euo pipefail "$leaf"
grep -q 'install --fresh$' "$TEST_CALLS" || fail "fresh install calls manager"
: > "$TEST_CALLS"
TEST_SUPPORTED=1 bash -euo pipefail "$leaf"
! grep -q 'install --fresh$' "$TEST_CALLS" || fail "unsupported install touched configuration"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$leaf"; then fail "install failure must propagate"; fi
: > "$TEST_CALLS"
"$ROOT/bin/omarchy-setup-t2-bluetooth" --verify
grep -q 'manage.py verify$' "$TEST_CALLS" || fail "verify route"
"$ROOT/bin/omarchy-setup-t2-bluetooth" --rollback
grep -q 'manage.py rollback$' "$TEST_CALLS" || fail "rollback route"
bash -euo pipefail "$ROOT/migrations/1789070892.sh"
grep -qx 'setup' "$TEST_CALLS" || fail "migration uses setup"
if TEST_INSTALL_STATUS=1 bash -euo pipefail "$ROOT/migrations/1789070892.sh"; then fail "migration failure must remain pending"; fi
pass "fresh install, setup, and migration share manager and propagate failures"
