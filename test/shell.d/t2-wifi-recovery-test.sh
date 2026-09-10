#!/bin/bash

set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

require_command python3
python3 "$ROOT/test/shell.d/t2-wifi-recovery-unit.py"
pass "Wi-Fi recovery scopes hardware, ignores unrelated failures, and serializes with sleep"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT
mkdir -p "$test_tmp/bin"
export TEST_CALLS="$test_tmp/calls"
export OMARCHY_PATH="$ROOT" OMARCHY_INSTALL="$ROOT/install"
export OMARCHY_T2_WIFI_UNIT="$test_tmp/unit.service"
export OMARCHY_T2_WIFI_LEGACY_UNIT="$test_tmp/legacy.service"
export OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL=0

cat > "$test_tmp/bin/omarchy-t2-wifi-recovery" <<'SH'
#!/bin/bash
[[ ${TEST_SUPPORTED:-1} == "1" ]]
SH
cat > "$test_tmp/bin/systemctl" <<'SH'
#!/bin/bash
printf '%s\n' "$*" >> "$TEST_CALLS"
SH
cat > "$test_tmp/bin/sudo" <<'SH'
#!/bin/bash
exec "$@"
SH
cat > "$test_tmp/bin/omarchy-setup-t2-wifi-recovery" <<'SH'
#!/bin/bash
printf 'setup\n' >> "$TEST_CALLS"
SH
chmod +x "$test_tmp/bin/"*
export PATH="$test_tmp/bin:$PATH"
leaf="$ROOT/install/hardware/apple/fix-wifi-recovery.sh"

TEST_SUPPORTED=0 bash -euo pipefail "$leaf"
[[ ! -e $OMARCHY_T2_WIFI_UNIT ]] || fail "unsupported hardware is untouched"
pass "unsupported hardware does not install recovery"

bash -euo pipefail "$leaf"
cp "$OMARCHY_T2_WIFI_UNIT" "$test_tmp/first-unit"
bash -euo pipefail "$leaf"
cmp -s "$OMARCHY_T2_WIFI_UNIT" "$test_tmp/first-unit" || fail "idempotent unit contents"
! grep -q -- '--now' "$TEST_CALLS" || fail "fresh installation must not start the service"
pass "fresh installation is idempotent and enables only for the next boot"

OMARCHY_T2_WIFI_START_NOW=1 bash -euo pipefail "$leaf"
grep -Fxq 'enable --now omarchy-t2-wifi-recovery.service' "$TEST_CALLS" || fail "explicit setup starts recovery"
pass "explicit setup activates recovery"

printf 'standalone\n' > "$OMARCHY_T2_WIFI_LEGACY_UNIT"
if bash -euo pipefail "$leaf" >/dev/null 2>&1; then fail "standalone service conflict must stop setup"; fi
[[ $(cat "$OMARCHY_T2_WIFI_LEGACY_UNIT") == "standalone" ]] || fail "standalone service preserved"
rm "$OMARCHY_T2_WIFI_LEGACY_UNIT"
pass "standalone recovery is preserved and cannot run alongside Omarchy recovery"

printf 'administrator unit\n' > "$OMARCHY_T2_WIFI_UNIT"
if bash -euo pipefail "$leaf" >/dev/null 2>&1; then fail "custom unit must be preserved"; fi
[[ $(cat "$OMARCHY_T2_WIFI_UNIT") == "administrator unit" ]] || fail "custom unit changed"
cp "$test_tmp/first-unit" "$OMARCHY_T2_WIFI_UNIT"
pass "administrator unit edits are preserved"

OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL=1 bash -euo pipefail "$leaf"
grep -Fxq 'Environment=OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL=1' "${OMARCHY_T2_WIFI_UNIT}.d/10-model-opt-in.conf" || fail "explicit model opt-in persists"
printf 'custom override\n' > "${OMARCHY_T2_WIFI_UNIT}.d/10-model-opt-in.conf"
if OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL=1 bash -euo pipefail "$leaf" >/dev/null 2>&1; then fail "custom model override must be preserved"; fi
pass "model opt-in is explicit and preserves custom overrides"

: > "$TEST_CALLS"
TEST_SUPPORTED=0 bash -euo pipefail "$ROOT/migrations/1788636425.sh"
[[ ! -s $TEST_CALLS ]] || fail "migration skips unsupported hardware"
bash -euo pipefail "$ROOT/migrations/1788636425.sh"
grep -Fxq setup "$TEST_CALLS" || fail "migration invokes the shared setup path"
pass "migration shares setup and skips unsupported hardware"

: > "$TEST_CALLS"
"$ROOT/bin/omarchy-setup-t2-wifi-recovery" --disable
grep -Fxq 'disable --now omarchy-t2-wifi-recovery.service' "$TEST_CALLS" || fail "disable stops only the recovery service"
pass "disable leaves radio and kernel policy alone"

# A recovery holding the common lock must prevent the real sleep helper from
# touching the mocked module state. No system power transition is involved.
cat > "$test_tmp/bin/omarchy-hw-t2-bcm4377" <<'SH'
#!/bin/bash
exit 0
SH
chmod +x "$test_tmp/bin/omarchy-hw-t2-bcm4377"
(
  exec 8>"$test_tmp/wifi.lock"
  flock -n 8
  if OMARCHY_T2_BCM4377_LOCK="$test_tmp/wifi.lock" "$ROOT/bin/omarchy-t2-bcm4377-sleep" pre >/dev/null; then
    fail "sleep preparation must refuse while recovery owns the lock"
  fi
)
pass "sleep preparation refuses an overlapping firmware recovery"
