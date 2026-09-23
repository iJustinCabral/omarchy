#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/base-test.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
export TEST_CALLS="$work/calls" OMARCHY_T2_BCM4377_UNIT="$work/old.service"
export PATH="$work/bin:$PATH"
cat > "$work/bin/sudo" <<'SH'
#!/bin/bash
"$@"
SH
cat > "$work/bin/systemctl" <<'SH'
#!/bin/bash
if [[ $1 == "show" ]]; then
  echo "${TEST_ACTIVE:-inactive}"
else
  echo "$*" >> "$TEST_CALLS"
  exit "${TEST_DISABLE_RC:-0}"
fi
SH
chmod +x "$work/bin/"*
migration="$ROOT/migrations/1789075037.sh"
bash -euo pipefail "$migration"
[[ ! -e $TEST_CALLS ]]
cat > "$OMARCHY_T2_BCM4377_UNIT" <<'UNIT'
[Unit]
Description=Unload BCM4377 Wi-Fi around sleep (T2 Mac)
Documentation=https://github.com/omacom/omarchy/discussions/4695
DefaultDependencies=no
Before=sleep.target
StopWhenUnneeded=yes

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=30
TimeoutStopSec=30
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/bin/omarchy-t2-bcm4377-sleep pre
# ExecStopPost also runs after a failed or timed-out ExecStart, so partial
# preparation is rolled back before systemd completes the failed start job.
ExecStopPost=/usr/bin/omarchy-t2-bcm4377-sleep post

[Install]
RequiredBy=sleep.target
UNIT
bash -euo pipefail "$migration"
grep -Fxq 'disable omarchy-t2-bcm4377-sleep.service' "$TEST_CALLS"
bash -euo pipefail "$migration"
[[ -f $OMARCHY_T2_BCM4377_UNIT ]]
if TEST_ACTIVE=active bash -euo pipefail "$migration"; then
  fail "active sleep transaction must defer retirement"
fi
if TEST_DISABLE_RC=1 bash -euo pipefail "$migration"; then
  fail "disable failure must leave migration pending"
fi
: > "$TEST_CALLS"
echo '# administrator customization' >> "$OMARCHY_T2_BCM4377_UNIT"
bash -euo pipefail "$migration"
[[ ! -s $TEST_CALLS ]]
pass "sleep retirement handles absent, owned, active and custom units without radio changes"
