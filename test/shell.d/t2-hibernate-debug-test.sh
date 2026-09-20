#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

command="$ROOT/bin/omarchy-debug-t2-hibernate"
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT

stub_bin="$test_tmp/bin"
power="$test_tmp/power"
dmi="$test_tmp/dmi"
calls="$test_tmp/calls"
bluetooth_state="$test_tmp/bluetooth-state"
brcmfmac_srcversion="$test_tmp/brcmfmac-srcversion"
wifi_driver="$test_tmp/wifi-driver"
wifi_device="$test_tmp/wifi-device"
mkdir -p "$wifi_driver" "$wifi_device"
printf '0x14e4\n' >"$wifi_device/vendor"
printf '0x4488\n' >"$wifi_device/device"
ln -s "$wifi_device" "$wifi_driver/0000:73:00.0"
mkdir -p "$stub_bin" "$power" "$dmi"
: >"$calls"
printf 'on\n' >"$bluetooth_state"
printf 'SAFE_TEST_MODULE\n' >"$brcmfmac_srcversion"
printf 'freeze mem disk\n' >"$power/state"
printf '[platform] shutdown reboot suspend test_resume\n' >"$power/disk"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
printf '0\n' >"$power/pm_trace"
: >"$power/pm_trace_dev_match"
printf '3298534883\n' >"$power/image_size"
printf '253:0\n' >"$power/resume"
printf '1923214\n' >"$power/resume_offset"
printf 'MacBookAir9,1\n' >"$dmi/product_name"
printf 'Mac-0CFF9C7C2B63DF8D\n' >"$dmi/board_name"
printf 'quiet resume=/dev/mapper/root resume_offset=1923214\n' >"$test_tmp/cmdline"

cat >"$stub_bin/omarchy-hw-t2" <<'SH'
#!/bin/bash
(( ${T2_HARDWARE:-1} == 1 ))
SH
cat >"$stub_bin/uname" <<'SH'
#!/bin/bash
echo test-t2-kernel
SH
cat >"$stub_bin/swapon" <<'SH'
#!/bin/bash
echo '/swap/swapfile 8G 0'
SH
cat >"$stub_bin/bluetoothctl" <<'SH'
#!/bin/bash
case "${1:-}" in
  show)
    case "$(<"$TEST_BLUETOOTH_STATE")" in
      on) echo 'Powered: yes' ;;
      off) echo 'Powered: no' ;;
      *) exit 1 ;;
    esac
    ;;
  power)
    if [[ $2 == "on" && ${TEST_BLUETOOTH_RESTORE_FAIL:-0} == 1 ]]; then
      exit 1
    fi
    if [[ $2 == "on" && -n ${TEST_BLUETOOTH_FAIL_ONCE:-} && ! -e $TEST_BLUETOOTH_FAIL_ONCE ]]; then
      touch "$TEST_BLUETOOTH_FAIL_ONCE"
      exit 1
    fi
    printf '%s\n' "$2" >"$TEST_BLUETOOTH_STATE"
    printf 'bluetoothctl power %s\n' "$2" >>"$TEST_CALLS"
    ;;
esac
SH
cat >"$stub_bin/sudo" <<'SH'
#!/bin/bash
printf 'sudo %s\n' "$*" >>"$TEST_CALLS"
if [[ ${1:-} == "-n" ]]; then
  shift
fi
if [[ ${1:-} == "-v" ]]; then
  exit 0
fi
exec "$@"
SH
cat >"$stub_bin/logger" <<'SH'
#!/bin/bash
printf 'logger %s\n' "$*" >>"$TEST_CALLS"
SH
cat >"$stub_bin/sync" <<'SH'
#!/bin/bash
printf 'sync\n' >>"$TEST_CALLS"
SH
cat >"$stub_bin/gum" <<'SH'
#!/bin/bash
exit "${TEST_CONFIRM_STATUS:-0}"
SH
cat >"$stub_bin/snapshot-create" <<'SH'
#!/bin/bash
printf 'snapshot-create %s\n' "$*" >>"$TEST_CALLS"
exit "${TEST_SNAPSHOT_STATUS:-0}"
SH
cat >"$stub_bin/tee" <<'SH'
#!/bin/bash
if [[ $1 == "$TEST_WIFI_DRIVER/unbind" ]]; then
  read -r device
  [[ ${TEST_WIFI_UNBIND_FAIL:-0} == 1 ]] && exit 1
  if [[ ${TEST_WIFI_UNBIND_NOOP:-0} != 1 ]]; then
    rm "$TEST_WIFI_DRIVER/$device"
  fi
  printf '%s\n' "$device"
elif [[ $1 == "$TEST_WIFI_DRIVER/bind" ]]; then
  read -r device
  [[ ${TEST_WIFI_BIND_FAIL:-0} == 1 ]] && exit 1
  ln -s "$TEST_WIFI_TARGET" "$TEST_WIFI_DRIVER/$device"
  printf '%s\n' "$device"
else
  exec /usr/bin/tee "$@"
fi
SH
chmod +x "$stub_bin"/*

export PATH="$stub_bin:$PATH"
export TEST_CALLS="$calls"
export TEST_BLUETOOTH_STATE="$bluetooth_state"
export TEST_WIFI_DRIVER="$wifi_driver" TEST_WIFI_TARGET="$wifi_device"
export OMARCHY_T2_HIBERNATE_BRCMFMAC_DRIVER="$wifi_driver"
export OMARCHY_T2_HIBERNATE_SYS_POWER="$power"
export OMARCHY_T2_HIBERNATE_DMI_ROOT="$dmi"
export OMARCHY_T2_HIBERNATE_CMDLINE="$test_tmp/cmdline"
export OMARCHY_T2_HIBERNATE_BRCMFMAC_SRCVERSION="$brcmfmac_srcversion"

check_output=$($command check)
[[ $check_output == *"model: MacBookAir9,1"* ]] || fail "check reports the T2 model"
[[ $check_output == *"resume=/dev/mapper/root"* ]] || fail "check reports the resume device"
[[ $check_output == *"resume_offset=1923214"* ]] || fail "check reports the resume offset"
[[ $check_output == *"kernel resume target: 253:0 offset 1923214"* ]] || fail "check reports the live kernel resume target"
[[ $check_output == *"PM trace: 0"* ]] || fail "check reports PM trace state"
[[ $check_output == *"Bluetooth: powered"* ]] || fail "check reports Bluetooth power"
pass "T2 hibernation check is read-only and reports the active configuration"

: >"$calls"
printf 'on\n' >"$bluetooth_state"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
$command test freezer --bluetooth-off --yes >/dev/null
grep -Fxq 'bluetoothctl power off' "$calls" || fail "freezer isolation powers Bluetooth down"
grep -Fxq 'bluetoothctl power on' "$calls" || fail "freezer isolation restores Bluetooth"
grep -Fq "sudo tee $power/state" "$calls" || fail "freezer test enters the disk power state"
grep -Fq 'logger --tag omarchy-t2-hibernate-test starting stage=freezer bluetooth_off=true pm_trace=false disk_mode=current' "$calls" || fail "freezer test records its start"
grep -Fq 'logger --tag omarchy-t2-hibernate-test returned stage=freezer bluetooth_off=true pm_trace=false disk_mode=current' "$calls" || fail "freezer test records its return"
[[ $(<"$power/pm_test") == "none" ]] || fail "freezer test restores the previous PM test level"
[[ $(<"$bluetooth_state") == "on" ]] || fail "freezer test leaves Bluetooth in its original state"
pass "freezer isolation restores temporary PM and Bluetooth state"

: >"$calls"
printf 'on\n' >"$bluetooth_state"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
$command test freezer --bluetooth-off --no-sudo-prompt --yes >/dev/null
grep -Fxq 'sudo -n true' "$calls" || fail "unattended test requires immediately available sudo"
grep -Fq "sudo -n tee $power/state" "$calls" || fail "unattended test keeps sysfs writes noninteractive"
[[ $(<"$power/pm_test") == "none" ]] || fail "unattended test restores the previous PM test level"
[[ $(<"$bluetooth_state") == "on" ]] || fail "unattended test restores Bluetooth"
pass "unattended test fails closed instead of prompting for sudo"

: >"$calls"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
TEST_CONFIRM_STATUS=1 $command test devices >/dev/null
! grep -Fq "sudo tee $power/state" "$calls" || fail "cancelled test must not enter a power state"
pass "live test requires confirmation"

: >"$calls"
printf 'unavailable\n' >"$bluetooth_state"
if $command test freezer --bluetooth-off --yes >/dev/null 2>&1; then
  fail "Bluetooth isolation must stop when controller power is unknown"
fi
! grep -Fq "sudo tee $power/state" "$calls" || fail "unverified Bluetooth isolation must not enter a power state"
printf 'on\n' >"$bluetooth_state"
pass "Bluetooth isolation requires a verified controller state"

: >"$calls"
printf '[platform] shutdown reboot suspend test_resume\n' >"$power/disk"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
$command test test-resume --pm-trace --yes >/dev/null
grep -Fq "sudo tee $power/disk" "$calls" || fail "test-resume selects the hibernation mode"
grep -Fq "sudo tee $power/pm_trace" "$calls" || fail "traced test enables the RTC-backed PM trace"
grep -Fq 'logger --tag omarchy-t2-hibernate-test starting stage=test-resume bluetooth_off=false pm_trace=true disk_mode=current' "$calls" || fail "test-resume records its start"
[[ $(<"$power/disk") == "platform" ]] || fail "test-resume restores the previous disk mode"
[[ $(<"$power/pm_test") == "none" ]] || fail "test-resume restores the previous PM test level"
[[ $(<"$power/pm_trace") == "0" ]] || fail "test-resume restores the previous PM trace state"
pass "test-resume can persist the last device callback and restores kernel controls"

: >"$calls"
printf '[platform] shutdown reboot suspend test_resume\n' >"$power/disk"
printf '5D40EE47A0592AA2E41E149\n' >"$brcmfmac_srcversion"
if output=$($command test test-resume --yes 2>&1); then
  fail "test-resume must reject the restore-time FLR module"
fi
[[ $output == *"rejected restore-time FLR implementation"* ]] || fail "unsafe module rejection explains the blocked test"
! grep -Fq "sudo tee $power/state" "$calls" || fail "unsafe module must not enter a power state"
printf 'SAFE_TEST_MODULE\n' >"$brcmfmac_srcversion"
pass "test-resume rejects the known hard-resetting Wi-Fi module"

: >"$calls"
printf 'on\n' >"$bluetooth_state"
printf '[platform] shutdown reboot suspend test_resume\n' >"$power/disk"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
chmod 444 "$power/state"
if output=$($command test test-resume --bluetooth-off --pm-trace --yes 2>&1); then
  fail "test-resume must report a rejected state transition"
fi
chmod 644 "$power/state"
[[ $output == *"The kernel rejected the 'test-resume' test."* ]] || fail "failed test reports the kernel rejection"
[[ $output != *"unbound variable"* ]] || fail "failed test cleanup must retain its state"
grep -Fq 'logger --tag omarchy-t2-hibernate-test failed stage=test-resume bluetooth_off=true pm_trace=true disk_mode=current' "$calls" || fail "failed test records its failure"
[[ $(<"$power/disk") == "platform" ]] || fail "failed test restores the previous disk mode"
[[ $(<"$power/pm_test") == "none" ]] || fail "failed test restores the previous PM test level"
[[ $(<"$power/pm_trace") == "0" ]] || fail "failed test restores the previous PM trace state"
[[ $(<"$bluetooth_state") == "on" ]] || fail "failed test restores Bluetooth"
pass "failed power transition preserves its error and restores temporary state"

printf '0:0\n' >"$power/resume"
if $command test test-resume --yes >/dev/null 2>&1; then
  fail "test-resume must reject an unconfigured kernel resume device"
fi
printf '253:0\n' >"$power/resume"
pass "test-resume requires a live kernel resume target"

: >"$calls"
printf '[platform] shutdown reboot suspend test_resume\n' >"$power/disk"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
$command test platform --disk-mode shutdown --yes >/dev/null
grep -Fq "sudo tee $power/disk" "$calls" || fail "disk-mode test writes the temporary mode"
grep -Fq 'logger --tag omarchy-t2-hibernate-test starting stage=platform bluetooth_off=false pm_trace=false disk_mode=shutdown' "$calls" || fail "disk-mode test records the isolation condition"
[[ $(<"$power/disk") == "platform" ]] || fail "disk-mode test restores the previous mode"
pass "platform test can isolate ACPI S4 preparation with temporary shutdown mode"

: >"$calls"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
$command test devices --wifi-unbind --yes >/dev/null
[[ -L "$wifi_driver/0000:73:00.0" ]] || fail "Wi-Fi isolation restores the binding"
awk -v unbind="sudo tee $wifi_driver/unbind" -v state="sudo tee $power/state" -v bind="sudo tee $wifi_driver/bind" '
  $0 == unbind { detached = NR }
  $0 == state { entered = NR }
  $0 == bind { restored = NR }
  END { exit !(detached > 0 && entered > detached && restored > entered) }
' "$calls" || fail "Wi-Fi detach/test/rebind ordering"
grep -Fq 'disk_mode=current wifi_unbind=true' "$calls" || fail "Wi-Fi isolation is recorded"
pass "Wi-Fi is detached before the test and rebound after return"

for failure in TEST_WIFI_UNBIND_FAIL TEST_WIFI_UNBIND_NOOP; do
  : >"$calls"
  printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
  if env "$failure=1" "$command" test devices --wifi-unbind --yes >/dev/null 2>&1; then
    fail "Wi-Fi isolation must reject $failure"
  fi
  ! grep -Fq "sudo tee $power/state" "$calls" || fail "failed detach must not enter PM"
  [[ -L "$wifi_driver/0000:73:00.0" ]] || fail "failed detach retains Wi-Fi"
done
pass "Wi-Fi isolation requires verified detachment"

: >"$calls"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
chmod 444 "$power/state"
if "$command" test devices --wifi-unbind --yes >/dev/null 2>&1; then
  fail "Wi-Fi-isolated rejected PM transition must fail"
fi
chmod 644 "$power/state"
[[ -L "$wifi_driver/0000:73:00.0" ]] || fail "failed PM transition must rebind Wi-Fi"
pass "Wi-Fi binding is restored after a rejected PM transition"

printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
if output=$(TEST_WIFI_BIND_FAIL=1 "$command" test devices --wifi-unbind --yes 2>&1); then
  fail "Wi-Fi rebind failure must not report success"
fi
[[ $output == *"Failed to rebind Wi-Fi"* ]] || fail "Wi-Fi rebind failure is actionable"
[[ $output != *"test returned successfully"* ]] || fail "failed cleanup must not claim success"
ln -s "$wifi_device" "$wifi_driver/0000:73:00.0"
pass "Wi-Fi rebind failure propagates"

: >"$calls"
printf 'on\n' >"$bluetooth_state"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
if output=$(TEST_BLUETOOTH_RESTORE_FAIL=1 "$command" test devices --wifi-unbind --bluetooth-off --yes 2>&1); then
  fail "Bluetooth restoration failure must not report success"
fi
[[ $output == *"Failed to restore Bluetooth power"* ]] || fail "Bluetooth restoration failure is actionable"
[[ -L "$wifi_driver/0000:73:00.0" ]] || fail "Bluetooth cleanup failure must not prevent Wi-Fi rebinding"
printf 'on\n' >"$bluetooth_state"
pass "Bluetooth cleanup failure propagates without skipping Wi-Fi restoration"

: >"$calls"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
TEST_BLUETOOTH_FAIL_ONCE="$test_tmp/bluetooth-failed-once" "$command" test freezer --bluetooth-off --yes >/dev/null
[[ $(<"$bluetooth_state") == "on" ]] || fail "transient Bluetooth failure must recover"
grep -Fq 'Bluetooth restoration attempt=1 failed' "$calls" || fail "transient failure must be recorded"
! grep -Fq 'Bluetooth restoration attempt=2 failed' "$calls" || fail "Bluetooth retry must stop after verified success"
pass "Bluetooth restoration retries a transient failure and verifies recovery"

: >"$calls"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
if "$command" test snapshot-create --yes >/dev/null 2>&1; then
  fail "snapshot-create requires an explicit helper"
fi
OMARCHY_T2_SNAPSHOT_HELPER="$stub_bin/snapshot-create" "$command" test snapshot-create --wifi-unbind --bluetooth-off --yes >/dev/null
grep -Fxq 'snapshot-create --create-and-discard' "$calls" || fail "snapshot-create invokes the cancellation-only helper"
! grep -Fq "sudo tee $power/state" "$calls" || fail "snapshot-create must not invoke kernel hibernation through sysfs"
[[ -L "$wifi_driver/0000:73:00.0" ]] || fail "snapshot-create restores Wi-Fi"
[[ $(<"$bluetooth_state") == "on" ]] || fail "snapshot-create restores Bluetooth"
printf '[none] core processors platform devices freezer\n' >"$power/pm_test"
if OMARCHY_T2_SNAPSHOT_HELPER="$stub_bin/snapshot-create" TEST_SNAPSHOT_STATUS=1 "$command" test snapshot-create --wifi-unbind --bluetooth-off --yes >/dev/null 2>&1; then
  fail "snapshot-create helper failure must propagate"
fi
[[ -L "$wifi_driver/0000:73:00.0" ]] || fail "snapshot-create failure restores Wi-Fi"
[[ $(<"$bluetooth_state") == "on" ]] || fail "snapshot-create failure restores Bluetooth"
pass "snapshot-create isolates creation and unwinds radios on success or error"

: >"$calls"
ln -s "$wifi_device" "$wifi_driver/0000:74:00.0"
if "$command" test devices --wifi-unbind --yes >/dev/null 2>&1; then
  fail "ambiguous Wi-Fi devices must be rejected"
fi
! grep -Fq "sudo tee $wifi_driver/unbind" "$calls" || fail "ambiguous target must not be detached"
rm "$wifi_driver/0000:74:00.0"
printf '0xffff\n' >"$wifi_device/device"
if "$command" test devices --wifi-unbind --yes >/dev/null 2>&1; then
  fail "unqualified Wi-Fi hardware must be rejected"
fi
! grep -Fq "sudo tee $wifi_driver/unbind" "$calls" || fail "unqualified target must not be detached"
printf '0x4488\n' >"$wifi_device/device"
pass "Wi-Fi isolation rejects ambiguous and unqualified PCI targets"

printf 'MacBookPro16,1\n' >"$dmi/product_name"
if $command test freezer --yes >/dev/null 2>&1; then
  fail "live test must reject an unqualified T2 model"
fi
pass "live tests remain scoped to MacBookAir9,1"
