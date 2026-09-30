#!/bin/bash

set -euo pipefail

source "$(dirname "$0")/base-test.sh"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT

stub_bin="$test_tmp/bin"
state="$test_tmp/state"
opt_in="$test_tmp/enabled"
model="$test_tmp/product_name"
calls="$test_tmp/calls"
mkdir -p "$stub_bin"

# Paths are rewritten in a copy of the command; every privileged or power-
# adjacent step is a logging stub, so nothing here can touch the real product.
sed -e "s|^STATE=.*|STATE=\"$state\"|" \
  -e "s|^OPT_IN=.*|OPT_IN=\"$opt_in\"|" \
  -e "s|^MODEL=.*|MODEL=\"$model\"|" \
  "$ROOT/bin/omarchy-update-t2-hibernation" >"$test_tmp/hook"

cat >"$stub_bin/sudo" <<'STUB'
#!/bin/bash
# Run read-only `test` for real; script the product's native actions.
if [[ $1 == "/usr/bin/python3" ]]; then
  action=${*: -1}
  printf 'native %s\n' "$action" >>"$CALLS"
  case $action in
    maintenance) exit "${MAINTENANCE_STATUS:-0}" ;;
    reactivate) exit "${REACTIVATE_STATUS:-0}" ;;
    assess)
      (( ${ASSESS_STATUS:-0} == 0 )) || exit "$ASSESS_STATUS"
      printf '%s\n' "${ASSESS_OUTPUT:-{\"class\": \"unchanged\"\}}"
      ;;
  esac
  exit 0
fi
exec "$@"
STUB

cat >"$stub_bin/gum" <<'STUB'
#!/bin/bash
case $1 in
  style) printf 'gum style\n' >>"$CALLS" ;;
  confirm)
    printf 'confirm %s\n' "$2" >>"$CALLS"
    [[ ${GUM_ANSWER:-yes} == "yes" ]]
    ;;
esac
STUB

cat >"$stub_bin/omarchy-hw-t2" <<'STUB'
#!/bin/bash
exit "${T2_STATUS:-0}"
STUB
chmod +x "$stub_bin"/*

reset() {
  rm -rf "$state" "$opt_in"
  mkdir -p "$state"
  printf 'MacBookAir9,1\n' >"$model"
  : >"$calls"
  unset GUM_ANSWER MAINTENANCE_STATUS REACTIVATE_STATUS ASSESS_STATUS ASSESS_OUTPUT T2_STATUS OMARCHY_UPDATE_UNATTENDED
}

set_active() {
  : >"$state/boot-policy.json"
  : >"$opt_in"
}
set_maintenance() { : >"$state/package-maintenance.pending"; }

run_hook() {
  status=0
  CALLS="$calls" PATH="$stub_bin:$PATH" bash "$test_tmp/hook" "$1" >"$test_tmp/out" 2>"$test_tmp/err" || status=$?
}

called() { grep -qxF "$1" "$calls"; }
said() { grep -q "$1" "$test_tmp/out" "$test_tmp/err"; }
untouched() { [[ ! -s $calls && ! -s $test_tmp/out && ! -s $test_tmp/err ]]; }

# Not installed, or not this hardware: silent no-op, nothing asked or run.
reset
rm -rf "$state"
for phase in pre post; do
  run_hook $phase
  (( status == 0 )) || fail "$phase without the product exits nonzero"
  untouched || fail "$phase without the product is not silent"
done
reset
set_active
printf 'MacBookPro16,1\n' >"$model"
run_hook pre
(( status == 0 )) && untouched || fail "another Mac is not left alone"
reset
set_active
export T2_STATUS=1
run_hook pre
(( status == 0 )) && untouched || fail "a non-T2 machine is not left alone"
pass "without the product on a MacBookAir9,1 nothing happens"

# Product installed but idle: nothing to pause or resume.
reset
for phase in pre post; do
  run_hook $phase
  (( status == 0 )) && untouched || fail "an inactive product is not left alone in $phase"
done
pass "an inactive product is left alone"

reset
run_hook bogus
(( status == 2 )) || fail "an unknown phase is not a usage error"
pass "an unknown phase is a usage error"

# pre, active.
reset
set_active
run_hook pre
(( status == 0 )) || fail "confirmed pause fails the update"
called "confirm Pause T2 hibernation for this update?" || fail "the pause is not asked for"
called "native maintenance" || fail "confirmed pause does not run maintenance"
said "paused" || fail "confirmed pause reports nothing"
pass "active plus yes pauses hibernation"

reset
set_active
GUM_ANSWER=no run_hook pre
(( status == 1 )) || fail "declined pause does not stop the update"
! called "native maintenance" || fail "declined pause still ran maintenance"
grep -q 'boot_policy_native.py maintenance' "$test_tmp/out" || fail "declined pause does not name the command"
pass "active plus no stops the update and names the command"

reset
set_active
MAINTENANCE_STATUS=1 run_hook pre
(( status == 1 )) || fail "failed pause does not stop the update"
said "MAINTENANCE-RUNBOOK" || fail "failed pause does not point at the runbook"
pass "a failed pause stops the update and points at the runbook"

reset
set_active
OMARCHY_UPDATE_UNATTENDED=1 run_hook pre
(( status == 1 )) || fail "unattended update proceeds without consent"
! grep -qE 'native|confirm' "$calls" || fail "unattended update prompted or ran the product"
pass "-y never pauses hibernation on its own"

# pre, already paused.
reset
set_maintenance
run_hook pre
(( status == 0 )) || fail "already-paused stops the update"
said "already paused" || fail "already-paused is not reported"
! called "native maintenance" || fail "already-paused ran maintenance again"
! called "confirm Pause T2 hibernation for this update?" || fail "already-paused asked again"
pass "already paused continues without asking"

# pre and post, incomplete states.
incomplete_states=(
  "set_maintenance; : >\$state/source-default-deactivation.pending"
  ": >\$state/source-default-activation.pending"
  ": >\$state/runtime-upgrade.pending"
  ": >\$state/.runtime-pending"
  "set_maintenance; : >\$opt_in"
  ": >\$opt_in"
  ": >\$state/boot-policy.json"
)
for setup in "${incomplete_states[@]}"; do
  reset
  eval "$setup"
  run_hook pre
  (( status == 1 )) || fail "incomplete state ($setup) does not stop the update"
  said "MAINTENANCE-RUNBOOK" || fail "incomplete state ($setup) does not point at the runbook"
  ! grep -qE 'native|confirm' "$calls" || fail "incomplete state ($setup) ran the product"
  run_hook post
  (( status == 0 )) || fail "post fails the update in incomplete state ($setup)"
  ! grep -qE 'native|confirm' "$calls" || fail "post in incomplete state ($setup) ran the product"
done
pass "an incomplete state stops pre with the runbook and never fails post"

# post.
reset
set_active
run_hook post
[[ ! -s $calls ]] || fail "post on an active product did something"
pass "post leaves an unpaused product alone"

reset
set_maintenance
run_hook post
(( status == 0 )) || fail "unchanged plus yes fails the update"
called "native assess" || fail "post does not assess"
called "confirm Turn hibernation back on?" || fail "unchanged does not offer to resume"
called "native reactivate" || fail "unchanged plus yes does not reactivate"
pass "paused and unchanged plus yes reactivates"

reset
set_maintenance
GUM_ANSWER=no run_hook post
(( status == 0 )) || fail "unchanged plus no fails the update"
! called "native reactivate" || fail "declined resume still reactivated"
grep -q 'boot_policy_native.py reactivate' "$test_tmp/out" || fail "declined resume does not name the command"
pass "paused and unchanged plus no leaves it off and names the command"

reset
set_maintenance
REACTIVATE_STATUS=1 run_hook post
(( status == 0 )) || fail "failed reactivation fails the update"
said "MAINTENANCE-RUNBOOK" || fail "failed reactivation does not point at the runbook"
pass "a failed reactivation does not fail the update"

reset
set_maintenance
OMARCHY_UPDATE_UNATTENDED=1 run_hook post
(( status == 0 )) || fail "unattended post fails"
called "native assess" || fail "unattended post does not assess"
! called "native reactivate" || fail "unattended post reactivated"
! called "confirm Turn hibernation back on?" || fail "unattended post prompted"
pass "-y never turns hibernation back on on its own"

reset
set_maintenance
ASSESS_OUTPUT='{"class": "requalification-required"}' run_hook post
(( status == 0 )) || fail "requalification-required fails the update"
said "kernel or drivers changed" || fail "requalification-required is not explained"
said "Suspend (S3) still works" || fail "requalification-required does not reassure about S3"
! called "native reactivate" || fail "requalification-required attempted reactivation"
! called "confirm Turn hibernation back on?" || fail "requalification-required offered to resume"
pass "requalification-required explains and never resumes"

reset
set_maintenance
ASSESS_OUTPUT='{"class": "unknown"}' run_hook post
(( status == 0 )) || fail "unknown fails the update"
said "MAINTENANCE-RUNBOOK" || fail "unknown does not point at the runbook"
! called "native reactivate" || fail "unknown attempted reactivation"
pass "unknown points at the runbook and never resumes"

reset
set_maintenance
ASSESS_STATUS=1 run_hook post
(( status == 0 )) || fail "a failing assess fails the update"
said "MAINTENANCE-RUNBOOK" || fail "a failing assess does not point at the runbook"
! called "native reactivate" || fail "a failing assess attempted reactivation"
pass "a failing assess is tolerated"

reset
set_maintenance
ASSESS_OUTPUT='not json' run_hook post
(( status == 0 )) || fail "unparseable assess fails the update"
! called "native reactivate" || fail "unparseable assess attempted reactivation"
pass "an unparseable assess is tolerated"
