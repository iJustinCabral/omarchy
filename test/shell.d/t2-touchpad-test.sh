#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

leaf="$ROOT/install/hardware/apple/fix-t2-touchpad.sh"
rule_src="$ROOT/install/hardware/apple/99-omarchy-t2-touchpad.rules"
hardware_all="$ROOT/install/hardware/all.sh"
migration="$ROOT/migrations/1788537572.sh"

grep -Fq 'ID_INPUT_TOUCHPAD_INTEGRATION' "$rule_src" ||
  fail "udev rule sets touchpad integration"
grep -Fq 'Apple Inc. Apple Internal Keyboard / Trackpad' "$rule_src" ||
  fail "udev rule matches the T2 HID name"
! grep -Fq '/etc/libinput' "$leaf" "$migration" ||
  fail "the workaround leaves administrator libinput overrides alone"
grep -Fq 'omarchy-hw-t2' "$leaf" ||
  fail "leaf gates on the T2 detector"
grep -Fq 'omarchy-hw-t2' "$migration" ||
  fail "migration gates on the T2 detector"
grep -Fq 'omarchy-hw-t2-touchpad-hwdb' "$leaf" ||
  fail "installer checks every T2 trackpad against the systemd hwdb"
grep -Fq 'omarchy-hw-t2-touchpad-hwdb' "$migration" ||
  fail "migration checks every T2 trackpad against the systemd hwdb"
if [[ -f $hardware_all ]]; then
  grep -q 'apple/fix-t2-touchpad.sh' "$hardware_all" ||
    fail "the T2 touchpad leaf runs during hardware setup"
  awk '
    /fix-t2\.sh/ { t2=NR }
    /fix-t2-touchpad\.sh/ { pad=NR }
    END {
      if (!(t2 && pad) || !(t2 < pad))
        exit 1
    }
  ' "$hardware_all" ||
    fail "the T2 touchpad leaf runs after T2 setup"
fi
pass "T2 touchpad files mark the pad internal without local libinput quirks"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT

stub_bin="$test_tmp/bin"
calls="$test_tmp/calls.log"
mkdir -p "$stub_bin"
: >"$calls"

cat >"$stub_bin/sudo" <<'SH'
#!/bin/bash

printf 'sudo' >>"$TEST_LOG"
printf '\t%s' "$@" >>"$TEST_LOG"
printf '\n' >>"$TEST_LOG"
"$@"
SH

cat >"$stub_bin/install" <<'SH'
#!/bin/bash

printf 'install' >>"$TEST_LOG"
printf '\t%s' "$@" >>"$TEST_LOG"
printf '\n' >>"$TEST_LOG"

while [[ ${1:-} == -* ]]; do
  shift
done

src=${1:-}
dest=${2:-}
if [[ -n $src && -n $dest ]]; then
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
fi
SH

cat >"$stub_bin/udevadm" <<'SH'
#!/bin/bash

printf 'udevadm' >>"$TEST_LOG"
printf '\t%s' "$@" >>"$TEST_LOG"
printf '\n' >>"$TEST_LOG"
SH

# Answers only for the products listed in HWDB_PRODUCTS, like a hwdb with
# entries for those IDs. "all" covers every product.
cat >"$stub_bin/systemd-hwdb" <<'SH'
#!/bin/bash

[[ $1 == "query" && $2 =~ ^touchpad:usb:v05acp([0-9a-f]{4}):name:Apple\ Inc\.\ Apple\ Internal\ Keyboard\ /\ Trackpad:$ ]] ||
  exit 0
product=${BASH_REMATCH[1]}
if [[ ${HWDB_PRODUCTS:-} == "all" || " ${HWDB_PRODUCTS:-} " == *" $product "* ]]; then
  echo "ID_INPUT_TOUCHPAD_INTEGRATION=${HWDB_VALUE:-internal}"
fi
SH

chmod +x "$stub_bin"/*

cat >"$stub_bin/omarchy-hw-t2" <<'SH'
#!/bin/bash

(( ${T2_HARDWARE:-0} == 1 ))
SH
chmod +x "$stub_bin/omarchy-hw-t2"

rule="$test_tmp/udev/99-omarchy-t2-touchpad.rules"
input_devices="$test_tmp/input"

# Fake /sys/class/input with one built-in T2 pad of the given product ID.
make_input_device() {
  local product=$1
  rm -rf "$input_devices"
  mkdir -p "$input_devices/input7/id" "$input_devices/input3/id"
  echo "Apple Inc. Apple Internal Keyboard / Trackpad" >"$input_devices/input7/name"
  echo 05ac >"$input_devices/input7/id/vendor"
  echo "$product" >"$input_devices/input7/id/product"
  echo "Some USB Mouse" >"$input_devices/input3/name"
  echo 046d >"$input_devices/input3/id/vendor"
  echo c077 >"$input_devices/input3/id/product"
}
make_input_device 0280

detector() {
  PATH="$stub_bin:$PATH" \
    HWDB_PRODUCTS="$1" \
    OMARCHY_INPUT_DEVICES_PATH="$input_devices" \
    "$ROOT/bin/omarchy-hw-t2-touchpad-hwdb"
}

detector "" && fail "detector reports unclassified pads when hwdb has no T2 entries"
detector all || fail "detector accepts a hwdb that classifies every T2 pad"
make_input_device 027b
detector "0280 0340" &&
  fail "detector checks the actual pad, not only 05ac:0280"
detector "027a 027b 027c 027d 027e 027f 0280 0340" ||
  fail "detector accepts a hwdb covering every known T2 pad"
make_input_device 0999
detector "027a 027b 027c 027d 027e 027f 0280 0340" &&
  fail "detector checks a present pad outside the known T2 list"
rm -rf "$input_devices"
detector "0280 0340" &&
  fail "detector checks known T2 IDs when no input devices are visible"
make_input_device 0280
pass "hwdb detector covers the present pad and every known T2 ID"

run_migration() {
  PATH="$stub_bin:$ROOT/bin:$PATH" \
    TEST_LOG="$calls" \
    T2_HARDWARE="${1:-1}" \
    HWDB_PRODUCTS="${2:-}" \
    HWDB_VALUE="${3:-internal}" \
    OMARCHY_INPUT_DEVICES_PATH="$input_devices" \
    OMARCHY_PATH="$ROOT" \
    OMARCHY_T2_TOUCHPAD_RULE="$rule" \
    bash -euo pipefail "$migration" >/dev/null
}

: >"$calls"
run_migration 1
[[ -f $rule ]] || fail "migration installs the udev rule"
grep -Fq 'ID_INPUT_TOUCHPAD_INTEGRATION' "$rule" ||
  fail "migration copies the packaged udev rule"
grep -Fq $'sudo\tudevadm\tcontrol\t--reload-rules' "$calls" ||
  fail "migration reloads udev rules after install"
grep -Fq $'sudo\tudevadm\ttrigger\t--subsystem-match=input\t--action=change' "$calls" ||
  fail "migration reapplies input rules after install"
pass "migration installs and activates the udev rule on T2"

: >"$calls"
run_migration 1
[[ ! -s $calls ]] || fail "an already repaired T2 install is left unchanged" "$(cat "$calls")"
pass "migration is machine-idempotent"

rm -f "$rule"
: >"$calls"
run_migration 0
[[ ! -e $rule ]] || fail "non-T2 systems get no trackpad rule"
[[ ! -s $calls ]] || fail "non-T2 systems skip the trackpad repair" "$(cat "$calls")"
pass "migration skips unrelated hardware"

: >"$calls"
run_migration 1 all
[[ ! -e $rule ]] || fail "upstream hwdb support needs no fallback rule"
[[ ! -s $calls ]] || fail "upstream hwdb support skips the fallback" "$(cat "$calls")"
pass "migration defers to upstream systemd hwdb support"

make_input_device 027b
: >"$calls"
run_migration 1 "0280 0340"
[[ -f $rule ]] || fail "migration installs the fallback when hwdb supports 0280 but not the actual pad"
make_input_device 0280
pass "migration installs the fallback for a pad the hwdb lacks (MacBookPro15,2 05ac:027b)"

rm -f "$rule"
: >"$calls"
run_migration 1 all external
[[ ! -e $rule ]] || fail "an administrator hwdb override marking the pad external is respected"
pass "migration respects an administrator hwdb classification"

ln -s /dev/null "$rule"
: >"$calls"
run_migration 1
[[ -L $rule && $(readlink "$rule") == "/dev/null" ]] || fail "migration keeps an administrator mask of the rule"
[[ ! -s $calls ]] || fail "migration leaves a masked rule alone" "$(cat "$calls")"
rm -f "$rule"
pass "migration preserves an administrator mask of the rule"

run_leaf() {
  PATH="$stub_bin:$ROOT/bin:$PATH" \
    TEST_LOG="$calls" \
    T2_HARDWARE="${1:-1}" \
    HWDB_PRODUCTS="${2:-}" \
    HWDB_VALUE="${3:-internal}" \
    OMARCHY_INPUT_DEVICES_PATH="$input_devices" \
    OMARCHY_PATH="$ROOT" \
    OMARCHY_INSTALL="$ROOT/install" \
    OMARCHY_T2_TOUCHPAD_RULE="$rule" \
    bash -euo pipefail "$leaf" >/dev/null
}

rm -f "$rule"
: >"$calls"
run_leaf 1
[[ -f $rule ]] || fail "installer leaf installs the udev rule"
pass "installer leaf installs the udev rule on T2"

rm -f "$rule"
: >"$calls"
run_leaf 0
[[ ! -e $rule ]] || fail "installer leaf skips machines without T2"
[[ ! -s $calls ]] || fail "installer leaf is silent on unrelated hardware" "$(cat "$calls")"
pass "installer leaf skips unrelated hardware"

: >"$calls"
run_leaf 1 all
[[ ! -e $rule ]] || fail "installer adds no fallback when systemd supports the pad"
[[ ! -s $calls ]] || fail "installer defers to upstream systemd hwdb" "$(cat "$calls")"
pass "installer leaf defers to upstream systemd hwdb support"

make_input_device 027b
: >"$calls"
run_leaf 1 "0280 0340"
[[ -f $rule ]] || fail "installer installs the fallback when hwdb supports 0280 but not the actual pad"
make_input_device 0280
pass "installer leaf installs the fallback for a pad the hwdb lacks"

echo "# administrator edit" >"$rule"
: >"$calls"
run_leaf 1
[[ $(cat "$rule") == "# administrator edit" ]] || fail "installer keeps an administrator-edited rule"
[[ ! -s $calls ]] || fail "installer leaves an existing rule alone" "$(cat "$calls")"
rm -f "$rule"
ln -s /dev/null "$rule"
run_leaf 1
[[ -L $rule ]] || fail "installer keeps an administrator mask of the rule"
rm -f "$rule"
pass "installer leaf preserves administrator rule edits and masks"
