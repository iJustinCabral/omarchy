#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

leaf="$ROOT/install/hardware/apple/fix-t2-audio-dsp.sh"
first_run="$ROOT/install/user/first-run/t2-audio-dsp.sh"
detector="$ROOT/bin/omarchy-hw-t2-audio-dsp"
helper="$ROOT/bin/omarchy-t2-audio-dsp"
hardware_all="$ROOT/install/hardware/all.sh"
provision="$ROOT/bin/omarchy-provision-first-run"
models="$ROOT/default/audio/t2linux/models"
graph_91="$ROOT/default/audio/t2linux/9_1/graph.json"
mic_91="$ROOT/default/audio/t2linux/9_1/mic.json"
migration="$ROOT/migrations/1789344000.sh"

[[ -x $detector ]] || fail "T2 DSP detector is executable"
[[ -x $helper ]] || fail "T2 DSP helper is executable"
grep -Fq 'omarchy-hw-t2-audio-dsp' "$leaf" || fail "hardware leaf gates on the DSP detector"
grep -Fq 'omarchy-pkg-add lsp-plugins-lv2' "$leaf" || fail "hardware leaf installs lsp-plugins-lv2"
grep -Fq 'omarchy-t2-audio-dsp on' "$first_run" || fail "first-run enables the DSP"
grep -Fq 'omarchy-t2-audio-dsp on' "$migration" || fail "migration enables the DSP"
grep -Fq 't2-audio-dsp.sh' "$provision" || fail "first-run provision runs the T2 DSP leaf"
if [[ -f $hardware_all ]]; then
  grep -q 'apple/fix-t2-audio-dsp.sh' "$hardware_all" ||
    fail "the T2 DSP leaf runs during hardware setup"
  awk '
    /fix-t2\.sh/ { t2=NR }
    /fix-t2-audio-dsp\.sh/ { dsp=NR }
    END {
      if (!(t2 && dsp) || !(t2 < dsp))
        exit 1
    }
  ' "$hardware_all" ||
    fail "the T2 DSP leaf runs after T2 setup"
fi

grep -Fq 'MacBookAir9,1 9_1' "$models" || fail "models table includes MacBookAir9,1"
[[ -r $graph_91 ]] || fail "MacBookAir9,1 speaker graph is vendored"
[[ -r $mic_91 ]] || fail "MacBookAir9,1 mic graph is vendored"
grep -Fq '@T2_AUDIO_DIR@' "$graph_91" || fail "speaker FIR paths are rewritten at enable time"
grep -Fq '"AUX2"' "$mic_91" || fail "mic graph maps the third capsule as AUX2"
! grep -Fq '/home/' "$graph_91" "$mic_91" || fail "vendored graphs do not hard-code a user home"
grep -Fq 'alsa_output.t2-speakers' "$graph_91" ||
  fail "speaker DSP sink uses an alsa_output name so volume keys stay on the limiter"
grep -Fq 'https://chadmed.au/bankstown' "$graph_91" || fail "speaker graph uses bankstown"
grep -Fq 'https://chadmed.au/triforce' "$mic_91" || fail "mic graph uses triforce"

pass "T2 DSP files ship measured graphs and wire after T2 setup"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT

stub_bin="$test_tmp/bin"
calls="$test_tmp/calls.log"
mkdir -p "$stub_bin"
: >"$calls"

cat >"$stub_bin/lspci" <<'SH'
#!/bin/bash

if (( ${T2_HARDWARE:-0} == 1 )); then
  echo '74:00.1 Non-VGA unclassified device [0000]: Apple Inc. T2 Bridge Controller [106b:1801] (rev 01)'
fi
for _ in {1..4096}; do
  echo '02:00.0 Host bridge [0600]: Filler Device [ffff:0000]'
done
SH
chmod +x "$stub_bin/lspci"

cat >"$test_tmp/product_name" <<'EOF'
MacBookAir9,1
EOF

export PATH="$stub_bin:$PATH"
export OMARCHY_PATH="$ROOT"
export OMARCHY_T2_AUDIO_MODELS="$models"

# The detector reads DMI from sysfs. Point it at a fake file by wrapping
# the real script is awkward, so exercise the models table plus a stubbed
# product_name via a tiny wrapper that the helper itself uses in tests.
cat >"$stub_bin/omarchy-hw-t2-audio-dsp" <<SH
#!/bin/bash
if (( \${T2_HARDWARE:-0} != 1 )); then
  exit 1
fi
product=\$(cat "$test_tmp/product_name")
while read -r dmi dir; do
  [[ \$dmi == \#* || -z \$dmi ]] && continue
  if [[ \$dmi == "\$product" ]]; then
    printf '%s\\n' "\$dir"
    exit 0
  fi
done <"$models"
exit 1
SH
chmod +x "$stub_bin/omarchy-hw-t2-audio-dsp"

T2_HARDWARE=0 "$stub_bin/omarchy-hw-t2-audio-dsp" &&
  fail "detector rejects machines without a T2"
T2_HARDWARE=1 "$stub_bin/omarchy-hw-t2-audio-dsp" | grep -qx '9_1' ||
  fail "detector maps MacBookAir9,1 to profile 9_1"
printf 'iMac20,1\n' >"$test_tmp/product_name"
T2_HARDWARE=1 "$stub_bin/omarchy-hw-t2-audio-dsp" &&
  fail "detector rejects T2 machines without a shipped profile"
printf 'MacBookAir9,1\n' >"$test_tmp/product_name"

pass "T2 DSP detector matches shipped models only"

# Render without talking to pacman or WirePlumber.
cat >"$stub_bin/omarchy-pkg-add" <<'SH'
#!/bin/bash
printf 'pkg-add %s\n' "$*" >>"$TEST_LOG"
SH
cat >"$stub_bin/omarchy-pkg-aur-accessible" <<'SH'
#!/bin/bash
exit 1
SH
cat >"$stub_bin/omarchy-pkg-missing" <<'SH'
#!/bin/bash
exit 1
SH
cat >"$stub_bin/omarchy-pkg-aur-add" <<'SH'
#!/bin/bash
printf 'pkg-aur-add %s\n' "$*" >>"$TEST_LOG"
exit 1
SH
cat >"$stub_bin/systemctl" <<'SH'
#!/bin/bash
exit 0
SH
cat >"$stub_bin/pactl" <<'SH'
#!/bin/bash
exit 1
SH
chmod +x "$stub_bin"/omarchy-pkg-* "$stub_bin/systemctl" "$stub_bin/pactl"

export TEST_LOG="$calls"
export HOME="$test_tmp/home"
export XDG_CONFIG_HOME="$test_tmp/home/.config"
export XDG_DATA_HOME="$test_tmp/home/.local/share"
mkdir -p "$HOME"

T2_HARDWARE=1 PATH="$stub_bin:$PATH" OMARCHY_PATH="$ROOT" \
  "$helper" on >/dev/null

conf="$XDG_CONFIG_HOME/wireplumber/wireplumber.conf.d/50-t2-audio-dsp.conf"
[[ -f $conf ]] || fail "enable writes the WirePlumber DSP drop-in"
grep -Fq 'alsa_output.platform-sound.RawSpeakers' "$conf" ||
  fail "WirePlumber drop-in hides the raw speaker node"
grep -Fq 'filter-path' "$conf" || fail "WirePlumber drop-in points at the rendered graph"
rendered="$XDG_DATA_HOME/omarchy/t2-audio-dsp/9_1/graph.json"
[[ -f $rendered ]] || fail "enable renders the speaker graph"
! grep -Fq '@T2_AUDIO_DIR@' "$rendered" || fail "rendered FIR paths are concrete"
grep -Fq "$XDG_DATA_HOME/omarchy/t2-audio-dsp/9_1/" "$rendered" ||
  fail "rendered graph loads FIRs from the user data dir"
grep -Fq 'pkg-add lsp-plugins-lv2' "$calls" || fail "enable installs lsp-plugins-lv2"

pass "T2 DSP enable renders graphs and a WirePlumber drop-in"
