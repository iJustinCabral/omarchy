# Recover the confirmed BCM4377 firmware-query stall without rebooting.
# Other Broadcom chips must never use this reset policy. Model opt-in does
# not bypass the Apple T2/14e4:4488 hardware checks in the helper.

if omarchy-t2-wifi-recovery --supported >/dev/null 2>&1; then
  unit="${OMARCHY_T2_WIFI_UNIT:-/etc/systemd/system/omarchy-t2-wifi-recovery.service}"
  source_unit="$OMARCHY_INSTALL/hardware/apple/omarchy-t2-wifi-recovery.service"
  legacy_unit="${OMARCHY_T2_WIFI_LEGACY_UNIT:-/etc/systemd/system/t2-wifi-recovery.service}"
  model_override="${unit}.d/10-model-opt-in.conf"

  if [[ -e $legacy_unit || -L $legacy_unit ]]; then
    echo "A standalone T2 Wi-Fi recovery service exists. Remove it through its installer before enabling Omarchy recovery." >&2
    false
  elif [[ -L $unit ]] || { [[ -e $unit ]] && ! cmp -s "$unit" "$source_unit"; }; then
    echo "Preserving the existing Wi-Fi recovery unit; review its differences before enabling." >&2
    false
  else
    # Never change an administrator's override. Opt-in is explicit and sticky;
    # subsequent automatic hardware setup preserves an existing opt-in.
    opt_in=$'[Service]\nEnvironment=OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL=1'
    if [[ ${OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL:-0} == "1" ]] &&
      { [[ -L $model_override ]] || { [[ -e $model_override ]] && [[ $(cat "$model_override") != "$opt_in" ]]; }; }; then
      echo "Preserving the existing model override; review it before enabling." >&2
      false
    else
      install -Dm644 "$source_unit" "$unit"
      if [[ ${OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL:-0} == "1" ]]; then
        mkdir -p "${unit}.d"
        printf '%s\n' "$opt_in" > "$model_override"
        chmod 644 "$model_override"
      fi
      systemctl daemon-reload
      if [[ ${OMARCHY_T2_WIFI_START_NOW:-0} == "1" ]]; then
        systemctl enable --now omarchy-t2-wifi-recovery.service
      else
        systemctl enable omarchy-t2-wifi-recovery.service
      fi
      echo "Enabled BCM4377 firmware-stall recovery. Wi-Fi preferences are unchanged."
    fi
  fi
elif [[ ${OMARCHY_T2_WIFI_START_NOW:-0} == "1" ]]; then
  echo "Wi-Fi recovery requires a supported Apple T2/BCM4377b combination; other models need explicit opt-in." >&2
  false
fi
