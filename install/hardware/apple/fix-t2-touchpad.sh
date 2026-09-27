# Fix disable-while-typing on T2 Mac built-in trackpads.
#
# t2bce_vhci presents the keyboard/trackpad as USB with
# ATTR{removable}=="unknown", so udev marks the pad external. libinput
# then leaves disable-while-typing off. Thumbs resting on the clickpad
# jump the cursor while typing; Hyprland follow_mouse steals focus.
#
# Upstream libinput (50-system-apple.quirks) already marks the keyboard
# internal. Touchpad integration is a udev property, not a libinput
# quirk — same pattern as fix-z13-touchpad.sh. systemd's hwdb covers only some
# T2 trackpad IDs, so install the name-matched fallback until it classifies
# every one. An existing rule file, or an administrator mask, is left alone.

if omarchy-hw-t2; then
  if omarchy-hw-t2-touchpad-hwdb; then
    echo "Detected T2 Mac. The systemd hwdb already classifies its trackpad."
  else
    rule_dst="${OMARCHY_T2_TOUCHPAD_RULE:-/etc/udev/rules.d/99-omarchy-t2-touchpad.rules}"

    if [[ -e $rule_dst || -L $rule_dst ]]; then
      echo "Detected T2 Mac. Keeping the existing trackpad rule at $rule_dst."
    else
      echo "Detected T2 Mac. Marking the built-in trackpad as internal."
      install -Dm644 "$OMARCHY_INSTALL/hardware/apple/99-omarchy-t2-touchpad.rules" "$rule_dst"
    fi
  fi
fi
