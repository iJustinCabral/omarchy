echo "Mark T2 Mac built-in trackpads as internal so disable-while-typing works"

# t2bce_vhci USB pads are udev-external. Existing T2 installs already have
# linux-t2 and the keyboard quirk; they still need this udev rule until their
# systemd hwdb classifies every T2 trackpad ID, not just 05ac:0280.

if ! omarchy-hw-t2 || omarchy-hw-t2-touchpad-hwdb; then
  exit 0
fi

rule_dst="${OMARCHY_T2_TOUCHPAD_RULE:-/etc/udev/rules.d/99-omarchy-t2-touchpad.rules}"

# An existing file or an administrator mask (a /dev/null symlink) is kept.
if [[ ! -e $rule_dst && ! -L $rule_dst ]]; then
  sudo install -Dm644 "$OMARCHY_PATH/install/hardware/apple/99-omarchy-t2-touchpad.rules" "$rule_dst"
  sudo udevadm control --reload-rules
  sudo udevadm trigger --subsystem-match=input --action=change
fi
