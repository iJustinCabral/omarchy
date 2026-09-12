echo "Retire the BCM4377 Wi-Fi unload sleep workaround"

# Disabling the workaround avoids its observed Bluetooth resume regression.
# This does not fix the underlying Wi-Fi D3 timeout or enable hibernation.
unit="${OMARCHY_T2_BCM4377_UNIT:-/etc/systemd/system/omarchy-t2-bcm4377-sleep.service}"
[[ -f $unit ]] || exit 0

# Match the exact unit our retired installer wrote; preserve administrator units.
read -r checksum _ < <(sha256sum "$unit")
[[ $checksum == "31f5ac9e2c00f112e477550faec46bb38dab4abe2ba3f6f91d5b12b0f10c26ac" ]] || exit 0

state=$(systemctl show omarchy-t2-bcm4377-sleep.service -p ActiveState --value)
if [[ $state != "inactive" && $state != "failed" ]]; then
  echo "Sleep preparation is active; retry this migration after it finishes." >&2
  exit 1
fi

# Do not stop an active sleep transaction or touch either radio driver.
# Preserve the old unit for inspection, but remove its sleep.target enablement.
sudo systemctl disable omarchy-t2-bcm4377-sleep.service
