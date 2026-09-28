echo "Update the T2 Bluetooth startup gate to find Wi-Fi by device ID"

# The earlier gate waited for Wi-Fi at the fixed PCI address 0000:73:00.0.
# Only an installed gate is upgraded; absent or rolled-back setups are left alone.
if python3 "$OMARCHY_PATH/install/hardware/apple/t2-bluetooth/manage.py" supported; then
  sudo /usr/bin/python3 "$OMARCHY_PATH/install/hardware/apple/t2-bluetooth/manage.py" upgrade
fi
