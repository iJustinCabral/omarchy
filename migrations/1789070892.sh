echo "Order validated T2 Bluetooth startup before desktop sessions"
if python3 "$OMARCHY_PATH/install/hardware/apple/t2-bluetooth/manage.py" supported; then
  omarchy-setup-t2-bluetooth
fi
