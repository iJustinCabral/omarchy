echo "Upgrade T2 suspend drivers for hibernation callback support"
if python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" supported; then
  omarchy-setup-t2-suspend
fi
