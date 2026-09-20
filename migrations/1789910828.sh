echo "Remove the unsafe T2 Wi-Fi hibernation restore reset"
if python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" supported; then
  omarchy-setup-t2-suspend
fi
