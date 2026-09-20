echo "Install T2 audio hibernation callbacks"
if python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" supported; then
  omarchy-setup-t2-suspend
fi
