# Run after the T2 kernel and transactional Bluetooth startup gate are installed.
if python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" supported; then
  omarchy-pkg-add dkms linux-t2-headers gcc make patch &&
  python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" install
fi
