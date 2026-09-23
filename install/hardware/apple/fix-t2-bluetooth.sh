# Run after fix-t2.sh creates the initial module list. Do not start the gate
# in the installer; it controls ordering at the next boot.
if python3 "$OMARCHY_INSTALL/hardware/apple/t2-bluetooth/manage.py" supported; then
  python3 "$OMARCHY_INSTALL/hardware/apple/t2-bluetooth/manage.py" install --fresh
fi
