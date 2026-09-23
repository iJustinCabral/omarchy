echo "Install automatic suspend and radio recovery drivers on supported T2 Macs"
if python3 "$OMARCHY_PATH/packages/t2-suspend/installer/manage.py" supported; then
  omarchy-setup-t2-suspend
fi
