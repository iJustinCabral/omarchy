echo "Enable automatic firmware-stall recovery on validated T2 BCM4377 Macs"

# Eligibility is deliberately narrower than all T2 Macs. The setup leaf is
# idempotent and refuses administrator-owned or standalone recovery units.
if omarchy-t2-wifi-recovery --supported >/dev/null 2>&1; then
  omarchy-setup-t2-wifi-recovery
fi
