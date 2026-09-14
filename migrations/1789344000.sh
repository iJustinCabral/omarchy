echo "Enable T2 speaker and microphone DSP on matching Macs"

# Existing T2 installs already have apple-t2-audio-config (UCM routing) but
# play and record through the raw converters. Apply the measured FIR graphs
# when this machine has a shipped profile. No-op on every other computer.

if ! omarchy-hw-t2-audio-dsp >/dev/null; then
  exit 0
fi

omarchy-t2-audio-dsp on
