# Wrap T2 internal speakers and mics with the model FIR graph. First-run
# rather than finalize-user: WirePlumber is not up in the ISO chroot.

set -euo pipefail

omarchy-t2-audio-dsp on
