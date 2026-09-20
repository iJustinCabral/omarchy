#!/bin/bash
set -euo pipefail
release=$1
[[ $release =~ ^[a-zA-Z0-9._+-]+-t2$ ]] || { echo "Expected a linux-t2 kernel release" >&2; exit 1; }
headers=/lib/modules/$release/build
debug=()
if grep -qx 'CONFIG_BRCMDBG=y' "$headers/.config"; then
  debug=(KCFLAGS=-DDEBUG)
fi
make -C "$headers" M="$PWD/drivers/net/wireless/broadcom/brcm80211/brcmfmac" W=1 "${debug[@]}" -j4 modules
make -C "$headers" M="$PWD/drivers/bluetooth" W=1 -j4 modules
make -C "$headers" M="$PWD/drivers/staging/t2bce/t2bce_core" CONFIG_T2BCE_CORE=m W=1 -j4 modules
make -C "$headers" M="$PWD/drivers/staging/t2bce/t2bce_audio" CONFIG_T2BCE_AUDIO=m KBUILD_EXTRA_SYMBOLS="$PWD/drivers/staging/t2bce/t2bce_core/Module.symvers" W=1 -j4 modules
