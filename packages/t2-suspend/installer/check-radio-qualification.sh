#!/bin/bash
# Usage: check-radio-qualification.sh KERNEL_RELEASE [ROOT]
# Exit 0: the kernel's stock radio modules match a qualified row of qualified-radio.conf.
# Exit 1: unqualified, so the stock radio drivers must be kept. Exit 2: usage or environment error.
# This is the DKMS PRE_BUILD script and is also run by the initramfs hook. It reads only the
# stock kernel tree, so an installed replacement never influences the answer.
set -uo pipefail
release=${1:-${kernelver:-}}
root=${2:-/}
root=${root%/}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
table=$here/qualified-radio.conf
if [[ -z $release ]]; then
  echo "check-radio-qualification: kernel release required" >&2
  exit 2
fi
if [[ ! -r $table ]]; then
  echo "check-radio-qualification: missing $table" >&2
  exit 2
fi
modules=(brcmfmac brcmfmac-wcc brcmfmac-cyw brcmfmac-bca hci_bcm4377)
declare -A directory=(
  [brcmfmac]=drivers/net/wireless/broadcom/brcm80211/brcmfmac
  [brcmfmac-wcc]=drivers/net/wireless/broadcom/brcm80211/brcmfmac/wcc
  [brcmfmac-cyw]=drivers/net/wireless/broadcom/brcm80211/brcmfmac/cyw
  [brcmfmac-bca]=drivers/net/wireless/broadcom/brcm80211/brcmfmac/bca
  [hci_bcm4377]=drivers/bluetooth
)
found=()
for module in "${modules[@]}"; do
  file=
  for candidate in "$root/usr/lib/modules/$release/kernel/${directory[$module]}/$module.ko"{,.zst,.xz,.gz}; do
    if [[ -f $candidate ]]; then
      file=$candidate
      break
    fi
  done
  srcversion=
  if [[ -n $file ]]; then
    srcversion=$(modinfo -F srcversion "$file" 2>/dev/null) || srcversion=
  fi
  found+=("${srcversion:-missing}")
done
while read -r label a b c d e rest; do
  [[ -z $label || $label == "#"* ]] && continue
  if [[ "$a $b $c $d $e" == "${found[*]}" ]]; then
    echo "T2 radio kernel $release matches qualified fingerprint $label"
    exit 0
  fi
done < "$table"
{
  echo "T2 radio package is not qualified for kernel $release; keeping the stock radio drivers."
  echo "Stock srcversions (${modules[*]}): ${found[*]}"
  echo "Wi-Fi keeps the unpatched stock suspend behavior until this kernel is requalified."
} >&2
exit 1
