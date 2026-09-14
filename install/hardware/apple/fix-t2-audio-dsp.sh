# Install LV2 plugins used by the T2 speaker/mic DSP graphs.
#
# Graphs themselves are applied at first-run / `omarchy t2 audio-dsp on`, when
# a user session and WirePlumber exist. Matching is DMI + T2 PCI, not the
# live audio graph, so the ISO chroot still gets the packages.

if omarchy-hw-t2-audio-dsp >/dev/null; then
  echo "Detected a T2 Mac with a shipped speaker/mic DSP profile."
  omarchy-pkg-add lsp-plugins-lv2
  if omarchy-pkg-aur-accessible; then
    aur_pkgs=(bankstown triforce)
    graph="$OMARCHY_PATH/default/audio/t2linux/$(omarchy-hw-t2-audio-dsp)/graph.json"
    if [[ -r $graph ]] && grep -Fq 'plugin.org.uk/swh-plugins/fastLookaheadLimiter' "$graph"; then
      aur_pkgs+=(swh-lv2-git)
    fi
    omarchy-pkg-aur-add "${aur_pkgs[@]}"
  fi
fi
