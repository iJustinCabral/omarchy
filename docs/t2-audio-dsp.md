# T2 speaker and microphone DSP

Intel T2 Macs route internal speakers and mics through `t2bce_audio` with ALSA UCM (`apple-t2-audio-config`). That path is electrically correct and also unvoiced: no FIR, no bass reconstruction, no array beamformer. The graphs under `default/audio/t2linux/` are the measured t2linux/Asahi tunings from [t2-apple-audio-dsp](https://github.com/lemmyg/t2-apple-audio-dsp).

## What gets installed

On a T2 Mac whose DMI product name is in `default/audio/t2linux/models`:

1. `install/hardware/apple/fix-t2-audio-dsp.sh` pulls `lsp-plugins-lv2` and, when the AUR is reachable, `bankstown`, `triforce`, and `swh-lv2-git` for the two 15"/16" graphs that need the SWH lookahead limiter.
2. First-run and the migration run `omarchy t2 audio-dsp on`, which renders the model graph into `~/.local/share/omarchy/t2-audio-dsp/` and writes `~/.config/wireplumber/wireplumber.conf.d/50-t2-audio-dsp.conf`.
3. WirePlumber hides the raw HiFi speaker/mic nodes and wraps them. The default sink is `alsa_output.t2-speakers` so Omarchy volume keys stay on the DSP (and therefore on the limiter) instead of the hidden hardware node.

Machines without a shipped profile are untouched.

## Safety

Keep the DSP volume around 75% or below. The raw converter stays at 100%. Selecting the hidden raw speaker node bypasses the woofer limiter.

Validated live on MacBookAir9,1: both speaker FIR and three-capsule mic beamformer linked in PipeWire 1.6.8 / WirePlumber 0.5.17. Other models are the upstream t2linux graphs with the same wrapper; they are not re-measured here.

## Commands

```bash
omarchy t2 audio-dsp status
omarchy t2 audio-dsp on
omarchy t2 audio-dsp off
```
