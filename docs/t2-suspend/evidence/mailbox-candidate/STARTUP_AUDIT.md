> Historical laboratory snapshot at commit `68bf7e0`. Relative tool paths and earlier next-step/merge statements refer to the lab, not this Omarchy checkout. See `docs/t2-suspend/README.md` for current consolidated status and `packages/t2-suspend/README.md` for runnable source preparation.

# Initialization audit after two failed candidate boots

This supersedes the earlier assumption that adding mailbox messages and then
host-capability writes was sufficient. No third driver patch is justified yet.
The source review found several coupled behaviors, and the experimental loading
environment has not been independently validated.

## Reproduced source behavior

`python3 audit-startup.py` verifies hashes against the retained source manifest,
extracts the actual stock/Asahi IRQ and host-ready functions, and compiles them
with mocked register access using warnings-as-errors and UBSan.

| Input | Stock result | Retained Asahi result |
|---|---|---|
| MSI delivered, mailbox status already zero | IRQ_NONE; no ring processing | IRQ_WAKE_THREAD; ring processing |
| Status nonzero in hard IRQ, zero in thread | No ring processing | No ring processing with this source's irq_ready coupling |
| Shared legacy interrupt, zero status | IRQ_NONE | IRQ_NONE |
| Private PCIe state DOWN | No ring processing | No ring processing |
| Observed flags 0x78810007, 64-bit register layout | host-ready register 0xa24 | host-ready register 0x144 |

Register numbers here are **PCIe-core-relative**. Asahi's accessor adds a BAR
window offset; that offset must not be transplanted into stock's selected-core
mapping mechanically. The harness normalizes the accessors to compare the
core-relative register choice, not absolute BAR addresses.

The Asahi source explains that firmware clears mailbox status in MSI mode.
Revision 2's firmware console actually logged `Single MSI enabled` and
`hostready:Y`. The stock ISR behavior retained in the candidate can discard a
notification when that status has been cleared. This is a demonstrated source
incompatibility for that input, not a capture proving it happened on the failed
boot. No IRQ-status evidence was retained during revision-2 initialization.

Asahi also chooses the host-ready and regular H2D notification registers using
the firmware DAR capability. Our candidate inherited selection solely from
hardware core revision. The observed flags have DAR clear. The functioning
stock driver shows that this difference alone does not establish causality;
register aliases and the negotiated protocol may matter.

## Other dependencies needing explicit treatment

- Asahi allocates MSI/IRQ before firmware download, because newer firmware can
  signal startup by MSI. Stock allocates IRQ after download and ring setup.
- Asahi masks and clears interrupt sources before releasing firmware from reset,
  with a comment about premature host-ready notification.
- Its `irq_ready` flag protects incomplete receive setup, but its hard-IRQ
  masking helper also clears the flag. The reproducer shows a nonzero-status
  path can skip ring processing. Do not copy the complete IRQ block blindly.
  Interrupt ownership, temporary masking, and ring lifetime are distinct states.
- DMA/ring initialization and packet layout need to remain compatible with the
  negotiated host flags. Host capability bits are not independent toggles.
- Setup failure calls `brcmf_fw_crashed()` unconditionally, even after an ordinary
  query timeout. Therefore revision 2's generic “halted or crashed” message is
  **not independent proof of a firmware trap**. Revision 1 did contain an actual
  firmware TRAP dump. Keep those findings separate.
- The cleanup warning involves cancelling uninitialized reset work after partial
  attach failure. It needs separate lifecycle treatment, not a suppressed warning.

Primary source is the retained, hash-verified
[Asahi pcie.c at 77cb8f24](https://github.com/AsahiLinux/linux/blob/77cb8f24c2381a8abb7272d7bbdec548d6426a8a/drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c).
The immutable URL was unavailable through web fetch during this review; the
previously downloaded matching local copy supplies the evidence.

## Controlled next experiment

Both failed candidates loaded Wi-Fi and its firmware-vendor modules from the
initramfs. Normal stock loads Wi-Fi later. Before blaming additional protocol
code, use **Stock Wi-Fi startup control**, which uses the exact packaged stock
kernel and stock module bytes, with the same early-loading configuration and
firmware inclusion as the failed diagnostic images. It involves no compilation,
no patched Wi-Fi code, no controller resets, and no suspend.

`prepare-boot.py --stock-control` stages the existing modules without replacement;
`stock-control-modules.json` records their compressed hashes and srcversions.
Inspection extracts the image and checks all four Wi-Fi module hashes and the
stock kernel section. Boot backup/proof: `work/boot-control/`.
The command-line marker is `t2_mailbox_control=1`; the verifier is
`verify-stock-control.py`.

Observe at least 150 seconds after boot and inspect logs, recovery-service
activity, Wi-Fi, and Bluetooth/AirPods. A recovery reset counts as a failed
startup even if connectivity eventually returns.

- If this control fails, the diagnostic loading environment is sufficient to
  produce startup failure without the mailbox patches. Correct that environment
  before evaluating any patched driver. This does not prove the patches correct.
- If it passes, it shows this environment can boot the packaged driver in that
  run. It does not rule out timing sensitivity; use the protocol/IRQ findings to
  design targeted initialization tracing before another candidate.

The normal Omarchy entry remains default. Return there if the control fails.
Removal after booting stock:
`python3 deploy-boot.py --stock-control remove` with root privileges.
No whole-kernel build, live-driver reload, or power transition was initiated.

Control installed and verified by the deployment routine. UKI SHA-256:
`8fe98b42069a2eee389e67f190b002f39e78aaa262efd2d031ab10a93a7ef4d2`.
Both normal and control variants of the deployment fixture tests passed install,
stock/default preservation, rollback, baseline drift, and failed-write cleanup.
