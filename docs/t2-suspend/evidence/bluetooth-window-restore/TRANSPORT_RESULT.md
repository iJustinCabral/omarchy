> Historical laboratory snapshot at commit `68bf7e0`. Relative tool paths and earlier next-step/merge statements refer to the lab, not this Omarchy checkout. See `docs/t2-suspend/README.md` for current consolidated status and `packages/t2-suspend/README.md` for runnable source preparation.

# Post-resume transport diagnosis

2026-09-12, same candidate boot `1a03791e-5c20-41fb-8c22-18b9e30dabfa`.
No new suspend/reboot, module reload, PCI reset, pairing removal or hardware
register writes were performed. Two bounded connect requests to the existing
AirPods bond were traced. They did not establish a connection.

## Measured state

Guarded read-only MMIO snapshot at monotonic 507.760707:

| Register group | Value |
| --- | --- |
| Firmware bootstage / RTI status | 2 / 2 |
| Host DMA window low/high/size | 0 / 0 / fffffe00 |
| RTI DMA window low/high/size | 0 / 0 / fffffe00 |
| Firmware context DMA address | 6077a000 |

The PCI identity, active runtime state, exact loaded candidate srcversion, and
all applicable window mappings were checked before reading the documented
status/DMA registers. No doorbell, sleep-control or unknown register was read.

Root PCI capability read reports D0, BusMaster+, MSI Enable+, IRQ168, ASPM
disabled. MSI address fee00838/data0 is recorded, not independently validated
against the interrupt-remapping table. PCIe AER UESta has no active errors.
DevSta shows CorrErr/UnsupReq status flags; do not claim all PCI status is clean.

Successful captures `/var/log/t2bt-connect-x_to0aeh` and
`/var/log/t2bt-connect-vr4ckreo` each show hci_send_frame -> enqueue -> returns0,
without any bcm4377_irq entry. IRQ168 counts stayed 6/0/0/5776 across both
16-second windows. Each trace retained 4/4 entries, cleanup_errors empty.
The CLI exit0 says only that the request was submitted; there was no Connected
success notification. An earlier setup-only attempt in t2bt-connect-dpvdhz9k
failed at tracefs file opening, issued no connection request and cleaned up.

## Shared memory read

A kprobe on enqueue captured the live bcm4377_data pointer. GDB read only
selected fields through /proc/kcore using the exact loaded module's DWARF types.
The kernel was neither attached/stopped nor modified. GDB's module-vs-kcore
executable warning is expected for this type-only use; loaded module srcversion
and the type layout were checked. The pointer is valid only for this instance.

Driver ctx_dma=6077a000, matching the firmware register. ring_state_dma=6077b000.
Cached bootstage/RTI=2/2, resume_config_failed=false. Context ring-state addresses
match the corresponding offsets within the host allocation; version=1, size=68,
caps=2. Source initializes version1 despite an outdated comment saying2.

Shared ring snapshot:

- Completion heads: 10,11,16,0,0,0.
- Completion tails: 10,11,16,0,0,0 (no unread completions).
- HCI command transfer ring1: host head99, firmware tail87 (12 outstanding).
- Other transfer heads: 10,99,75,0,15,53,99,0,0.
- Other transfer tails: 10,87,60,0,0,53,84,0,0.

This rules out the narrow explanation that completed responses are simply
waiting in the host completion rings for a missing interrupt. The controller
has not consumed the queued HCI commands. Firmware/RTI status2 alone is not
proof that its processor or DMA transport remains operational.

## Next implementation boundary

Investigate reactivation of retained Bluetooth transport after platform S3:
compare firmware command-consumer progress and transport notification state,
including PCIe doorbell delivery, against cold initialization. The existing
code already writes AWAKE on every enqueue, so another identical poke or fixed
delay is not a justified new fix. Re-pairing cannot repair this failure.

Do not reset the shared package or reuse setup_rti blindly: that sequence starts
an RTI 1->2 negotiation and configures DMA/rings, and its effect on retained ring
ownership must be reviewed first. A stale status2, stalled firmware processor,
missing doorbell notification or device DMA issue are still distinct possible
causes. No new image has been built or installed during this diagnosis.
