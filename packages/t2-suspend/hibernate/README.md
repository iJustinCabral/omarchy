# Repeatable hibernation integration

This directory is an offline foundation, not an installed hibernation service. The first v16 experiment restored the original source session successfully; its consumed test vector remains immutable. See [hardware evidence](../../../docs/t2-suspend/HIBERNATION.md).

`transaction.py` models a separate product-cycle ledger using explicitly supplied directories. It has no CLI, EFI operations, module loading, power transitions or imports of the historical experimental runner. Synthetic tests exercise it in temporary directories. No actual MacBookAir9,1 product qualification is supplied or created.

The immutable image-pair qualification identity and each fresh cycle identity serve different purposes. Cycle identities include a UUID, original boot, artifact manifest and external qualification binding; new identities cannot bypass an active, failed or unreconciled predecessor. Changes to the manifest invalidate qualification. Consumed historical test guards must never be deleted, reclassified or worked around by changing an image hash.

Qualification, return and archive receipts are external attestations in this initial ledger, not independently authenticated hardware proof. Metadata archival does not itself copy or authenticate raw EFI originals. A future adapter must validate and durably preserve those originals before reporting archival, verify original-source continuity and cleanup before reporting return/reconciliation, and implement narrowly owned reusable-slot retirement. The ledger performs none of these operations and cannot authorize a physical test.

The remaining integration must connect the tested early-source and isolated-restore boot policies with normal systemd hibernation preparation/cleanup, artifact deployment and update invalidation, and failure recovery. Current Omarchy's `systemctl hibernate` menu path does not implement that workflow. Do not enable it on the strength of this library or a single experimental return. Preserve production kernel/command-line bytes and the cold guard's ANS completion, DMA ownership and terminal pending-resume protections.

Run focused coverage with `PYTHONDONTWRITEBYTECODE=1 python3 packages/t2-suspend/tests/test-hibernate-product-transaction.py`. The T2 aggregate also includes these tests.
