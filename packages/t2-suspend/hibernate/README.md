# Repeatable hibernation integration

This directory is an offline foundation, not an installed hibernation service. The first v16 experiment restored the original source session successfully; its consumed test vector remains immutable. See [hardware evidence](../../../docs/t2-suspend/HIBERNATION.md).

`transaction.py` models a separate product-cycle ledger using explicitly supplied directories. It has no CLI, EFI operations, module loading, power transitions or imports of the historical experimental runner. Synthetic tests exercise it in temporary directories. No actual MacBookAir9,1 product qualification is supplied or created.

The immutable image-pair qualification identity and each fresh cycle identity serve different purposes. Cycle identities include a UUID, original boot, artifact manifest and external qualification binding; new identities cannot bypass an active, failed or unreconciled predecessor. Changes to the manifest invalidate qualification. Consumed historical test guards must never be deleted, reclassified or worked around by changing an image hash.

Qualification, return and archive receipts are external attestations in this initial ledger, not independently authenticated hardware proof. Metadata archival does not itself copy or authenticate raw EFI originals. A future adapter must validate and durably preserve those originals before reporting archival, verify original-source continuity and cleanup before reporting return/reconciliation, and implement narrowly owned reusable-slot retirement. The ledger performs none of these operations and cannot authorize a physical test.

`continuity.py` adds an injected, original-process collector: it validates consumed cycle records before its one power-write callback, retains a nonce and immutable pins, captures raw EFI immediately on return, and verifies cleanup health before proposing an internally hashed return record. There is no built-in power operation or host sampler. Its proof is conditional on a trusted original process and correctly implemented callbacks, not authentication of arbitrary JSON or caller-supplied provenance. An ordinary boot, historical experiment proof, changed process or mismatched cycle cannot substitute for that return path. Physical input and usable-hibernation qualification stay false.

`evidence_archive.py` copies explicitly supplied raw bytes into a private exclusive archive, verifies them, and durably publishes a completion manifest binding the cycle, return receipt and each member's size/hash. It never reads live EFI paths, retires slots or deletes evidence. Partial archives fail closed and remain preserved. This establishes copy integrity, not the truth of observations supplied by the caller.

These components still need an audited adapter that derives pins from actual artifacts, binds the collector's prepared-cycle record atomically to the ledger, supplies exact capture bytes to the archive and advances ledger states from internally computed receipts. A plain caller-provided hash is not sufficient for the future live workflow. No live product qualification or installed service exists yet.

The remaining integration must connect the tested early-source and isolated-restore boot policies with normal systemd hibernation preparation/cleanup, artifact deployment and update invalidation, and failure recovery. Current Omarchy's `systemctl hibernate` menu path does not implement that workflow. Do not enable it on the strength of this library or a single experimental return. Preserve production kernel/command-line bytes and the cold guard's ANS completion, DMA ownership and terminal pending-resume protections.

Run focused coverage with `PYTHONDONTWRITEBYTECODE=1 python3 packages/t2-suspend/tests/test-hibernate-product-transaction.py`. The T2 aggregate also includes these tests.

Companion tests are `test-hibernate-product-continuity.py` and `test-hibernate-product-archive.py` in the same tests directory; both are included in the T2 aggregate and use only synthetic inputs and temporary directories.
