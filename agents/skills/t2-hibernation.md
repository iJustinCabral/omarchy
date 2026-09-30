# T2 hibernation (MacBookAir9,1)

Read this before touching anything under `packages/t2-suspend/`, `bin/omarchy-update-t2-hibernation`, `bin/omarchy-system-hibernate`, the hibernation boot images, Limine boot entries on the MacBookAir9,1, or anything in `docs/t2-suspend/`. The hardware safety rules in `AGENTS.md` ("T2 Hibernation Hardware Safety" and "Autonomous T2 Agent Routing") stay in force and this guide does not weaken them. The entry point for the documents is [`docs/t2-suspend/README.md`](../../docs/t2-suspend/README.md).

## 1. Reconcile state first

Do this before any privileged action, and again after every reboot:

1. Read `docs/t2-suspend/RESUME.md` (the source of truth for status) and the hardware record `docs/t2-suspend/EVIDENCE-7.2.7.md`.
2. Run `git status --short`, `git log -5 --oneline` and `cat /proc/sys/kernel/random/boot_id`. A restored snapshot may not contain the latest commits.
3. Read `/home/jjc/.local/state/codex-mba-autonomous/handoff.json` with `jq`, especially `claude_checkpoint`. It is local state and is not in git; do not dump it.
4. Check who else drives the machine: `pgrep -a codex` and `pgrep -a claude` must show no other autonomous agent. Only one agent may drive the checkout and the hardware at a time.
5. Compare installed runtime, pending markers and ledger cycles with the repository before acting. Read-only checks that work without a password when `sudo -n` is allowed: `assess` (`sudo -n /usr/bin/python3 -I -B /var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/boot_policy_native.py assess`), the update guard, `ls` of the state directory. A missing local file is not permission to reconstruct authority from documents or to rerun a consumed action.

## 2. Hardware safety rules (summary, `AGENTS.md` is authoritative)

- Never reboot into or restage the failed marker-source UKI `974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd`, the earlier rejected v1 and v2 images, or any replacement-kernel image. Every private UKI preserves the production `.linux` and `.cmdline` byte-for-byte.
- An ordinary boot, a VM pass or a green fixture test is not S4 proof.
- Never repeat a failed or consumed vector under a new label. A consumed guard, a failed attempt, an acceptance file and the EFI stage slots are evidence. Never edit or delete them by hand, and never delete EFI variables by hand. The only sanctioned retirement is the reviewed cleanup tool for a successful vector.
- Do not run privileged Python from the writable workspace. Root steps run the root-owned, review-pinned runtime copy under `/var/lib/omarchy/t2-hibernate-product/runtime` or a verified root-owned export of a reviewed commit.
- Keep physical boot, EFI, module-load and power transitions serialised, one at a time, each with the owner's explicit go at that moment. A prior approval or an automatic goal continuation is not approval.
- Do not copy embedded unlock material, private images or firmware dumps into git, logs or test guests.
- Do not claim completion from fixtures. Use the vocabulary in `docs/t2-suspend/HIBERNATION-GUIDE.md`: implemented, observed, verified, hypothesis, proposed, unvalidated.

## 3. Orchestration pattern

Claude Opus orchestrates and delegates to Claude Sonnet sub-agents with an explicit `model` override and bounded task context. Implementers work in isolated worktrees with explicit, disjoint file ownership. Nothing is integrated until a separate, fresh sub-agent has audited it and the orchestrator has re-run the tests; iterate until the audit passes. Audits have caught real defects (unbounded recovery loops, a guard that would have blocked every update after the first kernel change), so do not skip them for small changes. Parallelise only independent source work. Hardware, EFI and power steps stay with the orchestrator and owner. The main checkout is the live Omarchy (`OMARCHY_PATH` is dev-linked), so sub-agents use worktrees and the main checkout stays clean for `omarchy update`.

## 4. Running the operator scripts

The per-generation operator scripts (for 7.2.7 under `~/.local/state/codex-mba-autonomous/gen-7.2.7/h6e/` and `h6f/`, each with a `RUNBOOK.md`) wrap the reviewed tools with pins and state checks. They are local, not in git. The generalised procedure is `docs/t2-suspend/REQUALIFICATION.md`.

- Run them as the normal user; they call `sudo` per root step. Steps without `--go` or a typed phrase are dry or read-only.
- Typed phrases (for example `EXECUTE-S4-<vector16>`, `REBIND-<manifest12>`) are read from `/dev/tty`. The agent tool shell and the `!` prompt have no tty, so the owner runs those scripts in their own terminal. An agent prepares, dry-runs, reviews and reports; it does not try to satisfy a phrase.
- The auto-mode permission classifier may block root state-changing commands from an agent. That is expected; hand the exact command to the owner rather than looking for a way around it.
- Tools print `+ command` trace lines on stdout; parse the last JSON line.
- Regenerate operator inputs after any reboot (boot-id bound) and after any receipt change (arm, disarm, reset).
- Record outcomes in `RESUME.md` and `EVIDENCE-<kernel>.md`, and add a checkpoint to the local handoff, before starting the next step.

## 5. Code and documentation changes

- Commit atomically; run the hibernation test modules you touched (unittest-style with `python3 -B -m unittest <module>`, script-style directly; some need kernel-source arguments) and `./test/cli` and `./test/shell`. `bin/omarchy-update-t2-hibernation` is covered by `test/shell.d/update-t2-hibernation-test.sh`; new commands follow `agents/skills/command-metadata.md`.
- Runtime files are byte-pinned by review digests. Changing anything inside the runtime inventory needs a reviewed runtime upgrade under maintenance before it reaches the machine; it does not take effect by merging.
- Keep the three documentation trees apart: procedure here, reference in `docs/t2-suspend/`, end-user text in `manual/t2-suspend.md` with no internals. Do not rewrite history in the lab journal; correct stale status lines and add new records.
- When a requalification or hardware run completes, update `RESUME.md` (top section), `EVIDENCE-<kernel>.md` and `docs/t2-suspend/README.md` status together.
