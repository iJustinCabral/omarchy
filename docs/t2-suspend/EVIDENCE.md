# T2 hibernation evidence summary

A short, honest statement of what was demonstrated. The full records are on branch `fix-t2-vintage-mac-support` (`docs/t2-suspend/HIBERNATION.md`, `RESUME.md`, `docs/t2-suspend/evidence/`). Raw archives stay on that machine and that branch; identifiers are recorded in EVIDENCE-7.2.7.md.

## Demonstrated on one MacBookAir9,1, kernel 7.2.6

- Three real S4 cycles through the normal desktop and logind path restored the original session on the same boot with the private source/restore pair: two on AC power, and one attended battery-only cycle. Each cycle archived its evidence, retired its stage slots and reconciled without failed units.
- An ordinary boot of the source image selected by the persistent default passed full admission between the AC cycles.
- The update-survival lifecycle (maintenance, guard, assess, reactivate) was implemented, independently audited, exercised in a disposable virtual machine against real `pacman` transactions including a kernel update, and deployed on that machine.

## 7.2.7 generation (2026-09-29 and 2026-09-30)

The first `omarchy update` from 7.2.6 to 7.2.7 went through the guard as designed: hibernation stayed off, `assess` reported `requalification-required`, and the same update exposed a defect in an interim radio driver package on the working branch (a partial BCE replacement that disabled internal input), since replaced by a radio-only package. The radio package in this stack never touches the BCE family.

Hibernation was then requalified on 7.2.7 through the attended campaign in [REQUALIFICATION.md](REQUALIFICATION.md): ordinary source and restore boots, `test_resume`, a cold-power S4 vector, a generation trial cycle, qualification, `rebind` and a routine S4 through `omarchy system hibernate`, with physical keyboard and trackpad input confirmed. The gate-by-gate record, with boot, vector and cycle identifiers, is [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md).

## Not established

- Other Mac models or other kernels without their own requalification.
- A deliberate battery-only cycle on 7.2.7, low-reserve behavior, power-source transitions or a measured endurance policy.
- Long-term reliability or a soak; unattended operation, automatic requalification or automatic enablement.
- The interactive `omarchy update` prompts on hardware (shell tests only).
- A clean-installation deployment of the runtime and private pair on a fresh machine.
- An unexplained lock-screen input incident on 2026-09-30, recorded as open in [EVIDENCE-7.2.7.md](EVIDENCE-7.2.7.md).
