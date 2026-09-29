# T2 hibernation evidence summary

A short, honest statement of what was demonstrated. The full records are on branch `fix-t2-vintage-mac-support` (`docs/t2-suspend/HIBERNATION.md`, `RESUME.md`, `docs/t2-suspend/evidence/`). Cycle identifiers and raw archives stay on that machine and that branch, not in this pull request.

## Demonstrated on one MacBookAir9,1, kernel 7.2.6

- Three real S4 cycles through the normal desktop and logind path restored the original session on the same boot with the private source/restore pair: two on AC power, and one attended battery-only cycle. Each cycle archived its evidence, retired its stage slots and reconciled without failed units.
- An ordinary boot of the source image selected by the persistent default passed full admission between the AC cycles.
- The update-survival lifecycle (maintenance, guard, assess, reactivate) was implemented, independently audited, exercised in a disposable virtual machine against real `pacman` transactions including a kernel update, and deployed on that machine.

## What happened next

The first `omarchy update` from 7.2.6 to 7.2.7 went through the guard as designed: hibernation stayed off, `assess` reported that the qualified generation changed, and requalification is required. The same update exposed a defect in an interim radio driver package on the working branch (a partial BCE replacement that disabled internal input); it was replaced there by a radio-only package. The radio package in this stack is radio-only from the start and never touches the BCE family.

The candidate stack has since been rebased onto the 7.2.7 t2bce (offline source, patch and harness checks only; no hardware S4 exists for 7.2.7). Requalification on 7.2.7 is pending an attended test. Until it completes, nothing in this pull request claims hibernation on 7.2.7.

## Not established

- Other Mac models or other kernels without their own requalification.
- Long-term reliability, unattended operation or automatic enablement.
- Low-reserve behavior, power-source transitions or a measured battery and endurance policy.
- A clean-installation deployment of the runtime and private pair on a fresh machine.
