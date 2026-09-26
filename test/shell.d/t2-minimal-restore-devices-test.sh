#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
python3 "$ROOT/packages/t2-suspend/tests/test-minimal-restore-devices.py"
pass "Minimal restore device configuration and independent initramfs audit"
