#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
require_command python3
python3 "$ROOT/test/shell.d/t2-bluetooth-qualified-unit.py"
pass "qualified Bluetooth gate waits for netdev without requiring connectivity"
