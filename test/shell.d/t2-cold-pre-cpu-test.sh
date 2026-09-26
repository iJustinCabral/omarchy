#!/bin/bash

set -euo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

python3 "$ROOT/packages/t2-suspend/experiments/hibernate-cold-pre-cpu/test-offline.py"
pass "Cold pre-CPU diagnostic callback and initramfs recovery contracts"
