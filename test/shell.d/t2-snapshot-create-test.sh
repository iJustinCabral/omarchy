#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"

test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT
cc -Wall -Wextra -Werror -O2 "$ROOT/packages/t2-suspend/tests/test-snapshot-create.c" -o "$test_tmp/test-snapshot-create"
"$test_tmp/test-snapshot-create"
cc -Wall -Wextra -Werror -O2 "$ROOT/packages/t2-suspend/tools/snapshot-create.c" -o "$test_tmp/snapshot-create"
if "$test_tmp/snapshot-create" --help >/dev/null 2>&1; then
  fail "snapshot helper requires explicit create-and-discard intent"
fi
pass "snapshot helper builds and rejects implicit execution"
