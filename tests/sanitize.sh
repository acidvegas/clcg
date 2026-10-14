#!/bin/sh
# Build clcg and the library tests with ASan + UBSan and run every test against them
set -e
cd "$(dirname "$0")/.."
make clean >/dev/null
make CFLAGS="-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra" clcg tests/libtest examples
tests/libtest
python3 tests/test.py
make clean >/dev/null
make >/dev/null
