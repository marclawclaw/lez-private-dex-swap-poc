#!/usr/bin/env bash
# Clone LEZ at the pinned dev commit, apply the PoC, run the tests.
#   ./run.sh          # real proofs (slow)
#   DEV=1 ./run.sh    # RISC0_DEV_MODE=1: fake proofs, same execution and boundary checks
set -euo pipefail
LEZ_COMMIT=86df4f6f0a  # logos-execution-zone dev, just before the risc0 3.1 bump (needs r0vm 3.0.x)
HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${LEZ_DIR:-$HERE/logos-execution-zone}
if [ ! -d "$DIR/.git" ]; then
  git clone https://github.com/logos-blockchain/logos-execution-zone.git "$DIR"
fi
cd "$DIR"
if ! git rev-parse -q --verify poc/private-dex-swap >/dev/null; then
  git checkout -b poc/private-dex-swap "$LEZ_COMMIT"
  git -c user.name=poc -c user.email=poc@localhost am "$HERE/patches/0001-poc-private-dex-swap.patch"
else
  git checkout poc/private-dex-swap
fi
if [ "${DEV:-0}" = 1 ]; then export RISC0_DEV_MODE=1; else unset RISC0_DEV_MODE; fi
cargo test --release -p lee --lib -- private_dex_swap --test-threads=1
