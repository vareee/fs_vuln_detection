#!/usr/bin/env bash
set -euo pipefail

cargo build --release --example memory_usage
memory_binary="${CARGO_TARGET_DIR:-target}/release/examples/memory_usage"

printf 'mode,scenario,count,challenges_per_round,retained_bytes,peak_bytes,transcript_bytes\n'
for rounds in 1 8 32 128; do
    "$memory_binary" full "$rounds" 1
    "$memory_binary" disabled "$rounds" 1
done

for challenges in 2 4 8; do
    "$memory_binary" full 32 "$challenges"
    "$memory_binary" disabled 32 "$challenges"
done

for operations in 1000 10000 100000; do
    "$memory_binary" full "$operations" 1 chain
    "$memory_binary" disabled "$operations" 1 chain
done

for rounds in 32 128 512; do
    "$memory_binary" full "$rounds" 1 rounds
    "$memory_binary" disabled "$rounds" 1 rounds
done
