#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: sh scripts/build.sh [Rust target triple]' >&2
    exit 2
fi

cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

if [ "$#" -eq 1 ]; then
    cargo build --locked --release --target "$1"
    BINARY="target/$1/release/secrethunter"
else
    cargo build --locked --release
    BINARY="target/release/secrethunter"
fi

mkdir -p dist
cp "$BINARY" dist/secrethunter
cp "$BINARY" ~/.local/bin/secrethunter
chmod 755 dist/secrethunter
chmod 755 ~/.local/bin/secrethunter

printf '%s\n' "Built $ROOT/dist/secrethunter"
