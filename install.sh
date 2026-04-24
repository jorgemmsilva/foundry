#!/usr/bin/env bash
set -euo pipefail

FEATURES="native-tls"

for crate in cast forge anvil chisel; do
  echo "Installing $crate..."
  cargo install --path "crates/$crate" --features "$FEATURES"
done

echo "Done. Installed to ~/.cargo/bin/"
