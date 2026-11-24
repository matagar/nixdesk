#!/usr/bin/env bash
# Corre las pruebas unitarias de src/nixdesk_permiso.rs en un crate mínimo, fuera
# del repositorio, para fallar antes de la compilación larga. El módulo solo usa
# sodiumoxide y base64 (por `hbb_common`, que acá es un crate de dos líneas que los
# reexporta) y serde_json. Se parte del Cargo.lock del proyecto para probar con las
# mismas versiones con que se compila.
set -euo pipefail

raiz="$(cd "$(dirname "$0")/../.." && pwd)"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/src" "$dir/hbb_common/src"

cat > "$dir/Cargo.toml" <<'TOML'
[package]
name = "nixdesk-permiso-prueba"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
hbb_common = { path = "hbb_common" }
serde_json = "1.0"
TOML

cat > "$dir/hbb_common/Cargo.toml" <<'TOML'
[package]
name = "hbb_common"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
sodiumoxide = "0.2"
base64 = "0.22"
TOML

printf 'pub use base64;\npub use sodiumoxide;\n' > "$dir/hbb_common/src/lib.rs"
printf 'pub mod nixdesk_permiso;\n' > "$dir/src/lib.rs"
cp "$raiz/src/nixdesk_permiso.rs" "$dir/src/nixdesk_permiso.rs"
cp "$raiz/Cargo.lock" "$dir/Cargo.lock"

cd "$dir"
cargo test nixdesk_permiso
grep -E '^name = "(sodiumoxide|base64|serde_json)"' -A 1 Cargo.lock
