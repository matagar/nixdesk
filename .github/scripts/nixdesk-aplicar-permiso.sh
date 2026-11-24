#!/usr/bin/env bash
# Permiso de conexión firmado de NixDesk: deja en src/nixdesk.rs la clave pública
# del panel y el modo con que se compila, tomados de NIXDESK_PERMISO_PUB_KEY y
# NIXDESK_PERMISO_MODO, y controla que el campo del LoginRequest esté en el proto.
# Lo usan los flujos de compilación de NixDesk. Si un valor no es válido o una
# línea ya no coincide, falla.
set -euo pipefail

raiz="$(cd "$(dirname "$0")/../.." && pwd)"
f="$raiz/src/nixdesk.rs"
proto="$raiz/libs/base/protos/message.proto"

modo="${NIXDESK_PERMISO_MODO:-aviso}"
clave="${NIXDESK_PERMISO_PUB_KEY:-}"

case "$modo" in
  no|aviso|exigir) ;;
  *) echo "NIXDESK_PERMISO_MODO tiene que ser no, aviso o exigir (vino: $modo)"; exit 1 ;;
esac

if [ -n "$clave" ]; then
  # Una clave Ed25519 son 32 bytes: en base64, 43 caracteres y un "=".
  if ! printf '%s' "$clave" | grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
    echo "NIXDESK_PERMISO_PUB_KEY tiene que ser el base64 de 32 bytes"
    exit 1
  fi
  bytes=$(printf '%s' "$clave" | base64 --decode | wc -c)
  if [ "$((bytes))" -ne 32 ]; then
    echo "NIXDESK_PERMISO_PUB_KEY no decodifica a 32 bytes"
    exit 1
  fi
fi

# El campo vive en el proto del propio repositorio (libs/base), no en el submódulo.
grep -nE '^[[:space:]]*string nixdesk_permiso = 1001;' "$proto"

# Sin `sed -i`: no se escribe igual en GNU y en macOS.
sed -E \
  -e "s|^(pub const PERMISO_PUB_KEY: &str = \")[^\"]*(\";)|\1${clave}\2|" \
  -e "s|^(pub const PERMISO_MODO: &str = \")[^\"]*(\";)|\1${modo}\2|" \
  "$f" > "$f.nuevo"
mv "$f.nuevo" "$f"
grep -nF "pub const PERMISO_PUB_KEY: &str = \"${clave}\";" "$f"
grep -nF "pub const PERMISO_MODO: &str = \"${modo}\";" "$f"

if [ -z "$clave" ]; then
  echo "Sin clave pública: los equipos no miran permisos (modo efectivo: no)"
else
  echo "Permiso de conexión: modo $modo"
fi
