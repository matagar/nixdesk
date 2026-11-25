#!/usr/bin/env bash
# Firma del APK de NixDesk para Android con la clave propia. Lo usa el flujo
# nixdesk-android.yml. Nunca imprime los secretos ni cae a la firma de depuración:
# si falta algo o no coincide, falla.
#
#   controlar              revisa los cuatro secretos y el almacén, y lo borra
#   preparar <archivo>     lo mismo, deja el almacén y escribe el key.properties
#                          que lee flutter/android/app/build.gradle
#   verificar <apk>        apksigner sobre el APK; la huella del certificado tiene
#                          que ser la del almacén. La deja en el resumen del job
#   limpiar [archivo]      borra el almacén y el key.properties
#
# Entrada (variables de entorno, desde los secretos de Actions):
#   NIXDESK_ANDROID_KEYSTORE_B64        el .jks (o .p12) en base64
#   NIXDESK_ANDROID_KEYSTORE_PASSWORD   clave del almacén
#   NIXDESK_ANDROID_KEY_ALIAS           alias de la clave
#   NIXDESK_ANDROID_KEY_PASSWORD        clave de la clave
set -euo pipefail

orden="${1:-}"
tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
jks="$tmp/nixdesk-android-release.jks"

fallar() {
  echo "::error::$1"
  exit 1
}

controlar_secretos() {
  local faltan=""
  local nombre
  for nombre in NIXDESK_ANDROID_KEYSTORE_B64 NIXDESK_ANDROID_KEYSTORE_PASSWORD \
    NIXDESK_ANDROID_KEY_ALIAS NIXDESK_ANDROID_KEY_PASSWORD; do
    if [ -z "${!nombre:-}" ]; then
      faltan="$faltan $nombre"
    fi
  done
  if [ -n "$faltan" ]; then
    fallar "Faltan secretos de Actions para firmar el APK:$faltan. Se cargan en Settings > Secrets and variables > Actions > Secrets. Sin ellos no se compila (no se usa la firma de depuración)."
  fi
}

armar_almacen() {
  umask 077
  if ! printf '%s' "$NIXDESK_ANDROID_KEYSTORE_B64" | tr -d '[:space:]' | base64 --decode > "$jks" 2>/dev/null; then
    rm -f "$jks"
    fallar "NIXDESK_ANDROID_KEYSTORE_B64 no es base64 válido"
  fi
  if [ ! -s "$jks" ]; then
    rm -f "$jks"
    fallar "NIXDESK_ANDROID_KEYSTORE_B64 decodifica a un archivo vacío"
  fi
  # Clave del almacén y alias. La salida de keytool no se muestra.
  if ! keytool -list -keystore "$jks" -storepass:env NIXDESK_ANDROID_KEYSTORE_PASSWORD \
    -alias "$NIXDESK_ANDROID_KEY_ALIAS" > /dev/null 2>&1; then
    rm -f "$jks"
    fallar "El almacén no abre con NIXDESK_ANDROID_KEYSTORE_PASSWORD o no tiene el alias NIXDESK_ANDROID_KEY_ALIAS (revisar que el secreto no tenga un salto de línea al final)"
  fi
  # Clave de la clave: armar un pedido de certificado obliga a usar la clave privada.
  if ! keytool -certreq -keystore "$jks" -storepass:env NIXDESK_ANDROID_KEYSTORE_PASSWORD \
    -alias "$NIXDESK_ANDROID_KEY_ALIAS" -keypass:env NIXDESK_ANDROID_KEY_PASSWORD > /dev/null 2>&1; then
    rm -f "$jks"
    fallar "La clave privada del alias no abre con NIXDESK_ANDROID_KEY_PASSWORD"
  fi
}

# SHA-256 del certificado (DER) del alias: lo mismo que informa apksigner.
# Deja el resultado en la variable `huella` (sin subshell, para que un fallo corte).
huella=""
calcular_huella() {
  huella="$(keytool -exportcert -keystore "$jks" -storepass:env NIXDESK_ANDROID_KEYSTORE_PASSWORD     -alias "$NIXDESK_ANDROID_KEY_ALIAS" 2>/dev/null | sha256sum | awk '{print $1}')" || huella=""
  # La huella de una entrada vacía quiere decir que keytool no exportó nada.
  if [ "$huella" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
    huella=""
  fi
  if ! printf '%s' "$huella" | grep -Eq '^[0-9a-f]{64}$'; then
    rm -f "$jks"
    fallar "No se pudo leer el certificado del alias"
  fi
}

escribir_propiedades() {
  local destino="$1"
  # Formato de java.util.Properties: se escapan la barra invertida, los controles,
  # el espacio inicial y todo lo que no sea ASCII. La ruta del almacén va absoluta
  # (build.gradle la resuelve con file(), relativa al módulo app).
  NIXDESK_JKS="$jks" NIXDESK_DESTINO="$destino" python3 - <<'PY'
import os
import struct


def escapar(valor):
    salida = []
    for i, c in enumerate(valor):
        if c == "\\":
            salida.append("\\\\")
        elif c == "\n":
            salida.append("\\n")
        elif c == "\r":
            salida.append("\\r")
        elif c == "\t":
            salida.append("\\t")
        elif c == " " and i == 0:
            salida.append("\\ ")
        elif ord(c) < 32 or ord(c) > 126:
            crudo = c.encode("utf-16-be")
            for unidad in struct.unpack(">%dH" % (len(crudo) // 2), crudo):
                salida.append("\\u%04x" % unidad)
        else:
            salida.append(c)
    return "".join(salida)


lineas = [
    "storeFile=" + escapar(os.environ["NIXDESK_JKS"]),
    "storePassword=" + escapar(os.environ["NIXDESK_ANDROID_KEYSTORE_PASSWORD"]),
    "keyAlias=" + escapar(os.environ["NIXDESK_ANDROID_KEY_ALIAS"]),
    "keyPassword=" + escapar(os.environ["NIXDESK_ANDROID_KEY_PASSWORD"]),
]
destino = os.environ["NIXDESK_DESTINO"]
descriptor = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as archivo:
    archivo.write("\n".join(lineas) + "\n")
PY
  test -s "$destino"
  test "$(wc -l < "$destino")" -eq 4
}

# Deja en `herramienta` la ruta de un programa de las build-tools más nuevas del SDK.
herramienta=""
buscar_herramienta() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
  local carpeta
  carpeta="$(ls -d "$sdk"/build-tools/*/ 2>/dev/null | sort -V | tail -n 1 || true)"
  if [ -z "$carpeta" ] || [ ! -x "${carpeta}$1" ]; then
    fallar "No se encontró $1 en $sdk/build-tools"
  fi
  herramienta="${carpeta}$1"
}

case "$orden" in
  controlar)
    controlar_secretos
    armar_almacen
    calcular_huella
    rm -f "$jks"
    echo "Secretos de firma completos. Huella SHA-256 del certificado: $huella"
    ;;

  preparar)
    destino="${2:-}"
    [ -n "$destino" ] || fallar "Uso: nixdesk-android-firma.sh preparar <key.properties>"
    controlar_secretos
    armar_almacen
    calcular_huella
    escribir_propiedades "$destino"
    echo "Almacén de firma listo. Huella SHA-256 del certificado: $huella"
    if [ -n "${GITHUB_ENV:-}" ]; then
      echo "NIXDESK_ANDROID_CERT_SHA256=$huella" >> "$GITHUB_ENV"
    fi
    ;;

  verificar)
    apk="${2:-}"
    [ -f "$apk" ] || fallar "Uso: nixdesk-android-firma.sh verificar <apk>"
    esperada="${NIXDESK_ANDROID_CERT_SHA256:-}"
    printf '%s' "$esperada" | grep -Eq '^[0-9a-f]{64}$' \
      || fallar "Falta NIXDESK_ANDROID_CERT_SHA256 (la deja el paso que prepara la firma)"
    buscar_herramienta apksigner
    apksigner="$herramienta"
    salida="$tmp/nixdesk-apksigner.txt"
    if ! "$apksigner" verify --verbose --print-certs "$apk" > "$salida"; then
      cat "$salida" || true
      fallar "apksigner no pudo verificar la firma del APK"
    fi
    cat "$salida"
    if grep -q 'CN=Android Debug' "$salida"; then
      fallar "El APK quedó firmado con la clave de depuración"
    fi
    # apksigner rotula cada firmante según la versión: "Signer #1 certificate ..." o "V2 Signer: certificate ...".
    # Se cuenta con su propia línea "Number of signers" y se exige que todas las huellas informadas sean la misma.
    if ! grep -q -E '^Number of signers: 1$' "$salida"; then
      fallar "Se esperaba un solo firmante en el APK"
    fi
    if [ "$(grep -E ' certificate SHA-256 digest: ' "$salida" | awk '{print $NF}' | sort -u | wc -l)" != "1" ]; then
      fallar "El APK informa más de un certificado, o ninguno"
    fi
    huella="$(grep -m 1 -E ' certificate SHA-256 digest: ' "$salida" | awk '{print $NF}')"
    if [ "$huella" != "$esperada" ]; then
      fallar "El APK está firmado con otro certificado (APK: $huella; almacén: $esperada)"
    fi
    sujeto="$(grep -m 1 -E ' certificate DN: ' "$salida" | sed -E 's/^.* certificate DN: //')"
    esquemas="$(grep -E '^Verified using v[0-9.]+ scheme .*: true$' "$salida" | sed -E 's/^Verified using (v[0-9.]+) scheme.*/\1/' | tr '\n' ' ')"
    con_dos_puntos="$(printf '%s' "$huella" | tr 'a-f' 'A-F' | sed -E 's/(..)/\1:/g; s/:$//')"
    echo "Firma verificada. Huella SHA-256 del certificado: $huella"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### Firma del APK"
        echo ""
        echo "- Archivo: \`$(basename "$apk")\`"
        echo "- Certificado: \`$sujeto\`"
        echo "- Huella SHA-256 del certificado: \`$huella\`"
        echo "- La misma, como la muestra keytool: \`$con_dos_puntos\`"
        echo "- Esquemas de firma verificados: ${esquemas:-ninguno informado}"
        echo ""
      } >> "$GITHUB_STEP_SUMMARY"
    fi
    rm -f "$salida"
    ;;

  limpiar)
    rm -f "$jks" "$tmp/nixdesk-apksigner.txt"
    if [ -n "${2:-}" ]; then
      rm -f "$2"
    fi
    ;;

  *)
    fallar "Uso: nixdesk-android-firma.sh controlar | preparar <key.properties> | verificar <apk> | limpiar [key.properties]"
    ;;
esac
