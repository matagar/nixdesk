//! Permiso de conexión firmado de NixDesk: verificación del lado del equipo controlado.
//!
//! El panel (servidor de API) decide quién puede conectarse a qué equipo. Quien
//! controla le pide un permiso para ESTA conexión y lo manda en el `LoginRequest`
//! (campo `nixdesk_permiso`); el equipo lo verifica acá antes de mirar la contraseña
//! o cualquier otra forma de aprobación.
//!
//! Formato: `base64(JSON) "." base64(firma)`. La firma es Ed25519 sobre
//! `"nixdesk-permiso-v1\0" + bytes del JSON` tal como llegaron (no se vuelve a
//! serializar). El JSON trae `{v, kid, eq, des, usr, rol, iat, exp}`:
//! `eq` es el ID del equipo controlado y `des` el desafío de la conexión (el
//! `challenge` del mensaje `Hash` que el equipo genera al abrirla).
//!
//! La referencia es `verificarPermiso` de `servidor-api/src/claves.mjs`.
//!
//! Este archivo no depende del resto de la aplicación (solo de `sodiumoxide` y
//! `base64`, que reexporta `hbb_common`, y de `serde_json`), así los flujos de
//! compilación corren sus pruebas en un crate mínimo antes de la compilación larga
//! (`.github/scripts/nixdesk-probar-permiso.sh`).

use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
use hbb_common::sodiumoxide::crypto::sign;

const DOMINIO: &[u8] = b"nixdesk-permiso-v1\0";

/// Segundos que se acepta un permiso después de su `exp`, por el reloj desfasado del equipo.
pub const TOLERANCIA_SEG: i64 = 300;

/// Un permiso real mide unos 300 caracteres; lo que pase de esto no se analiza.
const LARGO_MAXIMO: usize = 2048;

/// Terminal de administrador sin cuenta de Windows: quien controla, con sesión
/// iniciada en el panel, manda este "usuario" en `os_login` en lugar de uno real.
/// El equipo lo acepta solo si la conexión trae un permiso válido con rol `admin`.
/// Lleva asteriscos porque Windows no admite ese carácter en un nombre de usuario:
/// nunca coincide con una cuenta de verdad.
pub const USUARIO_TERMINAL_ADMIN: &str = "*nixdesk-permiso*";

/// Lo que el equipo anota de un permiso válido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datos {
    pub usr: String,
    pub rol: String,
    pub kid: String,
    pub iat: i64,
    pub exp: i64,
}

/// Por qué no vale un permiso. Va al registro del equipo y a la auditoría del
/// panel; a quien se conecta no se le muestra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motivo {
    /// El `LoginRequest` vino sin permiso.
    Falta,
    /// No tiene la forma `base64.base64`, o la firma no mide 64 bytes.
    Formato,
    /// La clave pública compilada no es un base64 de 32 bytes.
    Clave,
    /// La firma no corresponde a esos bytes con esa clave.
    Firma,
    /// La firma vale pero el contenido no es el JSON esperado.
    Json,
    /// `v` no es 1.
    Version,
    /// Es para otro equipo.
    Equipo,
    /// Es para otra conexión.
    Desafio,
    /// Venció hace más que la tolerancia.
    Vencido,
}

impl Motivo {
    pub fn como_texto(&self) -> &'static str {
        match self {
            Motivo::Falta => "falta",
            Motivo::Formato => "formato",
            Motivo::Clave => "clave",
            Motivo::Firma => "firma",
            Motivo::Json => "json",
            Motivo::Version => "version",
            Motivo::Equipo => "equipo",
            Motivo::Desafio => "desafio",
            Motivo::Vencido => "vencido",
        }
    }
}

/// Qué hace el equipo con el permiso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modo {
    /// No se mira.
    No,
    /// Se verifica y se deja pasar siempre; si falta o no vale, se registra y se avisa al panel.
    Aviso,
    /// Sin permiso válido se rechaza el inicio de sesión.
    Exigir,
}

impl Modo {
    pub fn como_texto(&self) -> &'static str {
        match self {
            Modo::No => "no",
            Modo::Aviso => "aviso",
            Modo::Exigir => "exigir",
        }
    }
}

/// Modo vigente: el compilado (`no`, `aviso`, `exigir`), que la opción del equipo
/// `nixdesk-exigir-permiso` (`N`, `aviso`, `Y`) puede bajar o subir. Sin clave
/// pública compilada no hay con qué verificar y el modo es `No`, diga lo que diga
/// la opción.
pub fn modo_efectivo(compilado: &str, clave_publica_b64: &str, opcion: &str) -> Modo {
    if clave_publica_b64.is_empty() {
        return Modo::No;
    }
    match opcion.trim() {
        "Y" | "y" => Modo::Exigir,
        "N" | "n" => Modo::No,
        "aviso" => Modo::Aviso,
        _ => match compilado {
            "no" => Modo::No,
            "exigir" => Modo::Exigir,
            _ => Modo::Aviso,
        },
    }
}

/// Verifica un permiso. `id_propio` es el ID de este equipo, `desafio` el de esta
/// conexión y `ahora` la hora del equipo en segundos desde 1970.
pub fn verificar(
    permiso: &str,
    clave_publica_b64: &str,
    id_propio: &str,
    desafio: &str,
    ahora: i64,
) -> Result<Datos, Motivo> {
    if permiso.is_empty() {
        return Err(Motivo::Falta);
    }
    if permiso.len() > LARGO_MAXIMO {
        return Err(Motivo::Formato);
    }
    let mut partes = permiso.split('.');
    let (cuerpo, firma) = match (partes.next(), partes.next(), partes.next()) {
        (Some(c), Some(f), None) if !c.is_empty() && !f.is_empty() => (c, f),
        _ => return Err(Motivo::Formato),
    };
    let cuerpo = STANDARD.decode(cuerpo).map_err(|_| Motivo::Formato)?;
    let firma = STANDARD.decode(firma).map_err(|_| Motivo::Formato)?;
    if firma.len() != sign::SIGNATUREBYTES {
        return Err(Motivo::Formato);
    }
    let clave = STANDARD
        .decode(clave_publica_b64)
        .ok()
        .and_then(|k| sign::PublicKey::from_slice(&k))
        .ok_or(Motivo::Clave)?;

    // Forma combinada de libsodium: firma seguida del mensaje firmado.
    let mut firmado = Vec::with_capacity(firma.len() + DOMINIO.len() + cuerpo.len());
    firmado.extend_from_slice(&firma);
    firmado.extend_from_slice(DOMINIO);
    firmado.extend_from_slice(&cuerpo);
    if sign::verify(&firmado, &clave).is_err() {
        return Err(Motivo::Firma);
    }

    // Recién con la firma verificada se interpreta el contenido.
    let d: serde_json::Value = serde_json::from_slice(&cuerpo).map_err(|_| Motivo::Json)?;
    let texto = |k: &str| d.get(k).and_then(|x| x.as_str());
    if d.get("v").and_then(|x| x.as_i64()) != Some(1) {
        return Err(Motivo::Version);
    }
    // Un ID o un desafío vacíos de este lado no pueden coincidir con nada.
    if id_propio.is_empty() || texto("eq") != Some(id_propio) {
        return Err(Motivo::Equipo);
    }
    if desafio.is_empty() || texto("des") != Some(desafio) {
        return Err(Motivo::Desafio);
    }
    let exp = d.get("exp").and_then(|x| x.as_i64()).ok_or(Motivo::Json)?;
    if exp.saturating_add(TOLERANCIA_SEG) < ahora {
        return Err(Motivo::Vencido);
    }
    Ok(Datos {
        usr: texto("usr").unwrap_or_default().to_owned(),
        rol: texto("rol").unwrap_or_default().to_owned(),
        kid: texto("kid").unwrap_or_default().to_owned(),
        iat: d.get("iat").and_then(|x| x.as_i64()).unwrap_or_default(),
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector de `servidor-api/pruebas/vector-permiso.json` (clave de prueba: la
    // privada se descartó al generarlo).
    const CLAVE: &str = "mT2twxZd9+e+DBiT8ttrM8EIOtmDiGVAnw1iguywEiA=";
    const EQUIPO: &str = "111111111";
    const DESAFIO: &str = "aB3xY9";
    const EXP: i64 = 1795392120;
    const CUERPO: &str = "eyJ2IjoxLCJraWQiOiI5YTgxYWYwMCIsImVxIjoiMTExMTExMTExIiwiZGVzIjoiYUIzeFk5IiwidXNyIjoibW9yYWxlcyIsInJvbCI6ImR1ZW5vIiwiaWF0IjoxNzk1MzkyMDAwLCJleHAiOjE3OTUzOTIxMjB9";
    const FIRMA: &str = "VwaGWrKLgX/4+kCfe+liBpEe4nwR+p/VFr5RYB+rA9YlITotJdFCKAGscBNwX/GszK/Djw1tAdwWCw5j9hHRBw==";
    // La clave pública de producción: otra clave válida, que no firmó el vector.
    const OTRA_CLAVE: &str = "zvH+7vUHKWQpfdK+/Vcm8yZpDE550swJ++sHbnveuqo=";

    fn permiso() -> String {
        format!("{CUERPO}.{FIRMA}")
    }

    #[test]
    fn valido() {
        let d = verificar(&permiso(), CLAVE, EQUIPO, DESAFIO, EXP - 60).unwrap();
        assert_eq!(
            d,
            Datos {
                usr: "morales".to_owned(),
                rol: "dueno".to_owned(),
                kid: "9a81af00".to_owned(),
                iat: 1795392000,
                exp: EXP,
            }
        );
    }

    #[test]
    fn otro_equipo() {
        assert_eq!(
            verificar(&permiso(), CLAVE, "222222222", DESAFIO, EXP),
            Err(Motivo::Equipo)
        );
        assert_eq!(
            verificar(&permiso(), CLAVE, "", DESAFIO, EXP),
            Err(Motivo::Equipo)
        );
    }

    #[test]
    fn otro_desafio() {
        assert_eq!(
            verificar(&permiso(), CLAVE, EQUIPO, "aB3xY8", EXP),
            Err(Motivo::Desafio)
        );
        // Distingue mayúsculas: tiene que ser el mismo texto.
        assert_eq!(
            verificar(&permiso(), CLAVE, EQUIPO, "ab3xy9", EXP),
            Err(Motivo::Desafio)
        );
        assert_eq!(
            verificar(&permiso(), CLAVE, EQUIPO, "", EXP),
            Err(Motivo::Desafio)
        );
    }

    #[test]
    fn vencimiento_y_tolerancia() {
        // Vencido pero dentro de la tolerancia: vale.
        assert!(verificar(&permiso(), CLAVE, EQUIPO, DESAFIO, EXP + 1).is_ok());
        assert!(verificar(&permiso(), CLAVE, EQUIPO, DESAFIO, EXP + TOLERANCIA_SEG).is_ok());
        assert_eq!(
            verificar(&permiso(), CLAVE, EQUIPO, DESAFIO, EXP + TOLERANCIA_SEG + 1),
            Err(Motivo::Vencido)
        );
        // Un equipo con el reloj atrasado lo acepta igual: `iat` no se mira.
        assert!(verificar(&permiso(), CLAVE, EQUIPO, DESAFIO, 0).is_ok());
    }

    #[test]
    fn firma_alterada() {
        // Otra firma de 64 bytes, bien formada.
        let otra = FIRMA.replacen("VwaG", "VwaH", 1);
        assert_eq!(
            verificar(&format!("{CUERPO}.{otra}"), CLAVE, EQUIPO, DESAFIO, EXP),
            Err(Motivo::Firma)
        );
        let ceros = STANDARD.encode([0u8; 64]);
        assert_eq!(
            verificar(&format!("{CUERPO}.{ceros}"), CLAVE, EQUIPO, DESAFIO, EXP),
            Err(Motivo::Firma)
        );
    }

    #[test]
    fn json_alterado() {
        // El mismo JSON con otro usuario y con otro equipo, sin volver a firmar.
        let json = String::from_utf8(STANDARD.decode(CUERPO).unwrap()).unwrap();
        for (de, a, equipo) in [
            ("morales", "moralez", EQUIPO),
            ("\"rol\":\"dueno\"", "\"rol\":\"admin\"", EQUIPO),
            ("111111111", "222222222", "222222222"),
            ("1795392120", "1995392120", EQUIPO),
        ] {
            let cambiado = json.replacen(de, a, 1);
            assert_ne!(cambiado, json);
            let cuerpo = STANDARD.encode(cambiado);
            assert_eq!(
                verificar(&format!("{cuerpo}.{FIRMA}"), CLAVE, equipo, DESAFIO, EXP),
                Err(Motivo::Firma)
            );
        }
        // Los mismos datos serializados distinto (un espacio de más) tampoco valen:
        // se firman los bytes, no los datos.
        let cuerpo = STANDARD.encode(json.replacen("{", "{ ", 1));
        assert_eq!(
            verificar(&format!("{cuerpo}.{FIRMA}"), CLAVE, EQUIPO, DESAFIO, EXP),
            Err(Motivo::Firma)
        );
    }

    #[test]
    fn formato_roto() {
        assert_eq!(
            verificar("", CLAVE, EQUIPO, DESAFIO, EXP),
            Err(Motivo::Falta)
        );
        let firma_corta = STANDARD.encode([7u8; 63]);
        let largo = "A".repeat(LARGO_MAXIMO + 1);
        for roto in [
            CUERPO.to_owned(),
            format!("{CUERPO}."),
            format!(".{FIRMA}"),
            ".".to_owned(),
            format!("{CUERPO}.{FIRMA}.{FIRMA}"),
            format!("{CUERPO}.{FIRMA}."),
            format!("{CUERPO} {FIRMA}"),
            format!("{CUERPO}.no es base64"),
            format!("***.{FIRMA}"),
            format!("{CUERPO}.{firma_corta}"),
            format!("{}.{FIRMA}", CUERPO.trim_end_matches('9')),
            largo,
        ] {
            assert_eq!(
                verificar(&roto, CLAVE, EQUIPO, DESAFIO, EXP),
                Err(Motivo::Formato),
                "{roto}"
            );
        }
    }

    #[test]
    fn clave_equivocada() {
        assert_eq!(
            verificar(&permiso(), OTRA_CLAVE, EQUIPO, DESAFIO, EXP),
            Err(Motivo::Firma)
        );
        let corta = STANDARD.encode([1u8; 31]);
        for mala in ["", "no es base64", "AAAA", corta.as_str()] {
            assert_eq!(
                verificar(&permiso(), mala, EQUIPO, DESAFIO, EXP),
                Err(Motivo::Clave),
                "{mala}"
            );
        }
    }

    #[test]
    fn modo() {
        // Sin clave no se mira nunca.
        assert_eq!(modo_efectivo("exigir", "", "Y"), Modo::No);
        // Sin opción en el equipo vale el modo compilado.
        assert_eq!(modo_efectivo("no", CLAVE, ""), Modo::No);
        assert_eq!(modo_efectivo("aviso", CLAVE, ""), Modo::Aviso);
        assert_eq!(modo_efectivo("exigir", CLAVE, ""), Modo::Exigir);
        // Un modo compilado desconocido queda en aviso.
        assert_eq!(modo_efectivo("", CLAVE, ""), Modo::Aviso);
        // La opción del equipo sube o baja el compilado.
        assert_eq!(modo_efectivo("aviso", CLAVE, "Y"), Modo::Exigir);
        assert_eq!(modo_efectivo("no", CLAVE, "Y"), Modo::Exigir);
        assert_eq!(modo_efectivo("exigir", CLAVE, "aviso"), Modo::Aviso);
        assert_eq!(modo_efectivo("exigir", CLAVE, "N"), Modo::No);
        // Un valor que no se entiende no cambia nada.
        assert_eq!(modo_efectivo("exigir", CLAVE, "quizas"), Modo::Exigir);
    }
}
