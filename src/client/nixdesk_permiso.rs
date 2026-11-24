//! Permiso de conexión firmado de NixDesk: lado que controla.
//!
//! Cuando el equipo manda su `Hash` (trae el `challenge` de esa conexión), se le
//! pide al servidor de API un permiso para ese equipo y ese desafío, con la sesión
//! iniciada en NixDesk. El permiso viaja en `LoginRequest.nixdesk_permiso`; quien
//! decide qué hacer con él (o sin él) es el equipo (`src/nixdesk_permiso.rs`).
//!
//! No se pide permiso, y el `LoginRequest` va sin él, cuando:
//! - el cliente no se compiló con servidor de API, o tiene configurado otro;
//! - no hay sesión iniciada;
//! - el equipo se alcanza por otro servidor (`id@servidor`) o por IP directa: el
//!   panel no conoce a ese equipo por lo que se escribió;
//! - el equipo no mandó desafío (no pasa con RustDesk ni con NixDesk; no se usa
//!   `salt` en su lugar porque es fijo por equipo y el permiso dejaría de estar
//!   atado a una conexión).

use super::LoginConfigHandler;
use hbb_common::{
    config::{Config, LocalConfig},
    log,
    rendezvous_proto::ConnType,
    tokio::time::{timeout, Duration, Instant},
};
use std::sync::{Arc, RwLock};

/// Tiempo límite del pedido al servidor de API. Mientras tanto la conexión espera.
const ESPERA: Duration = Duration::from_secs(6);

/// Un permiso dura unos minutos. Si hay que volver a mandar el login (reintento
/// de contraseña) y el guardado tiene más que esto, se pide otro.
const RENOVAR: Duration = Duration::from_secs(60);

const SIN_PERMISO: &str = "No tenés permiso para conectarte a ese equipo";

/// El permiso que se obtuvo, con el desafío para el que se pidió.
pub(super) struct Guardado {
    desafio: String,
    permiso: String,
    pedido: Instant,
}

enum Respuesta {
    Permiso(String),
    /// El panel dijo que este usuario no puede entrar a ese equipo (403).
    Denegado(String),
    /// No se pudo obtener (sin respuesta, sesión vencida, error del servidor).
    Nada,
}

impl LoginConfigHandler {
    /// Lo que va en `LoginRequest.nixdesk_permiso`: el permiso guardado si es el
    /// del desafío vigente, o vacío.
    pub(super) fn nixdesk_permiso_para_login(&self) -> String {
        match self.nixdesk_permiso.as_ref() {
            Some(g) if !g.desafio.is_empty() && g.desafio == self.hash.challenge => {
                g.permiso.clone()
            }
            _ => String::new(),
        }
    }
}

fn tipo(conn_type: ConnType) -> &'static str {
    match conn_type {
        ConnType::FILE_TRANSFER => "file-transfer",
        ConnType::PORT_FORWARD | ConnType::RDP => "port-forward",
        ConnType::VIEW_CAMERA => "view-camera",
        ConnType::TERMINAL => "terminal",
        _ => "remote",
    }
}

/// Servidor de API al que pedirle el permiso, o vacío si no corresponde pedirlo.
fn servidor() -> String {
    let compilado = crate::nixdesk::API_SERVER;
    if compilado.is_empty() {
        return String::new();
    }
    let vigente = crate::common::get_api_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    );
    // La sesión iniciada es la del servidor de API vigente. Si no es el compilado,
    // el token no es del panel de NixDesk y no se le manda.
    if vigente.trim_end_matches('/') != compilado.trim_end_matches('/') {
        return String::new();
    }
    compilado.trim_end_matches('/').to_owned()
}

/// Deja en `lc` el permiso para el desafío vigente, pidiéndolo si hace falta.
/// `Err` trae el mensaje para el usuario cuando el panel le negó ese equipo; en
/// cualquier otro caso es `Ok`, con o sin permiso (decide el equipo).
pub(super) async fn actualizar(lc: &Arc<RwLock<LoginConfigHandler>>) -> Result<(), String> {
    // Los datos se copian: el candado no se sostiene durante el pedido.
    let (id, desafio, tipo, vigente) = {
        let lc = lc.read().unwrap();
        let vigente = lc
            .nixdesk_permiso
            .as_ref()
            .map(|g| g.desafio == lc.hash.challenge && g.pedido.elapsed() < RENOVAR)
            .unwrap_or(false);
        let corresponde = lc.other_server.is_none()
            && !crate::common::is_direct_ip_access(&lc.id)
            && !lc.hash.challenge.is_empty();
        if !corresponde {
            return Ok(());
        }
        (
            lc.id.clone(),
            lc.hash.challenge.clone(),
            tipo(lc.conn_type),
            vigente,
        )
    };
    if vigente {
        return Ok(());
    }
    let api = servidor();
    let token = LocalConfig::get_option("access_token");
    if api.is_empty() || token.is_empty() {
        return Ok(());
    }
    match pedir(&api, &token, &id, &desafio, tipo).await {
        Respuesta::Permiso(permiso) => {
            lc.write().unwrap().nixdesk_permiso = Some(Guardado {
                desafio,
                permiso,
                pedido: Instant::now(),
            });
            Ok(())
        }
        Respuesta::Denegado(mensaje) => {
            lc.write().unwrap().nixdesk_permiso = None;
            Err(mensaje)
        }
        // Queda el que hubiera para este desafío: puede seguir vigente.
        Respuesta::Nada => Ok(()),
    }
}

async fn pedir(api: &str, token: &str, id: &str, desafio: &str, tipo: &str) -> Respuesta {
    let url = format!("{api}/api/nixdesk/permiso");
    let cuerpo = serde_json::json!({
        "peer_id": id,
        "desafio": desafio,
        "tipo": tipo,
    })
    .to_string();
    let encabezado = format!("Authorization: Bearer {token}");
    let (estado, texto) = match timeout(
        ESPERA,
        crate::common::post_request_with_status(url, cuerpo, &encabezado),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(err)) => {
            log::warn!("NixDesk: no se pudo pedir el permiso de conexion: {}", err);
            return Respuesta::Nada;
        }
        Err(_) => {
            log::warn!("NixDesk: el servidor de API no contesto el pedido de permiso a tiempo");
            return Respuesta::Nada;
        }
    };
    let json = serde_json::from_str::<serde_json::Value>(&texto).unwrap_or_default();
    let campo = |k: &str| {
        json.get(k)
            .and_then(|x| x.as_str())
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
    };
    match estado {
        200 => match campo("permiso") {
            Some(permiso) => {
                log::info!("NixDesk: permiso de conexion obtenido para {}", id);
                Respuesta::Permiso(permiso.to_owned())
            }
            None => {
                log::warn!("NixDesk: el servidor de API contesto sin permiso");
                Respuesta::Nada
            }
        },
        // Solo vale como negativa del panel si trae su mensaje: un 403 de otro
        // origen (un proxy en el medio) no tiene que frenar la conexión.
        403 if campo("error").is_some() => {
            log::warn!("NixDesk: el panel nego el permiso de conexion para {}", id);
            Respuesta::Denegado(campo("error").unwrap_or(SIN_PERMISO).to_owned())
        }
        _ => {
            // 401: la sesión venció o se cerró desde el panel. Se sigue sin permiso.
            log::warn!(
                "NixDesk: el servidor de API contesto {} al pedido de permiso",
                estado
            );
            Respuesta::Nada
        }
    }
}
