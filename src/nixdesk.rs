//! Ajustes de fábrica de NixDesk.
//!
//! RustDesk tiene un mecanismo para clientes personalizados: mapas de opciones que
//! se cargan al arrancar (`DEFAULT_SETTINGS`, `OVERWRITE_SETTINGS`, `HARD_SETTINGS`
//! y `BUILTIN_SETTINGS` de `hbb_common::config`). El camino oficial para llenarlos
//! es un `custom.txt` firmado con la clave de RustDesk, que no tenemos; acá se
//! llenan esos mismos mapas directamente, antes de que nadie lea una opción.
//!
//! El servidor de encuentro y su clave pública salen de las constantes de
//! `hbb_common` que el flujo de compilación ya reemplaza (`RENDEZVOUS_SERVERS` y
//! `RS_PUB_KEY`), así que no hay un segundo lugar donde escribirlos.

use base::config::keys;
use hbb_common::config;

/// Servidor de API propio (cuentas, libreta de direcciones, consola).
///
/// El flujo de compilación reemplaza esta línea con el valor de
/// `NIXDESK_API_SERVER`. Vacío significa "sin servidor de API": la aplicación no
/// consulta ninguno (tampoco los de RustDesk) y no muestra el inicio de sesión.
pub const API_SERVER: &str = "";

/// Copia de `API_SERVER` que queda entera dentro del binario. El compilador puede
/// partir una constante corta en valores inmediatos (pasa en macOS x86_64) y
/// entonces el control del flujo, que busca el texto en el binario, no la encuentra.
#[used]
static API_SERVER_EN_EL_BINARIO: &str = API_SERVER;

fn servidor_de_fabrica() -> &'static str {
    config::RENDEZVOUS_SERVERS.first().copied().unwrap_or("")
}

/// Indica si `servidor` (con o sin puerto) es el servidor con el que se compiló.
pub fn es_servidor_de_fabrica(servidor: &str) -> bool {
    let propio = servidor_de_fabrica();
    if propio.is_empty() {
        return false;
    }
    let s = servidor.trim();
    let sin_puerto = match s.rsplit_once(':') {
        Some((host, puerto)) if puerto.chars().all(|c| c.is_ascii_digit()) => host,
        _ => s,
    };
    sin_puerto.eq_ignore_ascii_case(propio)
}

/// Carga los ajustes de fábrica. Se llama desde `load_custom_client`, que corre al
/// principio de todos los procesos (interfaz, servicio, bandeja, conexiones).
pub fn aplicar_ajustes_de_fabrica() {
    static UNA_VEZ: std::sync::Once = std::sync::Once::new();
    UNA_VEZ.call_once(|| {
        // Tema oscuro de entrada. Es un valor por defecto: el usuario puede elegir
        // el claro o "seguir al sistema" en Ajustes y esa elección se respeta.
        config::DEFAULT_LOCAL_SETTINGS
            .write()
            .unwrap()
            .insert(keys::OPTION_THEME.to_owned(), "dark".to_owned());
        // La atribución a RustDesk está en "Acerca de"; no va en la pantalla principal.
        config::BUILTIN_SETTINGS
            .write()
            .unwrap()
            .insert("hide-powered-by-me".to_owned(), "Y".to_owned());
        let servidor = servidor_de_fabrica();
        // Sin compilar con servidor propio (desarrollo sobre el código tal cual)
        // no hay nada que fijar.
        if servidor.is_empty() || crate::common::is_public(servidor) {
            return;
        }
        {
            // Valores por defecto: son los vigentes mientras el usuario no escriba
            // otros, y la interfaz los muestra como tales (Servidor de ID y Key
            // dejan de verse vacíos). Si el usuario borra un campo, vuelve a estos.
            let mut d = config::DEFAULT_SETTINGS.write().unwrap();
            d.insert(
                keys::OPTION_CUSTOM_RENDEZVOUS_SERVER.to_owned(),
                servidor.to_owned(),
            );
            d.insert(keys::OPTION_KEY.to_owned(), config::RS_PUB_KEY.to_owned());
            if !API_SERVER.is_empty() {
                d.insert(keys::OPTION_API_SERVER.to_owned(), API_SERVER.to_owned());
            }
        }
        if API_SERVER.is_empty() {
            // Sin servidor de API no hay cuentas: se ocultan el inicio de sesión, la
            // libreta de direcciones y los grupos, que solo mostrarían errores.
            config::HARD_SETTINGS
                .write()
                .unwrap()
                .insert("disable-account".to_owned(), "Y".to_owned());
        }
    });
}
