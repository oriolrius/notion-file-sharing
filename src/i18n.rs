//! User interface languages: Catalan (default), Spanish and English.
//!
//! The web pages pick the language from the `nfs_lang` cookie (set by the selector), else from
//! `Accept-Language`, else Catalan. The CLI prints Catalan messages (`Display`).

use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    Ca,
    Es,
    En,
}

impl Lang {
    pub const ALL: [Lang; 3] = [Lang::Ca, Lang::Es, Lang::En];

    pub fn code(self) -> &'static str {
        match self {
            Lang::Ca => "ca",
            Lang::Es => "es",
            Lang::En => "en",
        }
    }

    /// Label in the selector: the language name in that language.
    pub fn name(self) -> &'static str {
        match self {
            Lang::Ca => "Català",
            Lang::Es => "Español",
            Lang::En => "English",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        match code.trim().to_ascii_lowercase().as_str() {
            "ca" => Some(Lang::Ca),
            "es" => Some(Lang::Es),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// First supported language of an `Accept-Language` header, by quality value.
    pub fn from_accept_language(header: &str) -> Option<Lang> {
        let mut best: Option<(f32, usize, Lang)> = None;
        for (pos, item) in header.split(',').enumerate() {
            let mut parts = item.split(';');
            let tag = parts.next().unwrap_or_default().trim();
            let primary = tag.split('-').next().unwrap_or_default();
            let Some(lang) = Lang::from_code(primary) else {
                continue;
            };
            let q = parts
                .find_map(|p| p.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);
            if q <= 0.0 {
                continue;
            }
            // Higher quality wins; on a tie the earlier entry wins.
            if best.is_none_or(|(bq, bpos, _)| q > bq || (q == bq && pos < bpos)) {
                best = Some((q, pos, lang));
            }
        }
        best.map(|(_, _, l)| l)
    }

    pub fn t(self) -> &'static Texts {
        match self {
            Lang::Ca => &CA,
            Lang::Es => &ES,
            Lang::En => &EN,
        }
    }

    pub fn not_a_file(self, block_type: &str) -> String {
        match self {
            Lang::Ca => format!("aquest bloc ({block_type}) no conté cap fitxer"),
            Lang::Es => format!("este bloque ({block_type}) no contiene ningún archivo"),
            Lang::En => format!("this block ({block_type}) has no file"),
        }
    }

    pub fn notion_rate_limited(self, secs: u64) -> String {
        match self {
            Lang::Ca => {
                format!("Notion està limitant peticions; torna-ho a provar d'aquí a {secs} s")
            }
            Lang::Es => format!(
                "Notion está limitando las peticiones; vuelve a probarlo dentro de {secs} s"
            ),
            Lang::En => format!("Notion limits the requests; try again in {secs} s"),
        }
    }

    pub fn kutt_failed(self, err: &str) -> String {
        match self {
            Lang::Ca => format!("l'escurçador (Kutt) ha fallat: {err}"),
            Lang::Es => format!("el acortador (Kutt) ha fallado: {err}"),
            Lang::En => format!("the URL shortener (Kutt) failed: {err}"),
        }
    }
}

/// Fixed texts of the web pages.
pub struct Texts {
    pub language: &'static str,
    pub logout: &'static str,
    pub footer_short: &'static str,

    pub gen_title: &'static str,
    pub gen_lead: &'static str,
    pub gen_error: &'static str,
    pub url_label: &'static str,
    /// Trusted static HTML (rendered with `|safe`).
    pub url_hint_html: &'static str,
    pub ttl_label: &'static str,
    pub ttl_7d: &'static str,
    pub ttl_30d: &'static str,
    pub ttl_1y: &'static str,
    pub ttl_none: &'static str,
    pub ttl_date: &'static str,
    pub date_aria: &'static str,
    pub options: &'static str,
    pub slug_label: &'static str,
    pub optional: &'static str,
    pub password: &'static str,
    pub generate: &'static str,
    pub busy: &'static str,
    pub ready: &'static str,
    pub to_share: &'static str,
    pub secure_url: &'static str,
    pub copy: &'static str,
    pub copied: &'static str,
    pub file: &'static str,
    pub size: &'static str,
    pub expires: &'static str,
    pub never: &'static str,
    pub yes: &'static str,
    pub js_not_notion: &'static str,
    pub js_no_block: &'static str,
    pub js_detected: &'static str,

    pub pw_title: &'static str,
    pub pw_lead: &'static str,
    pub pw_continue: &'static str,
    pub pw_wrong: &'static str,
    pub pw_too_many: &'static str,

    pub not_found_title: &'static str,
    pub not_found_text: &'static str,
    pub expired_title: &'static str,
    pub expired_text: &'static str,
    pub busy_title: &'static str,
    pub busy_text: &'static str,
    pub temp_title: &'static str,
    pub temp_text: &'static str,
    pub gen_off_title: &'static str,
    pub gen_off_text: &'static str,
    pub csrf_title: &'static str,
    pub csrf_text: &'static str,
    pub login_title: &'static str,
    pub login_unreachable: &'static str,
    pub login_bad_config: &'static str,
    pub login_rejected: &'static str,
    pub login_failed: &'static str,
    pub forbidden_title: &'static str,
    pub forbidden_text: &'static str,

    pub err_ttl: &'static str,
    pub err_date: &'static str,
    pub err_notion_not_found: &'static str,
    pub err_notion: &'static str,
}

pub static CA: Texts = Texts {
    language: "Idioma",
    logout: "surt",
    footer_short: "els enllaços curts són de u.joor.net",
    gen_title: "Nou enllaç",
    gen_lead: "Enganxa l'enllaç al bloc de Notion (vídeo o fitxer) i tria'n la caducitat.",
    gen_error: "No s'ha pogut crear",
    url_label: "Enllaç al bloc de Notion",
    url_hint_html: "A Notion: menú del bloc ⋮⋮ → <i>Copia l'enllaç al bloc</i>.",
    ttl_label: "Caducitat",
    ttl_7d: "7 dies",
    ttl_30d: "30 dies",
    ttl_1y: "1 any",
    ttl_none: "Sense límit",
    ttl_date: "Data…",
    date_aria: "Data de caducitat",
    options: "Opcions",
    slug_label: "Àlies curt",
    optional: "opcional",
    password: "Contrasenya",
    generate: "Genera els enllaços",
    busy: "Generant…",
    ready: "Enllaços a punt",
    to_share: "Per compartir",
    secure_url: "URL segura",
    copy: "Copia",
    copied: "Copiat",
    file: "Fitxer",
    size: "Mida",
    expires: "Caduca",
    never: "mai",
    yes: "sí",
    js_not_notion: "Ha de ser un enllaç https de notion.so o notion.com.",
    js_no_block: "Falta l'identificador del bloc (#…). Copia l'enllaç al bloc, no a la pàgina.",
    js_detected: "Bloc detectat",
    pw_title: "Enllaç protegit",
    pw_lead: "Escriu la contrasenya per descarregar el fitxer.",
    pw_continue: "Continua",
    pw_wrong: "Contrasenya incorrecta.",
    pw_too_many: "Massa intents. Torna-ho a provar d'aquí a uns minuts.",
    not_found_title: "Enllaç no trobat",
    not_found_text: "Aquest enllaç no existeix o no és vàlid.",
    expired_title: "Enllaç caducat",
    expired_text: "Aquest enllaç ha caducat.",
    busy_title: "Torna-ho a provar",
    busy_text: "Servei ocupat. Torna-ho a provar en uns segons.",
    temp_title: "Error temporal",
    temp_text: "No s'ha pogut obtenir el fitxer. Torna-ho a provar.",
    gen_off_title: "Generador desactivat",
    gen_off_text: "Aquest servidor no té el generador actiu.",
    csrf_title: "Sessió caducada",
    csrf_text: "Torna a carregar la pàgina i prova-ho de nou.",
    login_title: "Error d'inici de sessió",
    login_unreachable: "No s'ha pogut contactar el servidor d'identitat.",
    login_bad_config: "Configuració OIDC no vàlida.",
    login_rejected: "El servidor d'identitat ha rebutjat l'inici de sessió.",
    login_failed: "No s'ha pogut completar l'inici de sessió.",
    forbidden_title: "Sense permís",
    forbidden_text: "El teu usuari no pot crear enllaços.",
    err_ttl: "tria una caducitat",
    err_date: "tria la data de caducitat",
    err_notion_not_found: "Notion no troba el bloc: comprova l'enllaç i que la pàgina estigui compartida amb la integració",
    err_notion: "error consultant Notion; torna-ho a provar",
};

pub static ES: Texts = Texts {
    language: "Idioma",
    logout: "salir",
    footer_short: "los enlaces cortos son de u.joor.net",
    gen_title: "Nuevo enlace",
    gen_lead: "Pega el enlace al bloque de Notion (vídeo o archivo) y elige la caducidad.",
    gen_error: "No se ha podido crear",
    url_label: "Enlace al bloque de Notion",
    url_hint_html: "En Notion: menú del bloque ⋮⋮ → <i>Copiar enlace al bloque</i>.",
    ttl_label: "Caducidad",
    ttl_7d: "7 días",
    ttl_30d: "30 días",
    ttl_1y: "1 año",
    ttl_none: "Sin límite",
    ttl_date: "Fecha…",
    date_aria: "Fecha de caducidad",
    options: "Opciones",
    slug_label: "Alias corto",
    optional: "opcional",
    password: "Contraseña",
    generate: "Genera los enlaces",
    busy: "Generando…",
    ready: "Enlaces listos",
    to_share: "Para compartir",
    secure_url: "URL segura",
    copy: "Copiar",
    copied: "Copiado",
    file: "Archivo",
    size: "Tamaño",
    expires: "Caduca",
    never: "nunca",
    yes: "sí",
    js_not_notion: "Debe ser un enlace https de notion.so o notion.com.",
    js_no_block: "Falta el identificador del bloque (#…). Copia el enlace al bloque, no a la página.",
    js_detected: "Bloque detectado",
    pw_title: "Enlace protegido",
    pw_lead: "Escribe la contraseña para descargar el archivo.",
    pw_continue: "Continuar",
    pw_wrong: "Contraseña incorrecta.",
    pw_too_many: "Demasiados intentos. Vuelve a probarlo dentro de unos minutos.",
    not_found_title: "Enlace no encontrado",
    not_found_text: "Este enlace no existe o no es válido.",
    expired_title: "Enlace caducado",
    expired_text: "Este enlace ha caducado.",
    busy_title: "Vuelve a probarlo",
    busy_text: "Servicio ocupado. Vuelve a probarlo dentro de unos segundos.",
    temp_title: "Error temporal",
    temp_text: "No se ha podido obtener el archivo. Vuelve a probarlo.",
    gen_off_title: "Generador desactivado",
    gen_off_text: "Este servidor no tiene el generador activo.",
    csrf_title: "Sesión caducada",
    csrf_text: "Vuelve a cargar la página y prueba de nuevo.",
    login_title: "Error de inicio de sesión",
    login_unreachable: "No se ha podido contactar con el servidor de identidad.",
    login_bad_config: "Configuración OIDC no válida.",
    login_rejected: "El servidor de identidad ha rechazado el inicio de sesión.",
    login_failed: "No se ha podido completar el inicio de sesión.",
    forbidden_title: "Sin permiso",
    forbidden_text: "Tu usuario no puede crear enlaces.",
    err_ttl: "elige una caducidad",
    err_date: "elige la fecha de caducidad",
    err_notion_not_found: "Notion no encuentra el bloque: comprueba el enlace y que la página esté compartida con la integración",
    err_notion: "error al consultar Notion; vuelve a probarlo",
};

pub static EN: Texts = Texts {
    language: "Language",
    logout: "log out",
    footer_short: "short links are from u.joor.net",
    gen_title: "New link",
    gen_lead: "Paste the link to the Notion block (video or file) and choose when it expires.",
    gen_error: "Could not create the link",
    url_label: "Link to the Notion block",
    url_hint_html: "In Notion: block menu ⋮⋮ → <i>Copy link to block</i>.",
    ttl_label: "Expires",
    ttl_7d: "7 days",
    ttl_30d: "30 days",
    ttl_1y: "1 year",
    ttl_none: "No limit",
    ttl_date: "Date…",
    date_aria: "Expiry date",
    options: "Options",
    slug_label: "Short alias",
    optional: "optional",
    password: "Password",
    generate: "Create the links",
    busy: "Creating…",
    ready: "Links ready",
    to_share: "To share",
    secure_url: "Secure URL",
    copy: "Copy",
    copied: "Copied",
    file: "File",
    size: "Size",
    expires: "Expires",
    never: "never",
    yes: "yes",
    js_not_notion: "It must be an https link from notion.so or notion.com.",
    js_no_block: "The block id (#…) is missing. Copy the link to the block, not to the page.",
    js_detected: "Block found",
    pw_title: "Protected link",
    pw_lead: "Enter the password to download the file.",
    pw_continue: "Continue",
    pw_wrong: "Wrong password.",
    pw_too_many: "Too many attempts. Try again in a few minutes.",
    not_found_title: "Link not found",
    not_found_text: "This link does not exist or is not valid.",
    expired_title: "Link expired",
    expired_text: "This link has expired.",
    busy_title: "Try again",
    busy_text: "The service is busy. Try again in a few seconds.",
    temp_title: "Temporary error",
    temp_text: "Could not get the file. Try again.",
    gen_off_title: "Generator disabled",
    gen_off_text: "The link generator is not enabled on this server.",
    csrf_title: "Session expired",
    csrf_text: "Reload the page and try again.",
    login_title: "Login error",
    login_unreachable: "Could not reach the identity server.",
    login_bad_config: "The OIDC configuration is not valid.",
    login_rejected: "The identity server rejected the login.",
    login_failed: "Could not complete the login.",
    forbidden_title: "No permission",
    forbidden_text: "Your user cannot create links.",
    err_ttl: "choose an expiry",
    err_date: "choose the expiry date",
    err_notion_not_found: "Notion cannot find the block: check the link, and that the page is shared with the integration",
    err_notion: "error from Notion; try again",
};

/// Invalid user input to `links.rs` (CLI and web generator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    InvalidDuration(String),
    NonPositiveDuration(String),
    UnknownUnit(String),
    DurationTooLong,
    InvalidDate(String),
    DatePassed,
    NotAUrl,
    NotHttps,
    NotNotion,
    NoBlockId,
    BadBlockId(String),
    BadSlug,
}

impl InputError {
    pub fn msg(&self, lang: Lang) -> String {
        use InputError::*;
        match (lang, self) {
            (Lang::Ca, InvalidDuration(s)) => format!("durada no vàlida: {s}"),
            (Lang::Es, InvalidDuration(s)) => format!("duración no válida: {s}"),
            (Lang::En, InvalidDuration(s)) => format!("duration not valid: {s}"),
            (Lang::Ca, NonPositiveDuration(s)) => format!("la durada ha de ser positiva: {s}"),
            (Lang::Es, NonPositiveDuration(s)) => format!("la duración debe ser positiva: {s}"),
            (Lang::En, NonPositiveDuration(s)) => format!("the duration must be positive: {s}"),
            (Lang::Ca, UnknownUnit(s)) => {
                format!("unitat desconeguda a {s} (fes servir m, h, d, w o y)")
            }
            (Lang::Es, UnknownUnit(s)) => {
                format!("unidad desconocida en {s} (usa m, h, d, w o y)")
            }
            (Lang::En, UnknownUnit(s)) => format!("unknown unit in {s} (use m, h, d, w or y)"),
            (Lang::Ca, DurationTooLong) => "durada massa llarga".into(),
            (Lang::Es, DurationTooLong) => "duración demasiado larga".into(),
            (Lang::En, DurationTooLong) => "duration too long".into(),
            (Lang::Ca, InvalidDate(s)) => format!(
                "data no vàlida: {s} (fes servir +24h, +7d, +1y o 2026-12-31T23:59:59Z)"
            ),
            (Lang::Es, InvalidDate(s)) => format!(
                "fecha no válida: {s} (usa +24h, +7d, +1y o 2026-12-31T23:59:59Z)"
            ),
            (Lang::En, InvalidDate(s)) => format!(
                "date not valid: {s} (use +24h, +7d, +1y or 2026-12-31T23:59:59Z)"
            ),
            (Lang::Ca, DatePassed) => "la data de caducitat ja ha passat".into(),
            (Lang::Es, DatePassed) => "la fecha de caducidad ya ha pasado".into(),
            (Lang::En, DatePassed) => "the expiry date is in the past".into(),
            (Lang::Ca, NotAUrl) => "no és una URL vàlida".into(),
            (Lang::Es, NotAUrl) => "no es una URL válida".into(),
            (Lang::En, NotAUrl) => "not a valid URL".into(),
            (Lang::Ca, NotHttps) => "la URL ha de començar per https://".into(),
            (Lang::Es, NotHttps) => "la URL debe empezar por https://".into(),
            (Lang::En, NotHttps) => "the URL must start with https://".into(),
            (Lang::Ca, NotNotion) => "no és una URL de Notion (notion.so / notion.com)".into(),
            (Lang::Es, NotNotion) => "no es una URL de Notion (notion.so / notion.com)".into(),
            (Lang::En, NotNotion) => "not a Notion URL (notion.so / notion.com)".into(),
            (Lang::Ca, NoBlockId) => {
                "la URL no té l'identificador del bloc (#…): copia l'enllaç al bloc, no a la pàgina"
                    .into()
            }
            (Lang::Es, NoBlockId) => {
                "la URL no tiene el identificador del bloque (#…): copia el enlace al bloque, no a la página"
                    .into()
            }
            (Lang::En, NoBlockId) => {
                "the URL has no block id (#…): copy the link to the block, not to the page".into()
            }
            (Lang::Ca, BadBlockId(f)) => format!("«#{f}» no és un identificador de bloc de Notion"),
            (Lang::Es, BadBlockId(f)) => {
                format!("«#{f}» no es un identificador de bloque de Notion")
            }
            (Lang::En, BadBlockId(f)) => format!("\"#{f}\" is not a Notion block id"),
            (Lang::Ca, BadSlug) => {
                "l'àlies ha de tenir 3–64 caràcters: lletres, xifres, - o _".into()
            }
            (Lang::Es, BadSlug) => {
                "el alias debe tener 3–64 caracteres: letras, cifras, - o _".into()
            }
            (Lang::En, BadSlug) => "the alias must have 3–64 characters: letters, digits, - or _".into(),
        }
    }
}

/// The CLI prints Catalan messages.
impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg(Lang::Ca))
    }
}

impl std::error::Error for InputError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language() {
        assert_eq!(
            Lang::from_accept_language("es-ES,es;q=0.9,en;q=0.8"),
            Some(Lang::Es)
        );
        assert_eq!(
            Lang::from_accept_language("fr-FR,fr;q=0.9,en;q=0.5,ca;q=0.7"),
            Some(Lang::Ca)
        );
        assert_eq!(Lang::from_accept_language("en-US"), Some(Lang::En));
        assert_eq!(Lang::from_accept_language("de, ca;q=0"), None);
        assert_eq!(Lang::from_accept_language(""), None);
        assert_eq!(Lang::from_accept_language("*"), None);
    }

    #[test]
    fn codes_round_trip() {
        for l in Lang::ALL {
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
        assert_eq!(Lang::from_code("fr"), None);
    }
}
