//! PuTTY's saved sessions, read from the Windows registry and turned into
//! servers SSHSpan can save (`putty_list_sessions`).
//!
//! The rules, on every platform, are here; the Windows reader is in
//! `registry.rs`. The tests are in `tests.rs` and, for the real registry,
//! `registry_tests.rs`.
//!
//! Not the PPK key-file parser: that is [`crate::crypto::putty`].

use std::collections::HashMap;

use serde::Serialize;

/// Where PuTTY keeps its saved sessions, under `HKEY_CURRENT_USER`.
pub const SESSIONS_KEY: &str = r"Software\SimonTatham\PuTTY\Sessions";

/// The most sessions one listing reads; `truncated` says there were more.
pub const MAX_SESSIONS: usize = 1_000;

/// A string value with more data than this (UTF-16, its NUL included) is
/// not read: it is [`RegValue::TooLong`]. So a listing holds at most about
/// 40 MiB of strings while it is built (1,002 sessions, five string values
/// each), and what reaches the renderer is far less: names, hosts and user
/// names of at most 256 characters (a skipped session's name cut to 256 and
/// "…"), key file paths of at most 4,095, skip reasons of a line.
pub const MAX_STRING_BYTES: usize = 8 * 1024;

/// One value of a session's registry key: a string (REG_SZ), a number
/// (REG_DWORD), or a string with more than [`MAX_STRING_BYTES`] of data,
/// which is never read - too long, which is not the same as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Str(String),
    Dword(u32),
    TooLong,
}

/// One subkey of [`SESSIONS_KEY`]: its name as stored (escaped by PuTTY)
/// and the values the listing uses, by value name - or, when the subkey
/// could not be opened, no values and why (`unreadable`, the OS error).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawSession {
    pub key_name: String,
    pub values: HashMap<String, RegValue>,
    pub unreadable: Option<String>,
}

/// A saved SSHSpan server, as far as the listing compares it with a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SavedServer<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
}

/// A PuTTY session that can be saved as an SSHSpan server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PuttySession {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub key_file: Option<String>,
    pub auth_method: &'static str,
    pub notes: Vec<&'static str>,
    pub already_saved: bool,
}

/// A PuTTY session that is not offered, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedSession {
    pub name: String,
    pub reason: String,
}

/// What `putty_list_sessions` returns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PuttyListing {
    pub sessions: Vec<PuttySession>,
    pub skipped: Vec<SkippedSession>,
    pub truncated: bool,
}

impl RawSession {
    /// The string value `name`; absent when it is a DWORD.
    fn string(&self, name: &str) -> Option<&str> {
        match self.values.get(name) {
            Some(RegValue::Str(value)) => Some(value),
            _ => None,
        }
    }

    /// The DWORD value `name`; absent when it is a string.
    fn dword(&self, name: &str) -> Option<u32> {
        match self.values.get(name) {
            Some(RegValue::Dword(value)) => Some(*value),
            _ => None,
        }
    }

    /// The boolean `name` the way PuTTY reads one (`gppb_raw`): on when it
    /// is a nonzero DWORD.
    fn flag(&self, name: &str) -> bool {
        self.dword(name).is_some_and(|value| value != 0)
    }

    /// Whether `name` is a string too long to read.
    fn too_long(&self, name: &str) -> bool {
        matches!(self.values.get(name), Some(RegValue::TooLong))
    }
}

/// The session name a registry subkey name stands for. PuTTY escapes a name
/// byte by byte (`escape_registry_key` in its `windows/storage.c`): a space,
/// `\`, `*`, `?`, `%`, every byte below 0x20 or above `~`, and a leading `.`
/// become `%` and two hex digits. Here `%` and two hex digits, in either
/// case, is that byte, and any other `%` is itself. The bytes are UTF-8 in
/// current PuTTY and the system's ANSI code page in older ones: UTF-8 when
/// they are valid UTF-8, else that code page.
pub fn unescape_session_name(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let high = bytes.get(at + 1).and_then(hex_digit);
        let low = bytes.get(at + 2).and_then(hex_digit);
        match (bytes[at], high, low) {
            (b'%', Some(high), Some(low)) => {
                out.push(high << 4 | low);
                at += 3;
            }
            (byte, _, _) => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| legacy_code_page(e.as_bytes()))
}

fn hex_digit(byte: &u8) -> Option<u8> {
    char::from(*byte).to_digit(16).map(|digit| digit as u8)
}

/// A name that is not UTF-8, the way older PuTTY wrote it: in the system's
/// ANSI code page (1250 on Central European systems, 1251, 932, ...). Should
/// Windows not decode it, what is not UTF-8 shows as U+FFFD.
#[cfg(windows)]
fn legacy_code_page(bytes: &[u8]) -> String {
    decode_code_page(bytes, windows_sys::Win32::Globalization::CP_ACP)
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned())
}

/// Off Windows there is no ANSI code page to ask, and only the tests decode
/// names: Windows-1252 stands in for it.
#[cfg(not(windows))]
fn legacy_code_page(bytes: &[u8]) -> String {
    windows_1252(bytes)
}

/// `bytes` decoded with the Windows code page `code_page` (`CP_ACP`: the
/// system's ANSI code page), or `None` when Windows does not decode them.
#[cfg(windows)]
fn decode_code_page(bytes: &[u8], code_page: u32) -> Option<String> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    // The byte count is an `i32` parameter. A session name comes from a
    // registry key name - at most 32,767 UTF-16 units, so at most 98,301
    // bytes of UTF-8, and unescaping only shortens it - so it is nowhere
    // near `i32::MAX`. Checked all the same, for any other caller.
    let length = i32::try_from(bytes.len()).ok()?;
    // SAFETY: `bytes` holds `length` bytes and outlives the call; with no
    // output buffer (null, 0) the call only returns how many UTF-16 units
    // the decoded text needs.
    let needed = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
        )
    };
    let mut units = vec![0u16; usize::try_from(needed).ok().filter(|&n| n > 0)?];
    // SAFETY: as above, and `units` has room for the `needed` UTF-16 units
    // the first call asked for, which is what the call is told it has.
    let written = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            length,
            units.as_mut_ptr(),
            needed,
        )
    };
    units.truncate(usize::try_from(written).ok().filter(|&n| n > 0)?);
    Some(String::from_utf16_lossy(&units))
}

/// Windows-1252 the way the WHATWG Encoding Standard decodes it: 0x80-0x9F
/// are the code page's punctuation and letters (its five unassigned bytes
/// the C1 controls of the same number), every other byte the code point of
/// the same number.
#[cfg(not(windows))]
fn windows_1252(bytes: &[u8]) -> String {
    const FROM_0X80: [char; 32] = [
        '\u{20AC}', '\u{81}', '\u{201A}', '\u{192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{2C6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8D}', '\u{17D}',
        '\u{8F}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}',
        '\u{2014}', '\u{2DC}', '\u{2122}', '\u{161}', '\u{203A}', '\u{153}', '\u{9D}', '\u{17E}',
        '\u{178}',
    ];
    bytes
        .iter()
        .map(|&byte| match byte {
            0x80..=0x9F => FROM_0X80[usize::from(byte - 0x80)],
            _ => char::from(byte),
        })
        .collect()
}

/// PuTTY's template for new sessions, which is not a session.
const TEMPLATE_NAME: &str = "Default Settings";

/// The longest session name listed, in characters.
const MAX_NAME_CHARS: usize = 256;

/// The longest host name listed, in characters (DNS allows 253).
const MAX_HOST_CHARS: usize = 255;

/// The longest user name listed, in characters.
const MAX_USER_CHARS: usize = 256;

/// The longest key file path listed, in characters: as many as a string
/// value of [`MAX_STRING_BYTES`] holds before its NUL.
const MAX_KEY_FILE_CHARS: usize = MAX_STRING_BYTES / 2 - 1;

/// Why a session whose key file path is over [`MAX_KEY_FILE_CHARS`] is
/// skipped.
const KEY_FILE_TOO_LONG: &str = "key file path longer than 4,095 characters";

/// Why a session of another protocol is skipped, when the protocol is not
/// something to show.
const NOT_SSH: &str = "not an SSH session";

/// The longest protocol name a skip reason repeats.
const MAX_PROTOCOL_SHOWN: usize = 32;

fn host_too_long() -> String {
    format!("host name longer than {MAX_HOST_CHARS} characters")
}

fn user_too_long() -> String {
    format!("user name longer than {MAX_USER_CHARS} characters")
}

const HOST_NAME: &str = "HostName";
const PORT_NUMBER: &str = "PortNumber";
const PROTOCOL: &str = "Protocol";
const USER_NAME: &str = "UserName";
const USER_NAME_FROM_ENVIRONMENT: &str = "UserNameFromEnvironment";
const PUBLIC_KEY_FILE: &str = "PublicKeyFile";
const PROXY_METHOD: &str = "ProxyMethod";
const PORT_FORWARDINGS: &str = "PortForwardings";
const AGENT_FWD: &str = "AgentFwd";
const X11_FORWARD: &str = "X11Forward";

/// The values of a session the listing uses: the reader asks for these and
/// no others.
pub const VALUE_NAMES: [&str; 10] = [
    HOST_NAME,
    PORT_NUMBER,
    PROTOCOL,
    USER_NAME,
    USER_NAME_FROM_ENVIRONMENT,
    PUBLIC_KEY_FILE,
    PROXY_METHOD,
    PORT_FORWARDINGS,
    AGENT_FWD,
    X11_FORWARD,
];

/// One session as the server it would be saved as (`already_saved` is left
/// false: [`build_listing`] knows the saved servers), or why it is skipped.
/// The name is checked first, then whether the session could be read at
/// all. Absent values take PuTTY's defaults: the `ssh` protocol, port 22.
pub fn session_from_raw(
    raw: &RawSession,
    local_user: Option<&str>,
) -> Result<PuttySession, SkippedSession> {
    let name = unescape_session_name(&raw.key_name);
    let skip = |reason: String| SkippedSession {
        name: shown_name(&name),
        reason,
    };
    if name.chars().any(char::is_control) {
        return Err(skip("name contains a control character".into()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(skip(format!(
            "name longer than {MAX_NAME_CHARS} characters"
        )));
    }
    if let Some(error) = &raw.unreadable {
        return Err(skip(format!("could not be read ({})", shown(error))));
    }
    if raw.too_long(PROTOCOL) {
        return Err(skip(NOT_SSH.into()));
    }
    // An empty string is no protocol: PuTTY's default, SSH.
    if let Some(protocol) = trimmed(raw.string(PROTOCOL)) {
        if protocol != "ssh" {
            return Err(skip(not_ssh(&protocol)));
        }
    }
    if raw.too_long(HOST_NAME) {
        return Err(skip(host_too_long()));
    }
    let (host_user, host) = split_host_name(raw.string(HOST_NAME).unwrap_or(""));
    let host = stored_host(host).map_err(skip)?;
    let port = match raw.dword(PORT_NUMBER).unwrap_or(0) {
        0 => 22,
        number => u16::try_from(number).map_err(|_| skip("port out of range".into()))?,
    };
    let from_environment = raw.flag(USER_NAME_FROM_ENVIRONMENT);
    let username = match host_user {
        Some(user) => Some(user),
        // A `UserName` too long to read would be used: it is not empty.
        None if raw.too_long(USER_NAME) => return Err(skip(user_too_long())),
        None => trimmed(raw.string(USER_NAME))
            .or_else(|| trimmed(local_user.filter(|_| from_environment))),
    };
    if username
        .as_ref()
        .is_some_and(|user| user.chars().count() > MAX_USER_CHARS)
    {
        return Err(skip(user_too_long()));
    }
    let key_file = trimmed(raw.string(PUBLIC_KEY_FILE));
    if raw.too_long(PUBLIC_KEY_FILE)
        || key_file
            .as_ref()
            .is_some_and(|path| path.chars().count() > MAX_KEY_FILE_CHARS)
    {
        return Err(skip(KEY_FILE_TOO_LONG.into()));
    }
    let auth_method = if key_file.is_some() {
        "publickey"
    } else {
        "password"
    };
    Ok(PuttySession {
        name,
        host,
        port,
        username,
        key_file,
        auth_method,
        notes: notes(raw),
        already_saved: false,
    })
}

/// `value` trimmed, when anything is left.
fn trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// `text` fit to show in a skip: its control characters replaced.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// A skipped session's name as it is shown: [`shown`], and cut to
/// [`MAX_NAME_CHARS`] and "…" when it is longer. A name PuTTY wrote is never
/// longer (Windows creates key names of at most 256 characters, and
/// unescaping only shortens PuTTY's escaping); one with characters other
/// than ASCII in the key as they are, read byte by byte in a code page, can
/// be.
fn shown_name(name: &str) -> String {
    let cut: String = name.chars().take(MAX_NAME_CHARS).collect();
    let ellipsis = if cut.len() < name.len() {
        "\u{2026}"
    } else {
        ""
    };
    format!("{}{ellipsis}", shown(&cut))
}

/// Why a session of another protocol is skipped. The protocol is named when
/// it is something to show.
fn not_ssh(protocol: &str) -> String {
    if protocol.chars().count() <= MAX_PROTOCOL_SHOWN && !protocol.chars().any(char::is_control) {
        format!("{NOT_SSH} ({protocol})")
    } else {
        NOT_SSH.to_string()
    }
}

/// `HostName` the way PuTTY's front end reads it before it connects:
/// trimmed; a user name before the last `@` split off; what follows a
/// colon dropped when the host has exactly one outside square brackets
/// (PuTTY drops it: it is not a port - two or more are an IPv6 address,
/// kept); the spaces and tabs left removed. The user name, if any, and the
/// host.
fn split_host_name(host_name: &str) -> (Option<String>, String) {
    let host_name = host_name.trim();
    let (user, host) = match host_name.rsplit_once('@') {
        Some((user, host)) => (trimmed(Some(user)), host),
        None => (None, host_name),
    };
    let host = without_colon_suffix(host)
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t'))
        .collect();
    (user, host)
}

/// `host` without its colon and what follows when it has exactly one colon
/// outside square brackets; as it is otherwise.
fn without_colon_suffix(host: &str) -> &str {
    let mut depth = 0usize;
    let mut colon = None;
    for (at, c) in host.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => {
                if colon.is_some() {
                    return host;
                }
                colon = Some(at);
            }
            _ => {}
        }
    }
    colon.map_or(host, |at| &host[..at])
}

/// The host as it is saved, or why the session is skipped. An IPv6 address
/// in square brackets loses them: SSHSpan connects with
/// `TcpStream::connect((host, port))`, which takes a bare IPv6 address but
/// not a bracketed one. Anything else with brackets is no host name.
fn stored_host(host: String) -> Result<String, String> {
    if host.is_empty() {
        return Err("no host name".into());
    }
    if host.chars().any(char::is_control) {
        return Err("host name contains a control character".into());
    }
    let host = if host.contains(['[', ']']) {
        match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(inner) if inner.parse::<std::net::Ipv6Addr>().is_ok() => inner.to_string(),
            _ => return Err("bracketed host name is not an IPv6 address".into()),
        }
    } else {
        host
    };
    if host.chars().count() > MAX_HOST_CHARS {
        return Err(host_too_long());
    }
    Ok(host)
}

/// The settings PuTTY uses for the session that SSHSpan does not. Port
/// forwardings too long to read are port forwardings all the same.
fn notes(raw: &RawSession) -> Vec<&'static str> {
    [
        (raw.dword(PROXY_METHOD).is_some_and(|m| m != 0), "proxy"),
        (
            raw.too_long(PORT_FORWARDINGS)
                || raw
                    .string(PORT_FORWARDINGS)
                    .is_some_and(|f| !f.trim().is_empty()),
            "portForwarding",
        ),
        (raw.flag(AGENT_FWD), "agentForwarding"),
        (raw.flag(X11_FORWARD), "x11Forwarding"),
    ]
    .into_iter()
    .filter_map(|(used, note)| used.then_some(note))
    .collect()
}

/// Whether a saved server has the session's account: the same host (ASCII
/// case aside), port and user name - or, for a session without a user name,
/// the same host and port.
fn already_saved(session: &PuttySession, saved: &[SavedServer<'_>]) -> bool {
    saved.iter().any(|server| {
        server.host.trim().eq_ignore_ascii_case(&session.host)
            && server.port == session.port
            && session
                .username
                .as_deref()
                .is_none_or(|user| server.username.trim() == user)
    })
}

/// The order of the listing: by name, case aside.
fn by_name(name: &str) -> (String, String) {
    (name.to_lowercase(), name.to_string())
}

/// The listing of the sessions read (in the reader's order), without
/// PuTTY's template. At most [`MAX_SESSIONS`] of them, the first ones;
/// `truncated` when there were more. Sessions and skipped ones are sorted
/// by name.
pub fn build_listing(
    raw: Vec<RawSession>,
    saved: &[SavedServer<'_>],
    local_user: Option<&str>,
) -> PuttyListing {
    let read: Vec<RawSession> = raw
        .into_iter()
        .filter(|session| unescape_session_name(&session.key_name) != TEMPLATE_NAME)
        .collect();
    let mut sessions = Vec::new();
    let mut skipped = Vec::new();
    for session in read.iter().take(MAX_SESSIONS) {
        match session_from_raw(session, local_user) {
            Ok(session) => sessions.push(PuttySession {
                already_saved: already_saved(&session, saved),
                ..session
            }),
            Err(skip) => skipped.push(skip),
        }
    }
    sessions.sort_by_cached_key(|session| by_name(&session.name));
    skipped.sort_by_cached_key(|skip| by_name(&skip.name));
    PuttyListing {
        sessions,
        skipped,
        truncated: read.len() > MAX_SESSIONS,
    }
}

/// The registry's numbers for a string and a DWORD value.
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

#[cfg(windows)]
const _: () = assert!(
    REG_SZ == windows_sys::Win32::System::Registry::REG_SZ
        && REG_DWORD == windows_sys::Win32::System::Registry::REG_DWORD
);

/// A registry value's data as the listing uses it, the way PuTTY writes
/// them: a REG_SZ string (UTF-16, an odd number of bytes is no string; it
/// ends at its first NUL, the terminating one or an embedded one), too long
/// when it has more than [`MAX_STRING_BYTES`] - whatever it holds, as the
/// reader knows only the size of one it does not read - or a REG_DWORD of
/// exactly 4 bytes. Anything else is absent.
pub fn decode_value(value_type: u32, data: &[u8]) -> Option<RegValue> {
    match value_type {
        REG_SZ if data.len() > MAX_STRING_BYTES => Some(RegValue::TooLong),
        REG_SZ if data.len().is_multiple_of(2) => {
            let (pairs, _) = data.as_chunks::<2>();
            let units: Vec<u16> = pairs
                .iter()
                .map(|&pair| u16::from_le_bytes(pair))
                .take_while(|&unit| unit != 0)
                .collect();
            Some(RegValue::Str(String::from_utf16_lossy(&units)))
        }
        REG_DWORD => <[u8; 4]>::try_from(data)
            .ok()
            .map(|bytes| RegValue::Dword(u32::from_le_bytes(bytes))),
        _ => None,
    }
}

/// The local Windows user name (`USERNAME`), for sessions set to log in as
/// the local user.
pub fn local_user_name() -> Option<String> {
    local_user_from(std::env::var("USERNAME").ok())
}

/// [`local_user_name`] given the variable's value.
fn local_user_from(value: Option<String>) -> Option<String> {
    trimmed(value.as_deref())
}

/// How often a value is measured and read before one that keeps growing in
/// between is given up on.
#[cfg(any(windows, test))]
const READ_ATTEMPTS: usize = 3;

/// What one read of a value's data gave.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fetch {
    /// The data, and the value's type when it was read.
    Data { value_type: u32, data: Vec<u8> },
    /// The value had grown past the room given (ERROR_MORE_DATA): the size
    /// it needed then.
    Grew { size: usize },
    /// Any other error.
    Failed,
}

/// A value the way the reader reads it, with `measure` (its type and size;
/// `None` when it is not there) and `fetch` (its data, into the room given).
/// A string of more than [`MAX_STRING_BYTES`] is too long without being
/// read; another type, or a DWORD that is not 4 bytes, is absent without
/// being read. A value that grows between the two calls (PuTTY rewriting the
/// session) is measured and read again, [`READ_ATTEMPTS`] times in all; if
/// it never holds still, it is too long when it is a string whose last read
/// said it needs more than the cap, else absent.
#[cfg(any(windows, test))]
fn read_value(
    mut measure: impl FnMut() -> Option<(u32, usize)>,
    mut fetch: impl FnMut(usize) -> Fetch,
) -> Option<RegValue> {
    let mut grew = None;
    for _ in 0..READ_ATTEMPTS {
        let (value_type, size) = measure()?;
        match value_type {
            REG_SZ if size > MAX_STRING_BYTES => return Some(RegValue::TooLong),
            REG_SZ => {}
            REG_DWORD if size == 4 => {}
            _ => return None,
        }
        if size == 0 {
            return decode_value(value_type, &[]);
        }
        match fetch(size) {
            Fetch::Data { value_type, data } => return decode_value(value_type, &data),
            Fetch::Grew { size } => grew = Some((value_type, size)),
            Fetch::Failed => return None,
        }
    }
    grew.filter(|&(value_type, size)| value_type == REG_SZ && size > MAX_STRING_BYTES)
        .map(|_| RegValue::TooLong)
}

#[cfg(windows)]
pub use registry::read_sessions;

#[cfg(windows)]
mod registry;

#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod registry_tests;
