//! The reader against the real registry, under a scratch key of the current
//! user's that each test deletes again.

use super::*;
use core::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
    KEY_WRITE, REG_BINARY, REG_DWORD, REG_OPTION_VOLATILE, REG_SZ,
};

// windows-sys declares these only with its Win32_Security (security
// attributes and descriptors) and Win32_Security_Authorization features,
// which this crate does not enable. RegCreateKeyExW always gets null
// security attributes here.
#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        hkey: HKEY,
        lpsubkey: *const u16,
        reserved: u32,
        lpclass: *const u16,
        dwoptions: u32,
        samdesired: u32,
        lpsecurityattributes: *const c_void,
        phkresult: *mut HKEY,
        lpdwdisposition: *mut u32,
    ) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        stringsecuritydescriptor: *const u16,
        stringsdrevision: u32,
        securitydescriptor: *mut *mut c_void,
        securitydescriptorsize: *mut u32,
    ) -> i32;
    fn RegSetKeySecurity(
        hkey: HKEY,
        securityinformation: u32,
        psecuritydescriptor: *mut c_void,
    ) -> u32;
}

const SDDL_REVISION_1: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 4;
/// The access right to change an object's DACL.
const WRITE_DAC: u32 = 0x0004_0000;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    wide(text).into_iter().flat_map(u16::to_le_bytes).collect()
}

/// Whether `HKEY_CURRENT_USER\<path>` exists.
fn key_exists(path: &str) -> bool {
    let path = wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: `path` is NUL-terminated and outlives the call; `key` is a
    // valid place for the handle.
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status == ERROR_SUCCESS {
        // SAFETY: `key` was just opened and is closed once.
        unsafe { RegCloseKey(key) };
    }
    status == ERROR_SUCCESS
}

/// `HKEY_CURRENT_USER\Software\SSHSpan-test-<uuid>`, deleted with
/// everything under it when dropped - also when an assertion fails. Its
/// keys are created volatile, so a test killed before the drop leaves
/// nothing behind past the next sign-out either.
struct ScratchTree(String);

impl ScratchTree {
    fn new() -> Self {
        Self(format!(r"Software\SSHSpan-test-{}", uuid::Uuid::new_v4()))
    }

    fn sessions(&self) -> String {
        format!(r"{}\Sessions", self.0)
    }

    fn session(&self, key_name: &str) -> WriteKey {
        WriteKey::create(&format!(r"{}\{key_name}", self.sessions()))
    }
}

impl Drop for ScratchTree {
    fn drop(&mut self) {
        let path = wide(&self.0);
        // SAFETY: `path` is NUL-terminated and outlives the call.
        unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
    }
}

/// A key created for writing, closed when dropped.
struct WriteKey(HKEY);

impl WriteKey {
    fn create(path: &str) -> Self {
        let path = wide(path);
        let mut key: HKEY = null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call; no class
        // and no security attributes (null); `key` is a valid place for
        // the handle and the disposition is not asked for (null).
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                null(),
                REG_OPTION_VOLATILE,
                KEY_WRITE,
                null(),
                &mut key,
                null_mut(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "RegCreateKeyExW");
        Self(key)
    }

    fn set(&self, name: &str, value_type: u32, data: &[u8]) {
        let name = wide(name);
        let size = u32::try_from(data.len()).unwrap();
        // SAFETY: `self.0` is open for writing; `name` is NUL-terminated
        // and `data` holds `size` bytes, both outliving the call.
        let status =
            unsafe { RegSetValueExW(self.0, name.as_ptr(), 0, value_type, data.as_ptr(), size) };
        assert_eq!(status, ERROR_SUCCESS, "RegSetValueExW");
    }

    fn sz(&self, name: &str, value: &str) {
        self.set(name, REG_SZ, &utf16_bytes(value));
    }

    fn dword(&self, name: &str, value: u32) {
        self.set(name, REG_DWORD, &value.to_le_bytes());
    }
}

impl Drop for WriteKey {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `create` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Give `HKEY_CURRENT_USER\<path>` the DACL in `sddl`. The key is opened
/// for WRITE_DAC only, which its owner holds whatever the DACL says.
fn set_dacl(path: &str, sddl: &str) -> bool {
    let path = wide(path);
    let sddl = wide(sddl);
    let mut key: HKEY = null_mut();
    // SAFETY: `path` is NUL-terminated and outlives the call; `key` is a
    // valid place for the handle.
    let opened = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, WRITE_DAC, &mut key) };
    if opened != ERROR_SUCCESS {
        return false;
    }
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; the
    // descriptor goes to a valid place and its size is not asked for.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } != 0;
    // SAFETY: `key` is open for WRITE_DAC and `descriptor` was just made
    // by the conversion.
    let set = parsed
        && unsafe { RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, descriptor) }
            == ERROR_SUCCESS;
    if parsed {
        // SAFETY: the conversion allocated the descriptor with
        // LocalAlloc; it is freed once.
        unsafe { LocalFree(descriptor) };
    }
    // SAFETY: `key` was opened above and is closed once.
    unsafe { RegCloseKey(key) };
    set
}

/// A session key nobody may read (a protected, empty DACL) until the
/// guard drops. Then its owner - who may always change a DACL, whatever
/// it says - takes full control back, so the scratch tree can be deleted.
/// Declared after the tree, the guard drops before it, also when an
/// assertion fails; and the keys are volatile, so even a test killed in
/// between leaves nothing past the next sign-out.
struct NoReading(String);

impl NoReading {
    fn new(path: String) -> Self {
        assert!(set_dacl(&path, "D:P"), "could not lock {path}");
        Self(path)
    }
}

impl Drop for NoReading {
    fn drop(&mut self) {
        if !set_dacl(&self.0, "D:P(A;;KA;;;OW)") {
            eprintln!(
                "HKEY_CURRENT_USER\\{} keeps its empty DACL: it is volatile and goes \
                 at sign-out, and its owner can still change the DACL",
                self.0
            );
        }
    }
}

/// The sessions of `tree`, the way PuTTY writes them, plus values of the
/// wrong type and ones over the size the reader reads.
fn write_sessions(tree: &ScratchTree) {
    let prod = tree.session("prod%20web");
    prod.sz("HostName", "deploy@10.0.0.5");
    prod.dword("PortNumber", 22);
    prod.sz("Protocol", "ssh");
    prod.sz("UserName", "");
    prod.sz("PublicKeyFile", r"C:\keys\prod.ppk");
    prod.dword("ProxyMethod", 5);
    prod.sz("TerminalType", "xterm");
    let no_user = tree.session("no%20user");
    no_user.sz("HostName", "db.example");
    no_user.dword("PortNumber", 2222);
    no_user.sz("Protocol", "ssh");
    no_user.sz("UserName", "");
    no_user.dword("UserNameFromEnvironment", 0);
    no_user.sz("PublicKeyFile", "");
    let from_env = tree.session("env%20user");
    from_env.sz("HostName", "env.example");
    from_env.dword("UserNameFromEnvironment", 1);
    let unicode = tree.session("caf\u{e9}");
    unicode.sz("HostName", "cafe.example");
    let telnet = tree.session("console");
    telnet.sz("HostName", "switch.example");
    telnet.sz("Protocol", "telnet");
    let template = tree.session("Default%20Settings");
    template.sz("HostName", "");
    template.sz("Protocol", "ssh");
    let wrong = tree.session("wrong%20types");
    wrong.sz("HostName", "typed.example");
    wrong.sz("PortNumber", "2222");
    wrong.set("UserName", REG_BINARY, b"root");
    wrong.sz("AgentFwd", "1");
    wrong.set("X11Forward", REG_DWORD, &[1, 0, 0, 0, 0, 0, 0, 0]);
    wrong.set("PortForwardings", REG_SZ, &[0x4c, 0x00, 0x38]);
    let dword_host = tree.session("dword%20host");
    dword_host.dword("HostName", 1);
    let embedded = tree.session("nul%20host");
    embedded.sz("HostName", "nul.example\0ignored");
    let huge = tree.session("huge%20host");
    huge.sz("HostName", &"h".repeat(MAX_STRING_BYTES));
    let huge_user = tree.session("huge%20user");
    huge_user.sz("HostName", "user.example");
    huge_user.sz("UserName", &"u".repeat(MAX_STRING_BYTES));
    let huge_key = tree.session("huge%20key");
    huge_key.sz("HostName", "key.example");
    huge_key.sz("PublicKeyFile", &"k".repeat(MAX_STRING_BYTES));
    let huge_protocol = tree.session("huge%20protocol");
    huge_protocol.sz("HostName", "protocol.example");
    huge_protocol.sz("Protocol", &"p".repeat(MAX_STRING_BYTES));
    let huge_forwardings = tree.session("huge%20forwardings");
    huge_forwardings.sz("HostName", "fwd.example");
    huge_forwardings.sz("PortForwardings", &"L".repeat(MAX_STRING_BYTES));
    // 4,095 characters and the NUL: exactly the 8 KiB read.
    let at_cap = tree.session("cap%20key");
    at_cap.sz("HostName", "cap.example");
    at_cap.sz("PublicKeyFile", &"k".repeat(MAX_STRING_BYTES / 2 - 1));
    let flags = tree.session("nonzero%20flags");
    flags.sz("HostName", "flags.example");
    flags.dword("UserNameFromEnvironment", 3);
    flags.dword("AgentFwd", 2);
    flags.dword("X11Forward", 7);
}

#[test]
fn sessions_are_read_back_from_the_registry() {
    let tree = ScratchTree::new();
    write_sessions(&tree);
    let raw = read_sessions(&tree.sessions()).unwrap();
    let saved = [SavedServer {
        host: "DB.example",
        port: 2222,
        username: "someone",
    }];
    let listing = build_listing(raw, &saved, Some("windows-user"));
    let session = |name: &str, host: &str, port: u16, user: Option<&str>| {
        serde_json::json!({
            "name": name, "host": host, "port": port, "username": user,
            "keyFile": null, "authMethod": "password", "notes": [], "alreadySaved": false,
        })
    };
    let mut no_user = session("no user", "db.example", 2222, None);
    no_user["alreadySaved"] = true.into();
    let prod = serde_json::json!({
        "name": "prod web", "host": "10.0.0.5", "port": 22, "username": "deploy",
        "keyFile": r"C:\keys\prod.ppk", "authMethod": "publickey", "notes": ["proxy"],
        "alreadySaved": false,
    });
    let mut cap_key = session("cap key", "cap.example", 22, None);
    cap_key["keyFile"] = "k".repeat(MAX_STRING_BYTES / 2 - 1).into();
    cap_key["authMethod"] = "publickey".into();
    let mut forwardings = session("huge forwardings", "fwd.example", 22, None);
    forwardings["notes"] = serde_json::json!(["portForwarding"]);
    let mut flags = session("nonzero flags", "flags.example", 22, Some("windows-user"));
    flags["notes"] = serde_json::json!(["agentForwarding", "x11Forwarding"]);
    let skipped = |name: &str, reason: &str| serde_json::json!({ "name": name, "reason": reason });
    assert_eq!(
        serde_json::to_value(&listing).unwrap(),
        serde_json::json!({
            "sessions": [
                session("café", "cafe.example", 22, None),
                cap_key,
                session("env user", "env.example", 22, Some("windows-user")),
                forwardings,
                no_user,
                flags,
                session("nul host", "nul.example", 22, None),
                prod,
                session("wrong types", "typed.example", 22, None),
            ],
            "skipped": [
                skipped("console", "not an SSH session (telnet)"),
                skipped("dword host", "no host name"),
                skipped("huge host", "host name longer than 255 characters"),
                skipped("huge key", "key file path longer than 4,095 characters"),
                skipped("huge protocol", "not an SSH session"),
                skipped("huge user", "user name longer than 256 characters"),
            ],
            "truncated": false,
        })
    );
    let path = tree.0.clone();
    assert!(key_exists(&path));
    drop(tree);
    assert!(!key_exists(&path), "the scratch key is deleted");
}

/// One session that cannot be opened costs the listing that session,
/// not the others.
#[test]
fn a_session_that_cannot_be_opened_is_one_skipped_entry() {
    let tree = ScratchTree::new();
    tree.session("readable").sz("HostName", "ok.example");
    tree.session("locked").sz("HostName", "locked.example");
    let _locked = NoReading::new(format!(r"{}\locked", tree.sessions()));
    let raw = read_sessions(&tree.sessions()).expect("the readable session is read");
    let listing = build_listing(raw, &[], None);
    let names: Vec<&str> = listing.sessions.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["readable"]);
    assert_eq!(listing.skipped.len(), 1, "{listing:?}");
    let skipped = &listing.skipped[0];
    assert_eq!(skipped.name, "locked");
    // The words are in the system's language; the error number is not.
    assert!(
        skipped.reason.starts_with("could not be read (")
            && skipped.reason.ends_with("(os error 5))"),
        "{}",
        skipped.reason
    );
}

#[test]
fn a_missing_key_reads_as_no_sessions() {
    let tree = ScratchTree::new();
    assert_eq!(read_sessions(&tree.sessions()).unwrap(), vec![]);
    drop(WriteKey::create(&tree.sessions()));
    assert_eq!(read_sessions(&tree.sessions()).unwrap(), vec![]);
}

#[test]
fn the_reader_stops_once_a_listing_has_more_than_it_can_show() {
    let tree = ScratchTree::new();
    for i in 0..MAX_SESSIONS + 3 {
        tree.session(&format!("s{i:04}")).sz("HostName", "h");
    }
    let raw = read_sessions(&tree.sessions()).unwrap();
    assert_eq!(
        raw.len(),
        MAX_SESSIONS + 2,
        "one over, and one for the template"
    );
    let listing = build_listing(raw, &[], None);
    assert!(listing.truncated);
    assert_eq!(listing.sessions.len(), MAX_SESSIONS);
}
