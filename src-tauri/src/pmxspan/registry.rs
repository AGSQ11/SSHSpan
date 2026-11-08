//! The Windows registry reads of PMXSpan discovery: the Uninstall entries
//! and the URL-scheme check. Read only, never written.

use std::path::PathBuf;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

const UNINSTALL: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/// The most Uninstall entries looked at per hive.
const MAX_ENTRIES: u32 = 4096;

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: opened by `open`, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open(parent: HKEY, path: &str) -> Option<Key> {
    let mut key: HKEY = null_mut();
    let path = wide(path);
    // SAFETY: `parent` is predefined or open; `path` is NUL-terminated and
    // outlives the call; `key` is a valid out pointer.
    let status = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, KEY_READ, &mut key) };
    (status == ERROR_SUCCESS).then_some(Key(key))
}

/// A string value of `key` (REG_SZ or REG_EXPAND_SZ, not expanded).
fn string_value(key: &Key, name: &str) -> Option<String> {
    let name = wide(name);
    let mut size: u32 = 0;
    // SAFETY: valid open key, NUL-terminated name; null data asks the size.
    let status = unsafe {
        RegGetValueW(
            key.0,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            null_mut(),
            null_mut(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || size == 0 || size > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    let mut read = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `read` bytes; the call writes at most that.
    let status = unsafe {
        RegGetValueW(
            key.0,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut read,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let units = (read as usize / 2).min(buf.len());
    let text = String::from_utf16_lossy(&buf[..units]);
    Some(text.trim_end_matches('\0').to_string())
}

/// The install directory an Uninstall entry names: `InstallLocation`, else
/// the directory of `DisplayIcon` (`"C:\...\app.exe",0` form tolerated).
fn entry_dir(entry: &Key) -> Option<PathBuf> {
    if let Some(loc) = string_value(entry, "InstallLocation") {
        let loc = loc.trim().trim_matches('"');
        if !loc.is_empty() {
            return Some(PathBuf::from(loc));
        }
    }
    let icon = string_value(entry, "DisplayIcon")?;
    let icon = icon.trim();
    let icon = match icon.rsplit_once(',') {
        Some((path, idx)) if idx.trim().parse::<i32>().is_ok() => path,
        _ => icon,
    };
    PathBuf::from(icon.trim().trim_matches('"'))
        .parent()
        .map(PathBuf::from)
}

/// Install directories of the Uninstall entries (HKCU, then HKLM) whose
/// `DisplayName` is `display_name`.
pub fn install_dirs(display_name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let Some(root) = open(hive, UNINSTALL) else {
            continue;
        };
        let mut name = vec![0u16; 512];
        for index in 0..MAX_ENTRIES {
            let mut len = name.len() as u32;
            // SAFETY: `root` open for reading; `name` holds `len` units.
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                continue;
            }
            let sub = String::from_utf16_lossy(&name[..len as usize]);
            let Some(entry) = open(root.0, &sub) else {
                continue;
            };
            if string_value(&entry, "DisplayName").as_deref() == Some(display_name) {
                if let Some(dir) = entry_dir(&entry) {
                    out.push(dir);
                }
            }
        }
    }
    out
}

/// Whether `HKCU\Software\Classes\<scheme>` or `HKCR\<scheme>` exists with
/// a `URL Protocol` value.
pub fn url_scheme_registered(scheme: &str) -> bool {
    let has_protocol = |key: Option<Key>| {
        key.is_some_and(|k| {
            let name = wide("URL Protocol");
            let mut size = 0u32;
            // SAFETY: valid key and name; size query only.
            let status = unsafe {
                RegGetValueW(
                    k.0,
                    null(),
                    name.as_ptr(),
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                    null_mut(),
                    null_mut(),
                    &mut size,
                )
            };
            status == ERROR_SUCCESS
        })
    };
    has_protocol(open(
        HKEY_CURRENT_USER,
        &format!("Software\\Classes\\{scheme}"),
    )) || has_protocol(open(HKEY_CLASSES_ROOT, scheme))
}
