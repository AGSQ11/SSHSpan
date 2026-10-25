//! The reader: `HKEY_CURRENT_USER` opened for reading only, never written.

use super::{read_value, Fetch, RawSession, RegValue, MAX_SESSIONS, VALUE_NAMES};
use std::collections::HashMap;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
};

/// The most subkeys one listing reads: one more than it lists, so it can
/// tell there were more, and one for PuTTY's template, which is not a
/// session.
const SUBKEYS_READ: usize = MAX_SESSIONS + 2;

/// Room for any key name, so none is ever too long to enumerate (and a
/// session never vanishes from the listing for it): Windows documents
/// 255 characters but creates names of 256 (not 257), which with the NUL
/// would not fit 256 units; and its 16-bit length in bytes caps a name at
/// 32,767 UTF-16 units in any case.
const KEY_NAME_UNITS: usize = 32_768;

/// An open registry key, closed when dropped.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `open` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(units: impl Iterator<Item = u16>) -> Vec<u16> {
    units.chain(std::iter::once(0)).collect()
}

fn os_error(status: WIN32_ERROR) -> std::io::Error {
    std::io::Error::from_raw_os_error(status as i32)
}

/// `path` under `parent`, opened for reading, or the registry's error.
fn open(parent: HKEY, path: &[u16]) -> Result<Key, WIN32_ERROR> {
    let mut key: HKEY = null_mut();
    // SAFETY: `parent` is a predefined key or one open for reading;
    // `path` is NUL-terminated and outlives the call; `key` is a valid
    // place for the handle.
    let status = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, KEY_READ, &mut key) };
    match status {
        ERROR_SUCCESS => Ok(Key(key)),
        error => Err(error),
    }
}

/// The sessions under `HKEY_CURRENT_USER\<subkey>` - at most
/// `MAX_SESSIONS + 2` of them, in the registry's order - each with the
/// values in [`VALUE_NAMES`] it has. No key is no sessions; any other
/// error on it fails the read. Every subkey enumerated is one session, so
/// the cap bounds the enumeration: one that cannot be opened (deleted in
/// between, refused, or a name with an embedded NUL, which opens as
/// another name) has no values and the OS error in `unreadable`.
pub fn read_sessions(subkey: &str) -> std::io::Result<Vec<RawSession>> {
    let sessions = match open(HKEY_CURRENT_USER, &wide(subkey.encode_utf16())) {
        Ok(sessions) => sessions,
        Err(ERROR_FILE_NOT_FOUND) => return Ok(Vec::new()),
        Err(error) => return Err(os_error(error)),
    };
    let mut found = Vec::new();
    let mut name = vec![0u16; KEY_NAME_UNITS];
    for index in 0u32.. {
        if found.len() == SUBKEYS_READ {
            break;
        }
        let mut length = KEY_NAME_UNITS as u32;
        // SAFETY: `sessions.0` is open for reading; `name` holds
        // `length` UTF-16 units; the reserved, class and time pointers
        // are null, which the call allows.
        let status = unsafe {
            RegEnumKeyExW(
                sessions.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        match status {
            ERROR_SUCCESS => {}
            ERROR_NO_MORE_ITEMS => break,
            other => return Err(os_error(other)),
        }
        let key_name = &name[..length as usize];
        let (values, unreadable) = match open(sessions.0, &wide(key_name.iter().copied())) {
            Ok(session) => (values_of(&session), None),
            Err(error) => (HashMap::new(), Some(os_error(error).to_string())),
        };
        found.push(RawSession {
            key_name: String::from_utf16_lossy(key_name),
            values,
            unreadable,
        });
    }
    Ok(found)
}

/// The values in [`VALUE_NAMES`] that `session` has, of the type the
/// listing reads them as.
fn values_of(session: &Key) -> HashMap<String, RegValue> {
    VALUE_NAMES
        .iter()
        .filter_map(|&name| Some((name.to_string(), value_of(session, name)?)))
        .collect()
}

/// The value `name` of `key`, as [`read_value`] reads one.
fn value_of(key: &Key, name: &str) -> Option<RegValue> {
    let name = wide(name.encode_utf16());
    read_value(|| measure(key, &name), |room| fetch(key, &name, room))
}

/// The type and size in bytes of the value `name` (NUL-terminated) of
/// `key`; `None` when it is not there or cannot be read.
fn measure(key: &Key, name: &[u16]) -> Option<(u32, usize)> {
    let mut value_type = 0;
    let mut size = 0u32;
    // SAFETY: `key.0` is open for reading; `name` is NUL-terminated and
    // outlives the call; with no data buffer (null) only the type and
    // the size are written, to valid places.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut value_type,
            null_mut(),
            &mut size,
        )
    };
    (status == ERROR_SUCCESS).then_some((value_type, size as usize))
}

/// The data of the value `name` (NUL-terminated) of `key`, read into
/// `room` bytes - or, when it has grown past them since it was measured,
/// the size it needs now.
fn fetch(key: &Key, name: &[u16], room: usize) -> Fetch {
    let Ok(mut read) = u32::try_from(room) else {
        return Fetch::Failed;
    };
    let mut data = vec![0u8; room];
    let mut value_type = 0;
    // SAFETY: `key.0` is open for reading; `name` is NUL-terminated and
    // outlives the call; `data` holds `read` bytes and the call writes
    // no more than that: for a value that no longer fits it returns
    // ERROR_MORE_DATA (the buffer's contents then undefined, so unused)
    // with the size it needs in `read`.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &mut value_type,
            data.as_mut_ptr(),
            &mut read,
        )
    };
    match status {
        ERROR_SUCCESS => {
            data.truncate(read as usize);
            Fetch::Data { value_type, data }
        }
        ERROR_MORE_DATA => Fetch::Grew {
            size: read as usize,
        },
        _ => Fetch::Failed,
    }
}
