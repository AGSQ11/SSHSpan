//! Quick connect's ephemeral servers (INTEGRATION-SPEC section 6).
//!
//! A Quick connect that is not saved still needs a server record for the
//! tab's whole life - Reconnect, Restart, New session, Files and Split all
//! resolve a server id. Those records live here, in memory only: keyed by a
//! random id that starts with [`EPHEMERAL_PREFIX`], never written to SQLite,
//! and cleared on every vault lock. A password typed in the dialog is kept
//! with its record (zeroized when the record goes) and never sealed or
//! stored. The renderer forgets a record when the last tab using it closes.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::db::ServerRecord;
use crate::ssh_client::HostKeyProposal;

/// Every ephemeral id starts with this, so a command can tell one from a
/// saved server's UUID without a lookup (bookmarks and per-server settings
/// are never written for one).
pub const EPHEMERAL_PREFIX: &str = "quick-";

/// The most ephemeral servers at once: a renderer cannot grow this without
/// bound.
pub const MAX_EPHEMERAL: usize = 256;

/// One ephemeral server.
#[derive(Clone)]
pub struct EphemeralServer {
    pub record: ServerRecord,
    /// The password typed in the Quick connect dialog, for this record's
    /// lifetime only.
    pub password: Option<Zeroizing<String>>,
    /// Host keys a `connect` link proposed for it.
    pub proposal: Option<HostKeyProposal>,
}

/// Whether `id` names an ephemeral server.
pub fn is_ephemeral_id(id: &str) -> bool {
    id.starts_with(EPHEMERAL_PREFIX)
}

/// Tauri-managed registry of the ephemeral servers.
#[derive(Default)]
pub struct EphemeralRegistry(Mutex<HashMap<String, EphemeralServer>>);

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, EphemeralServer>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register `server` under a fresh random id (which is written into its
    /// record) and return the id. Refused when [`MAX_EPHEMERAL`] are held.
    pub fn insert(&self, mut server: EphemeralServer) -> Result<String, String> {
        let mut map = self.map();
        if map.len() >= MAX_EPHEMERAL {
            return Err("Too many Quick connect sessions are open - close some tabs first.".into());
        }
        let id = format!("{EPHEMERAL_PREFIX}{}", uuid::Uuid::new_v4().simple());
        server.record.id = id.clone();
        map.insert(id.clone(), server);
        Ok(id)
    }

    /// A copy of the server registered under `id`.
    pub fn get(&self, id: &str) -> Option<EphemeralServer> {
        self.map().get(id).cloned()
    }

    /// Forget `id` (its password is zeroized as it drops). True when it was
    /// there.
    pub fn remove(&self, id: &str) -> bool {
        self.map().remove(id).is_some()
    }

    /// Vault lock: forget every ephemeral server.
    pub fn clear(&self) {
        self.map().clear();
    }

    pub fn len(&self) -> usize {
        self.map().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ServerRecord {
        let now = chrono::Utc::now();
        ServerRecord {
            id: String::new(),
            name: "u@h".into(),
            host: "h.example".into(),
            port: 22,
            username: "u".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: None,
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: now,
            updated_at: now,
            bitwarden_id: None,
            bitwarden_revision_ts: None,
            bitwarden_updated_at: None,
        }
    }

    fn server(pw: &str) -> EphemeralServer {
        EphemeralServer {
            record: record(),
            password: Some(Zeroizing::new(pw.into())),
            proposal: None,
        }
    }

    #[test]
    fn ids_are_random_prefixed_and_resolve_until_removed() {
        let reg = EphemeralRegistry::new();
        let a = reg.insert(server("one")).unwrap();
        let b = reg.insert(server("two")).unwrap();
        assert_ne!(a, b);
        assert!(is_ephemeral_id(&a) && is_ephemeral_id(&b));
        assert!(!is_ephemeral_id("0f6c1d1e-5c1b-4c43-9d8a-1f2e3d4c5b6a"));
        let got = reg.get(&a).unwrap();
        assert_eq!(got.record.id, a, "the record carries its id");
        assert_eq!(got.password.as_deref().map(String::as_str), Some("one"));
        assert!(reg.remove(&a));
        assert!(reg.get(&a).is_none(), "unresolvable after close");
        assert!(!reg.remove(&a));
        assert!(reg.get(&b).is_some());
    }

    #[test]
    fn a_lock_clears_every_ephemeral_server() {
        let reg = EphemeralRegistry::new();
        let ids: Vec<String> = (0..3).map(|_| reg.insert(server("pw")).unwrap()).collect();
        assert_eq!(reg.len(), 3);
        reg.clear();
        assert!(reg.is_empty());
        for id in ids {
            assert!(reg.get(&id).is_none());
        }
    }

    #[test]
    fn the_registry_is_bounded() {
        let reg = EphemeralRegistry::new();
        for _ in 0..MAX_EPHEMERAL {
            reg.insert(server("pw")).unwrap();
        }
        assert!(reg.insert(server("pw")).is_err());
    }
}
