//! What a received link leaves behind in memory: the link waiting for an
//! unlock (spec section 1 - at most one, for ten minutes, never on disk) and
//! the proposals a validated link handed to a dialog (cleared on lock).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{Bundle, ConnectLink, Origin};

/// How long a link received while the vault is locked is kept for the
/// unlock (spec section 1).
pub const PENDING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long a proposal handed to a dialog stays usable.
pub const PROPOSAL_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// A second delivery of the very same URL within this window is the same
/// link arriving twice (the OS handler and the single-instance forwarder can
/// both deliver it) and is dropped.
pub const DUPLICATE_WINDOW: Duration = Duration::from_secs(3);
/// The most proposals kept at once: a peer that sends links in a loop cannot
/// grow this without bound.
pub const MAX_PROPOSALS: usize = 10_000;

/// A received link, before it is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// The raw URL: parsed again when it is taken (it was valid when it came).
    Url(String),
    /// Why a link was refused, for the renderer's toast.
    Refused(String),
}

/// What a validated link proposes for one host: where it lives in PMXSpan
/// and the host keys PMXSpan read from it. Never a pin by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub origin: Option<Origin>,
    /// Canonical base64 wire-format keys.
    pub host_keys: Vec<String>,
    /// Unix seconds.
    pub rotated_at: Option<i64>,
}

impl Proposal {
    pub fn from_connect(link: &ConnectLink) -> Self {
        Self {
            host: link.host.clone(),
            port: link.port,
            user: link.user.clone(),
            origin: link.origin.clone(),
            host_keys: link.host_keys.clone(),
            rotated_at: link.host_key_rotated,
        }
    }

    pub fn from_bundle_row(bundle: &Bundle, index: usize) -> Option<Self> {
        let row = bundle.hosts.get(index)?;
        if row.problem.is_some() {
            return None;
        }
        Some(Self {
            host: row.host.clone(),
            port: row.port,
            user: row.user.clone(),
            origin: Some(row.origin(&bundle.cluster)),
            host_keys: row.host_keys.iter().map(|k| k.key.clone()).collect(),
            rotated_at: row.host_key_rotated,
        })
    }

    /// The proposed host keys as the host-key check takes them.
    pub fn host_key_proposal(&self) -> Option<crate::ssh_client::HostKeyProposal> {
        (!self.host_keys.is_empty()).then(|| crate::ssh_client::HostKeyProposal {
            keys: self.host_keys.clone(),
            rotated_at: self.rotated_at,
        })
    }
}

/// Tauri-managed state of the handoff.
#[derive(Default)]
pub struct HandoffState {
    pending: Mutex<Option<(Received, Instant)>>,
    recent: Mutex<Option<(String, Instant)>>,
    proposals: Mutex<HashMap<String, (Proposal, Instant)>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl HandoffState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `url` is the same URL as one received less than
    /// [`DUPLICATE_WINDOW`] ago (then it is dropped), recording it.
    pub fn is_duplicate(&self, url: &str, now: Instant) -> bool {
        let mut recent = lock(&self.recent);
        let dup = matches!(&*recent, Some((u, at)) if u == url && now.saturating_duration_since(*at) < DUPLICATE_WINDOW);
        *recent = Some((url.to_string(), now));
        dup
    }

    /// Keep `received` for the renderer; a second link replaces the first
    /// (spec section 1: "drop it ... on a second URL").
    pub fn hold(&self, received: Received, now: Instant) {
        *lock(&self.pending) = Some((received, now));
    }

    /// Whether a link is waiting (and not expired).
    pub fn has_pending(&self, now: Instant) -> bool {
        let mut pending = lock(&self.pending);
        if matches!(&*pending, Some((_, at)) if now.saturating_duration_since(*at) >= PENDING_LIFETIME)
        {
            *pending = None;
        }
        pending.is_some()
    }

    /// Whether the waiting link is a refusal (shown at once, locked or not).
    pub fn pending_is_refusal(&self) -> bool {
        matches!(&*lock(&self.pending), Some((Received::Refused(_), _)))
    }

    /// Take the waiting link, unless it is older than [`PENDING_LIFETIME`]
    /// (then it is dropped).
    pub fn take(&self, now: Instant) -> Option<Received> {
        let taken = lock(&self.pending).take()?;
        (now.saturating_duration_since(taken.1) < PENDING_LIFETIME).then_some(taken.0)
    }

    /// Hand `proposal` to a dialog under a fresh random token.
    pub fn propose(&self, proposal: Proposal, now: Instant) -> String {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let mut map = lock(&self.proposals);
        map.retain(|_, (_, at)| now.saturating_duration_since(*at) < PROPOSAL_LIFETIME);
        if map.len() >= MAX_PROPOSALS {
            map.clear();
        }
        map.insert(token.clone(), (proposal, now));
        token
    }

    /// The proposal handed out under `token`, while it is fresh.
    pub fn proposal(&self, token: &str, now: Instant) -> Option<Proposal> {
        lock(&self.proposals)
            .get(token)
            .filter(|(_, at)| now.saturating_duration_since(*at) < PROPOSAL_LIFETIME)
            .map(|(p, _)| p.clone())
    }

    /// Vault lock: every proposal goes (the waiting link stays - it is
    /// what the next unlock continues with).
    pub fn clear_proposals(&self) {
        lock(&self.proposals).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_pending_link_for_ten_minutes_and_a_second_replaces_it() {
        let s = HandoffState::new();
        let t0 = Instant::now();
        s.hold(Received::Url("sshspan://connect?a".into()), t0);
        s.hold(Received::Url("sshspan://connect?b".into()), t0);
        assert!(s.has_pending(t0 + Duration::from_secs(60)));
        assert_eq!(
            s.take(t0),
            Some(Received::Url("sshspan://connect?b".into()))
        );
        assert_eq!(s.take(t0), None, "taken once");
        s.hold(Received::Url("sshspan://connect?c".into()), t0);
        assert!(
            !s.has_pending(t0 + PENDING_LIFETIME),
            "dropped after ten minutes"
        );
        s.hold(Received::Url("sshspan://connect?d".into()), t0);
        assert_eq!(s.take(t0 + PENDING_LIFETIME), None);
    }

    #[test]
    fn duplicates_within_seconds_are_dropped() {
        let s = HandoffState::new();
        let t0 = Instant::now();
        assert!(!s.is_duplicate("x", t0));
        assert!(s.is_duplicate("x", t0 + Duration::from_secs(1)));
        assert!(!s.is_duplicate("y", t0 + Duration::from_secs(1)));
        assert!(!s.is_duplicate("y", t0 + Duration::from_secs(10)));
    }

    #[test]
    fn proposals_expire_and_a_lock_clears_them_but_not_the_pending_link() {
        let s = HandoffState::new();
        let t0 = Instant::now();
        let p = Proposal {
            host: "h".into(),
            port: 22,
            user: "u".into(),
            origin: None,
            host_keys: vec![],
            rotated_at: None,
        };
        let token = s.propose(p.clone(), t0);
        assert_eq!(s.proposal(&token, t0), Some(p.clone()));
        assert_eq!(s.proposal(&token, t0 + PROPOSAL_LIFETIME), None);
        let token = s.propose(p, t0);
        s.hold(Received::Url("sshspan://connect?z".into()), t0);
        s.clear_proposals();
        assert_eq!(s.proposal(&token, t0), None);
        assert!(s.has_pending(t0));
    }
}
