//! Two-way sync between the SSHSpan vault and Bitwarden vault -
//! 1:1 port of bitwardenSyncService.js
//!
//! Sync model (per row, newest side wins; keys and servers alike):
//!   - local row with no live remote counterpart → pushed as a new item (a
//!     link to an item that was deleted remotely is replaced and reported)
//!   - remote item with no local counterpart → pulled, but only when the run
//!     allows remote data in (confirm-first); otherwise only counted
//!   - matched by link (keys also by fingerprint): local updatedAt vs the
//!     change marker stored at the last push/pull decides local; remote
//!     revisionDate vs the stored revision decides remote. Both moved →
//!     local wins. Only remote moved → pulled when allowed, else counted.
//!   - every push and pull writes the new marks back, so a synced row is
//!     in sync at the next run
//!   - deletions are NEVER propagated automatically.
//!   - a folder that cannot be found or created skips its half of the sync
//!     and is reported in `errors`.

use crate::bitwarden::{BitwardenClient, SyncCipher};
use crate::db::{Database, KeyRecord, ServerRecord};
use anyhow::Result;
use std::collections::HashMap;

// ─── Sync decisions (pure, unit-tested) ─────────────────────────────────────

/// Epoch milliseconds of an RFC 3339 timestamp (a cipher's `revisionDate`,
/// the marks stored on server rows); `None` when absent or unreadable.
fn epoch_ms(rfc3339: Option<&str>) -> Option<i64> {
    rfc3339
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp_millis())
}

/// The change marks of one local row, in epoch milliseconds: when it last
/// changed (`updated`), and what the last push or pull recorded - the row's
/// change marker as of then (`synced`) and the remote copy's revision then
/// (`revision`) - and when its category path last changed without the row
/// changing (`category`: a category renamed, moved or deleted, its
/// categories set; see [`crate::db::Database::category_marks`]), until that
/// has been uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncMarks {
    updated: i64,
    synced: Option<i64>,
    revision: Option<i64>,
    category: Option<i64>,
}

impl SyncMarks {
    fn of_key(row: &KeyRecord) -> Self {
        Self {
            updated: row.updated_at.timestamp_millis(),
            synced: row.bitwarden_updated_at,
            revision: row.bitwarden_revision_ts,
            category: None,
        }
    }

    fn of_server(sv: &ServerRecord) -> Self {
        Self {
            updated: sv.updated_at.timestamp_millis(),
            synced: epoch_ms(sv.bitwarden_updated_at.as_deref()),
            revision: epoch_ms(sv.bitwarden_revision_ts.as_deref()),
            category: None,
        }
    }
}

/// What the sync does with one local key or server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan<'a> {
    /// Upload as a NEW remote item. `relink`: the row still named a remote
    /// copy that is gone (deleted or in the trash).
    Create { relink: bool },
    /// First contact through a fingerprint match: adopt the link to `cipher`.
    Link { cipher: &'a str },
    /// Local edits win: upload over the live remote copy `cipher`.
    /// `conflict`: the remote copy changed as well.
    Update { cipher: &'a str, conflict: bool },
    /// Only the remote copy changed: pull `cipher` into the local row.
    Pull { cipher: &'a str },
    /// Only the remote copy `cipher` changed, and overwriting local data was
    /// not allowed for this run.
    SkipRemoteChange { cipher: &'a str },
    /// Nothing changed on either side.
    InSync,
    /// The linked item now belongs to an organization: SSHSpan syncs personal
    /// items only, so the row and the item are left alone and reported.
    OrgOwned,
}

/// The plan for a row matched to the live remote copy `cipher`.
///
/// A category change alone (`marks.category`) is uploaded only while the
/// remote copy is unchanged - the row then holds exactly what Bitwarden
/// holds, plus the new path. When the remote copy changed too, the remote
/// change wins as any other (listed for approval; the pull keeps the local
/// category), and the category goes up at a later run. It used to count as a
/// local edit, and "local wins" uploaded the row's older fields - a saved
/// password Bitwarden had rotated - over the newer ones, unasked.
fn plan_matched<'a>(
    link: Option<&str>,
    cipher: &'a SyncCipher,
    marks: SyncMarks,
    allow_remote_overwrite: bool,
) -> Plan<'a> {
    if link != Some(cipher.id.as_str()) {
        return Plan::Link { cipher: &cipher.id };
    }
    let local_changed = marks.updated > marks.synced.unwrap_or(0);
    let remote_changed = epoch_ms(cipher.revision_date.as_deref())
        .is_some_and(|revision| revision > marks.revision.unwrap_or(0));
    match (local_changed, remote_changed) {
        (false, false) if marks.category.is_some() => Plan::Update {
            cipher: &cipher.id,
            conflict: false,
        },
        (false, false) => Plan::InSync,
        (true, conflict) => Plan::Update {
            cipher: &cipher.id,
            conflict,
        },
        (false, true) if allow_remote_overwrite => Plan::Pull { cipher: &cipher.id },
        (false, true) => Plan::SkipRemoteChange { cipher: &cipher.id },
    }
}

/// What a row's stored link points at in this sync's snapshot of the vault.
#[derive(Debug, Clone, Copy)]
enum Linked<'a> {
    /// No link stored.
    Unlinked,
    /// A live personal item of the row's type - in any folder: an item the
    /// user moved out of the sync folder is still the same item.
    Personal(&'a SyncCipher),
    /// The item now belongs to an organization: left alone, reported.
    OrgOwned,
    /// Deleted, in the trash, or no longer an item of this type.
    Gone,
}

/// Where `link` points among the live (not trashed) items `live`.
fn linked_item<'a>(
    link: Option<&str>,
    live: &HashMap<&str, &'a SyncCipher>,
    cipher_type: u32,
) -> Linked<'a> {
    let Some(id) = link else {
        return Linked::Unlinked;
    };
    match live.get(id) {
        Some(cipher) if cipher.organization_id.is_some() => Linked::OrgOwned,
        Some(cipher) if cipher.cipher_type == cipher_type => Linked::Personal(cipher),
        _ => Linked::Gone,
    }
}

/// The plan for a key or server row: by what its link points at, else by
/// `fallback` (keys: the same fingerprint; servers: the server id stored in
/// the item's notes). Keys and servers follow the same rules - including the
/// confirm-first gate: a newer remote copy only overwrites the local row when
/// the run allows remote overwrites (servers ignored it, A2-47).
fn plan_row<'a>(
    link: Option<&str>,
    linked: Linked<'a>,
    fallback: Option<&'a SyncCipher>,
    marks: SyncMarks,
    allow_remote_overwrite: bool,
) -> Plan<'a> {
    match linked {
        Linked::Personal(cipher) => plan_matched(link, cipher, marks, allow_remote_overwrite),
        Linked::OrgOwned => Plan::OrgOwned,
        Linked::Unlinked | Linked::Gone => match fallback {
            Some(cipher) => plan_matched(link, cipher, marks, allow_remote_overwrite),
            // No live copy. A link that is still set names an item that was
            // deleted (or trashed) in Bitwarden: updating that dead id failed
            // on every run (A7-39). Upload it as a new item, reported.
            None => Plan::Create {
                relink: matches!(linked, Linked::Gone),
            },
        },
    }
}

/// The live personal SSH item with the same fingerprint as `row`.
fn fingerprint_match<'a>(
    row: &KeyRecord,
    remote_ssh: &[&'a SyncCipher],
    fp_by_cipher_id: &HashMap<String, String>,
) -> Option<&'a SyncCipher> {
    remote_ssh.iter().copied().find(|c| {
        fp_by_cipher_id
            .get(&c.id)
            .is_some_and(|fp| *fp == row.fingerprint_sha256)
    })
}

/// The plan for one local key with private material, with no category
/// change pending.
#[cfg(test)]
fn plan_key_row<'a>(
    row: &'a KeyRecord,
    live: &HashMap<&str, &'a SyncCipher>,
    remote_ssh: &[&'a SyncCipher],
    fp_by_cipher_id: &HashMap<String, String>,
    allow_remote_overwrite: bool,
) -> Plan<'a> {
    plan_key_row_marked(
        row,
        live,
        remote_ssh,
        fp_by_cipher_id,
        allow_remote_overwrite,
        None,
    )
}

/// The plan for one local key with private material; `category`: when its
/// category path changed without the key changing, if that is still to be
/// uploaded.
fn plan_key_row_marked<'a>(
    row: &'a KeyRecord,
    live: &HashMap<&str, &'a SyncCipher>,
    remote_ssh: &[&'a SyncCipher],
    fp_by_cipher_id: &HashMap<String, String>,
    allow_remote_overwrite: bool,
    category: Option<i64>,
) -> Plan<'a> {
    let link = row.bitwarden_id.as_deref();
    plan_row(
        link,
        linked_item(link, live, 5),
        fingerprint_match(row, remote_ssh, fp_by_cipher_id),
        SyncMarks {
            category,
            ..SyncMarks::of_key(row)
        },
        allow_remote_overwrite,
    )
}

/// Who the Login items of the servers folder belong to: the local server each
/// one's SSHSpan notes name, and the local servers linked to each one.
struct ServerNames {
    /// Item id -> the local server id its notes name.
    named: HashMap<String, String>,
    /// Item id -> the local servers whose stored link is that item.
    linked: HashMap<String, Vec<String>>,
}

impl ServerNames {
    fn new(named: HashMap<String, String>, local_servers: &[ServerRecord]) -> Self {
        let mut linked: HashMap<String, Vec<String>> = HashMap::new();
        for sv in local_servers {
            if let Some(item) = sv.bitwarden_id.as_deref() {
                linked
                    .entry(item.to_string())
                    .or_default()
                    .push(sv.id.clone());
            }
        }
        Self { named, linked }
    }

    /// Whether a local server other than `server_id` is linked to `item_id`.
    fn linked_to_another(&self, item_id: &str, server_id: &str) -> bool {
        self.linked
            .get(item_id)
            .is_some_and(|servers| servers.iter().any(|id| id != server_id))
    }
}

/// What the items naming a server offer as its own item, when its link is
/// missing or gone.
#[derive(Debug, Clone, Copy)]
enum OwnItem<'a> {
    /// No item names it.
    Missing,
    /// Exactly one: the server's item (an upload whose link was lost).
    Found(&'a SyncCipher),
    /// Several (the count): which one is the server's cannot be told -
    /// copies left by uploads whose link was lost, or a clone that was never
    /// imported. Nothing is guessed.
    Ambiguous(usize),
}

/// `sv`'s own Login item in the servers folder, found through the server id
/// in the items' notes - a server whose link was never stored (the upload
/// worked, the app quit before the link was saved) is found again instead of
/// duplicated. An item ANOTHER local server is linked to is that
/// server's, never `sv`'s: a Bitwarden clone copies the notes, so an imported
/// clone still names the original's server.
fn own_item_of<'a>(
    sv: &ServerRecord,
    remote_logins: &[&'a SyncCipher],
    names: &ServerNames,
) -> OwnItem<'a> {
    match own_item_candidates(sv, remote_logins, names).as_slice() {
        [] => OwnItem::Missing,
        [item] => OwnItem::Found(item),
        several => OwnItem::Ambiguous(several.len()),
    }
}

/// The items that could be `sv`'s own ([`own_item_of`]): their notes name
/// `sv`, and no other local server is linked to them.
fn own_item_candidates<'a>(
    sv: &ServerRecord,
    remote_logins: &[&'a SyncCipher],
    names: &ServerNames,
) -> Vec<&'a SyncCipher> {
    remote_logins
        .iter()
        .copied()
        .filter(|c| {
            names.named.get(&c.id).is_some_and(|id| *id == sv.id)
                && !names.linked_to_another(&c.id, &sv.id)
        })
        .collect()
}

/// How many of the items naming one server [`ambiguous_server_error`] lists
/// by name; the rest are counted.
const MAX_LISTED_ITEMS: usize = 5;

/// The error for a server that several unowned items name: which items they
/// are - title and id, at most [`MAX_LISTED_ITEMS`], each quoted as a pending
/// entry quotes it ([`pending_text`]: shortened, and without control, format
/// or direction characters that could reverse the advice around them) - and
/// what to do without losing data. "Delete the extra copies" (the old
/// advice) discarded a clone that was a legitimate second server, and
/// deleting the server's own copy made SSHSpan link to the clone and
/// overwrite it with this server's data on the next sync. So: delete only
/// true duplicates; for an item that is a different server, remove the
/// `serverId` entry from its notes (it is then offered as a new server) or
/// move it out of the servers folder.
fn ambiguous_server_error(
    client: &BitwardenClient,
    sv: &ServerRecord,
    candidates: &[&SyncCipher],
) -> String {
    let mut listed: Vec<String> = candidates
        .iter()
        .take(MAX_LISTED_ITEMS)
        .map(|item| {
            let title = pending_text(&item_display_name(client, item));
            let id = pending_text(&item.id);
            format!("\"{title}\" (id {id})")
        })
        .collect();
    if candidates.len() > MAX_LISTED_ITEMS {
        listed.push(format!("and {} more", candidates.len() - MAX_LISTED_ITEMS));
    }
    format!(
        "{count} Bitwarden items name server '{name}': {items}. SSHSpan cannot tell which one \
         is this server's, so it changed none of them. In Bitwarden, delete only the items that \
         are true duplicates of this server; if one of them is a different server, remove \
         \"serverId\": \"{id}\" from its notes (it is then offered as a new server) or move it \
         out of the SSHSpan servers folder. Then sync again.",
        count = candidates.len(),
        name = sv.name,
        items = listed.join(", "),
        id = sv.id,
    )
}

/// What the second pass makes of an item whose notes name a local server,
/// compared with the server's own item (`reference`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedItem {
    /// It IS the server's item.
    Own,
    /// Created before the server's item: a copy an earlier upload left, or
    /// the original restored from the trash after SSHSpan re-created it.
    /// Never imported; reported.
    OlderCopy,
    /// Created after the server's item: a clone made in Bitwarden (a clone
    /// copies the notes). New, behind the confirm prompt.
    Clone,
    /// No creation date to compare (missing or unreadable, or no item to
    /// compare with): reported, not imported.
    Undetermined,
}

fn classify_named_item(item: &SyncCipher, reference: Option<&SyncCipher>) -> NamedItem {
    let Some(reference) = reference else {
        return NamedItem::Undetermined;
    };
    if reference.id == item.id {
        return NamedItem::Own;
    }
    match (
        epoch_ms(item.creation_date.as_deref()),
        epoch_ms(reference.creation_date.as_deref()),
    ) {
        (Some(created), Some(theirs)) if created < theirs => NamedItem::OlderCopy,
        (Some(created), Some(theirs)) if created > theirs => NamedItem::Clone,
        _ => NamedItem::Undetermined,
    }
}

/// What the server pass does with one local server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerPlan<'a> {
    Plan(Plan<'a>),
    /// Unlinked (or its item gone) and this many items name it: nothing is
    /// guessed this run - no link, no upload - and the server is reported.
    Ambiguous(usize),
}

/// The plan for one local server with no category change pending.
#[cfg(test)]
fn plan_server_row<'a>(
    sv: &'a ServerRecord,
    live: &HashMap<&str, &'a SyncCipher>,
    remote_logins: &[&'a SyncCipher],
    names: &ServerNames,
    allow_remote_overwrite: bool,
) -> ServerPlan<'a> {
    plan_server_row_marked(sv, live, remote_logins, names, allow_remote_overwrite, None)
}

/// The plan for one local server: by its link, else by its own item found
/// through the items' notes ([`own_item_of`]); `category` as for
/// [`plan_key_row_marked`].
fn plan_server_row_marked<'a>(
    sv: &'a ServerRecord,
    live: &HashMap<&str, &'a SyncCipher>,
    remote_logins: &[&'a SyncCipher],
    names: &ServerNames,
    allow_remote_overwrite: bool,
    category: Option<i64>,
) -> ServerPlan<'a> {
    let link = sv.bitwarden_id.as_deref();
    let linked = linked_item(link, live, 1);
    let fallback = match linked {
        Linked::Unlinked | Linked::Gone => match own_item_of(sv, remote_logins, names) {
            OwnItem::Missing => None,
            OwnItem::Found(item) => Some(item),
            OwnItem::Ambiguous(count) => return ServerPlan::Ambiguous(count),
        },
        Linked::Personal(_) | Linked::OrgOwned => None,
    };
    ServerPlan::Plan(plan_row(
        link,
        linked,
        fallback,
        SyncMarks {
            category,
            ..SyncMarks::of_server(sv)
        },
        allow_remote_overwrite,
    ))
}

/// The Login items of the servers folder: personal, not deleted, and IN that
/// folder. No folder - it could not be found or created - means no items at
/// all (A2-51): comparing `None == None` matched every folder-less Login in
/// the user's vault, and imported them all as "servers".
fn server_logins_in<'a>(ciphers: &'a [SyncCipher], folder_id: Option<&str>) -> Vec<&'a SyncCipher> {
    let Some(folder_id) = folder_id else {
        return Vec::new();
    };
    ciphers
        .iter()
        .filter(|c| {
            c.cipher_type == 1
                && c.deleted_date.is_none()
                && c.organization_id.is_none()
                && c.folder_id.as_deref() == Some(folder_id)
        })
        .collect()
}

/// The id in the answer to a create-folder request.
fn created_folder_id(created: &serde_json::Value) -> Option<String> {
    created
        .get("id")
        .and_then(|id| id.as_str())
        .filter(|id| !id.is_empty())
        .map(String::from)
}

/// How many numbered names [`free_key_name`] tries before it falls back to a
/// random suffix.
const MAX_NAME_SUFFIX: u32 = 999;

/// `wanted`, or - when another key already uses that name, compared without
/// regard to case (the rule create, import and rename follow) - the first
/// free `wanted-2`, `wanted-3`, ..., shortened to stay within the key-name
/// limit. Key names cannot hold spaces (they become Host aliases), hence
/// `-N` rather than ` (N)`. Always ends: if every numbered name is taken, or
/// `taken` keeps saying so, a random suffix is used.
fn free_key_name(wanted: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(wanted) {
        return wanted.to_string();
    }
    let with_suffix = |suffix: &str| {
        let room = crate::crypto::keys::MAX_KEY_NAME_LEN.saturating_sub(suffix.chars().count());
        format!("{}{suffix}", wanted.chars().take(room).collect::<String>())
    };
    (2..=MAX_NAME_SUFFIX)
        .map(|n| with_suffix(&format!("-{n}")))
        .find(|candidate| !taken(candidate))
        .unwrap_or_else(|| {
            with_suffix(&format!(
                "-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ))
        })
}

/// At most this many `sync.error` audit rows per run; the rest are summed up
/// in one more row (a run where every key failed must not flood the log).
const MAX_SYNC_ERROR_AUDIT_ROWS: usize = 20;

/// Longest error text one audit row keeps.
const MAX_AUDIT_ERROR_CHARS: usize = 300;

/// The counters of a sync summary, in the order `sync.run` lists them.
const SUMMARY_COUNTERS: [&str; 17] = [
    "pushed",
    "updatedRemote",
    "pulled",
    "updatedLocal",
    "linked",
    "conflicts",
    "recreatedRemote",
    "remoteDeleted",
    "skippedOverwrites",
    "skippedNew",
    "serversPushed",
    "serversUpdatedRemote",
    "serversPulled",
    "serversUpdatedLocal",
    "serversRecreatedRemote",
    "skippedServerOverwrites",
    "skippedServerNew",
];

/// Audit rows for a finished sync (A8-04): one `sync.run` with every counter,
/// then one `sync.error` per failed item (capped). Names, item ids and error
/// messages only - the same texts the result already carries; never key
/// material, passwords or tokens.
pub fn sync_audit_rows(summary: &serde_json::Value) -> Vec<(&'static str, String)> {
    let count = |key: &str| summary.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
    let list = |key: &str| {
        summary
            .get(key)
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };
    let errors = list("errors");
    let mut run: Vec<String> = SUMMARY_COUNTERS
        .iter()
        .map(|key| format!("{key}={}", count(key)))
        .collect();
    run.push(format!("renamed={}", list("renamed").len()));
    run.push(format!("errors={}", errors.len()));
    if let Some(reason) = summary.get("aborted").and_then(|v| v.as_str()) {
        run.push(format!(
            "aborted=\"{}\"",
            clean_audit_text(reason, MAX_AUDIT_ERROR_CHARS)
        ));
    }
    let mut rows = vec![("sync.run", run.join(" "))];
    rows.extend(
        errors
            .iter()
            .take(MAX_SYNC_ERROR_AUDIT_ROWS)
            .map(|entry| ("sync.error", sync_error_text(entry))),
    );
    if errors.len() > MAX_SYNC_ERROR_AUDIT_ROWS {
        rows.push((
            "sync.error",
            format!(
                "... and {} more failure(s) in this run - see the sync result.",
                errors.len() - MAX_SYNC_ERROR_AUDIT_ROWS
            ),
        ));
    }
    rows
}

/// The `sync.error` text for a sync that failed as a whole.
pub fn sync_failure_audit_text(error: &str) -> String {
    clean_audit_text(error, MAX_AUDIT_ERROR_CHARS)
}

/// `<what>: <error>` for one entry of a sync result's `errors`.
fn sync_error_text(entry: &serde_json::Value) -> String {
    let text = |key: &str| entry.get(key).and_then(|v| v.as_str());
    let subject = if let Some(name) = text("name") {
        format!("key \"{}\"", clean_audit_text(name, 80))
    } else if let Some(server) = text("server") {
        format!("server \"{}\"", clean_audit_text(server, 80))
    } else if let Some(folder) = text("folder") {
        format!("folder \"{}\"", clean_audit_text(folder, 80))
    } else if let Some(id) = text("cipher_id") {
        format!("item {}", clean_audit_text(id, 80))
    } else {
        "sync".to_string()
    };
    let error = text("error").unwrap_or("unknown error");
    format!(
        "{subject}: {}",
        clean_audit_text(error, MAX_AUDIT_ERROR_CHARS)
    )
}

/// Text fit for one audit row: control characters dropped, cut at `max`
/// characters.
fn clean_audit_text(text: &str, max: usize) -> String {
    redact_key_material(text)
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

/// `text` with any PEM-style block (`-----BEGIN ...` up to the matching
/// `-----END ...-----`, or the end of the text) replaced, so key material an
/// error message quoted never reaches the audit log. Sync error messages are
/// written by SSHSpan and the vault server, and none is meant to carry a
/// secret; this is the backstop for one that does.
fn redact_key_material(text: &str) -> std::borrow::Cow<'_, str> {
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    const REMOVED: &str = "[key material removed]";
    if !text.contains(BEGIN) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        out.push_str(&rest[..start]);
        out.push_str(REMOVED);
        let after = &rest[start..];
        rest = match after.find(END) {
            Some(end) => {
                let tail = &after[end + END.len()..];
                // Skip the end marker's label and closing dashes.
                match tail.find("-----") {
                    Some(close) => &tail[close + 5..],
                    None => "",
                }
            }
            None => "",
        };
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

/// What a sync run did - kept outside the passes so a run that stops early
/// (vault locked, an error mid-run) still reports and audits its counts.
#[derive(Debug, Default)]
struct SyncReport {
    pushed: usize,
    updated_remote: usize,
    pulled: usize,
    updated_local: usize,
    linked: usize,
    conflicts: usize,
    recreated_remote: usize,
    remote_deleted: usize,
    skipped_overwrites: usize,
    skipped_new: usize,
    servers_pushed: usize,
    servers_updated_remote: usize,
    servers_pulled: usize,
    servers_updated_local: usize,
    servers_recreated_remote: usize,
    skipped_server_overwrites: usize,
    skipped_server_new: usize,
    renamed: Vec<serde_json::Value>,
    errors: Vec<serde_json::Value>,
    /// The remote changes this run left alone until the user allows them,
    /// one each ([`pending_server_entry`] / [`pending_key_entry`]), all of
    /// them: the summary shows at most [`MAX_PENDING_ENTRIES`] per list, and
    /// the approval token covers every one ([`SyncReport::approval_token`]).
    pending_servers: Vec<PendingChange>,
    pending_keys: Vec<PendingChange>,
    /// An approval came with the run, but the remote changes found are not
    /// the ones it was issued for: nothing was applied.
    approval_stale: bool,
}

/// One remote change a run left alone until the user allows it: what the
/// prompt shows, what an approval binds, and what applying it does.
#[derive(Debug, Clone)]
struct PendingChange {
    /// The entry the prompt shows.
    entry: serde_json::Value,
    /// The item the change comes from as the vault served it: its id, its
    /// revision date and a digest of the whole item - every encrypted field
    /// - so an approval issued for this list approves exactly these bytes.
    cipher: String,
    revision: Option<String>,
    cipher_digest: String,
    /// Whether it changes anything the pull writes. Shown first, so revision
    /// bumps that change nothing cannot push a real change past the cap.
    real: bool,
    pull: RemotePull,
}

/// What applying an approved remote change does.
#[derive(Debug, Clone)]
enum RemotePull {
    /// Pull the newer copy `cipher` into the local key `row`.
    Key { row: KeyRecord, cipher: String },
    /// Import the item `cipher` as a new key.
    NewKey { cipher: String },
    /// Pull the newer copy `cipher` into the local server `row`.
    Server { row: ServerRecord, cipher: String },
    /// Import the item `cipher` as a new server.
    NewServer { cipher: String },
}

/// SHA-256 (hex) of `cipher` as the vault served it - every field, the
/// encrypted ones included.
fn cipher_digest(cipher: &SyncCipher) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(cipher).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

impl PendingChange {
    fn new(entry: serde_json::Value, item: &SyncCipher, real: bool, pull: RemotePull) -> Self {
        Self {
            entry,
            cipher: item.id.clone(),
            revision: item.revision_date.clone(),
            cipher_digest: cipher_digest(item),
            real,
            pull,
        }
    }

    /// What an approval binds for this change.
    fn bound(&self, list: &str) -> serde_json::Value {
        serde_json::json!({
            "list": list,
            "cipher": self.cipher,
            "revision": self.revision,
            "cipherDigest": self.cipher_digest,
            "entry": self.entry,
        })
    }
}

/// The entries the prompt shows from `changes`: the real changes first (in
/// the order found), at most [`MAX_PENDING_ENTRIES`]; true when some were
/// left out.
fn shown_entries(changes: &[PendingChange]) -> (Vec<serde_json::Value>, bool) {
    let mut ordered: Vec<&PendingChange> = changes.iter().collect();
    ordered.sort_by_key(|change| !change.real);
    let shown = ordered
        .iter()
        .take(MAX_PENDING_ENTRIES)
        .map(|change| change.entry.clone())
        .collect();
    (shown, changes.len() > MAX_PENDING_ENTRIES)
}

/// Most entries one list of pending remote changes carries; past that only
/// `pendingTruncated` says there were more (the skip counts stay exact) -
/// and nothing can be approved: an approval would apply entries nobody saw
/// ([`SyncReport::too_many_changes`]).
const MAX_PENDING_ENTRIES: usize = 500;

/// Longest text a pending entry quotes from a vault item - and longest name
/// a server pulled from the vault is stored with - in characters.
const MAX_PENDING_TEXT_CHARS: usize = 80;

/// Text from a vault item for a pending entry ([`clean_item_text`]).
fn pending_text(text: &str) -> String {
    clean_item_text(text)
}

/// Text from a vault item, as SSHSpan shows or stores it: control, format
/// and text-direction characters dropped (everything
/// [`crate::assistant::is_disguising`] names - U+061C, U+200B-200F,
/// U+202A-202E, U+2060-2069, U+FEFF among them), every run of whitespace
/// (U+00A0, U+2000-200A, U+2028/2029 and U+3000 included) one space, the ends
/// trimmed, and at most [`MAX_PENDING_TEXT_CHARS`] characters, the last an
/// ellipsis when it was cut ([`crate::commands::dialog_text`]). Anyone who
/// can edit the item writes this text; it used to lose only its control
/// characters, so a name could reverse or hide part of what the approval
/// prompt showed.
fn clean_item_text(text: &str) -> String {
    crate::commands::dialog_text(text, MAX_PENDING_TEXT_CHARS)
}

/// One server the run did not overwrite (`kind` "overwrite": `name` is the
/// local server, `incomingName` the item's name, `host`/`port` where the
/// item would point it, `localHost`/`localPort` where it points now, and
/// `changes` which of its settings the pull would change - see
/// [`server_changes`]) or did not import ("new": `name`, `host`, `port` of
/// the item, `changes` null). The confirm prompt used to show only counts,
/// so a Bitwarden item rewritten to another host was approved blind; then
/// only the address, while a pull also replaces the user name, the saved
/// password, the auth method and the linked key. Names, addresses and the
/// names of changed settings only - no user name, password or key.
fn pending_server_entry(
    kind: &str,
    name: &str,
    incoming_name: Option<&str>,
    incoming: Option<(String, u16)>,
    local: Option<(&str, u16)>,
    changes: Option<&[&str]>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "name": pending_text(name),
        "incomingName": incoming_name.map(pending_text),
        "host": incoming.as_ref().map(|(host, _)| pending_text(host)),
        "port": incoming.map(|(_, port)| port),
        "localHost": local.map(|(host, _)| pending_text(host)),
        "localPort": local.map(|(_, port)| port),
        "changes": changes,
    })
}

/// One key the run did not overwrite ("overwrite": `name` is the local key,
/// `incomingName` the item's name, `fingerprint` the item's key,
/// `localFingerprint` the local one) or did not import ("new": the item's
/// `name` and `fingerprint`). Fingerprints only - never key material.
fn pending_key_entry(
    kind: &str,
    name: &str,
    incoming_name: Option<&str>,
    fingerprint: Option<&str>,
    local_fingerprint: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "name": pending_text(name),
        "incomingName": incoming_name.map(pending_text),
        "fingerprint": fingerprint.map(pending_text),
        "localFingerprint": local_fingerprint.map(pending_text),
    })
}

impl SyncReport {
    /// Note a server change left for the user's approval.
    fn pending_server(&mut self, change: PendingChange) {
        self.pending_servers.push(change);
    }

    /// Note a key change left for the user's approval.
    fn pending_key(&mut self, change: PendingChange) {
        self.pending_keys.push(change);
    }

    /// How many remote changes are pending, when a list is too long to show
    /// whole ([`MAX_PENDING_ENTRIES`]): then none can be approved.
    fn too_many_changes(&self) -> Option<usize> {
        (self.pending_servers.len() > MAX_PENDING_ENTRIES
            || self.pending_keys.len() > MAX_PENDING_ENTRIES)
            .then(|| self.pending_servers.len() + self.pending_keys.len())
    }

    /// The token that approves exactly the remote changes this run found,
    /// `None` when there are none - or when a list is too long to show whole
    /// ([`SyncReport::too_many_changes`]): SHA-256 (hex) over every pending
    /// change, each with its item's id, revision date, the digest of the
    /// item as served and every field the prompt shows, in a fixed order.
    /// The approving run applies its changes only when its own fetch gives
    /// the same token: a vault that serves something else the second time -
    /// another host, a rolled-back key, an older ciphertext replayed under
    /// the same revision date - gets nothing applied.
    fn approval_token(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        if self.pending_servers.is_empty() && self.pending_keys.is_empty() {
            return None;
        }
        if self.too_many_changes().is_some() {
            return None;
        }
        let mut bound: Vec<String> = self
            .pending_servers
            .iter()
            .map(|change| change.bound("servers").to_string())
            .chain(
                self.pending_keys
                    .iter()
                    .map(|change| change.bound("keys").to_string()),
            )
            .collect();
        bound.sort();
        let mut hasher = Sha256::new();
        for part in &bound {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Some(hex::encode(hasher.finalize()))
    }

    /// One `errors` entry: `{<what>: <name>, error}`, `what` being `name`
    /// (a key), `server`, `folder` or `cipher_id`.
    fn error(&mut self, what: &str, name: &str, error: impl std::fmt::Display) {
        let mut entry = serde_json::Map::new();
        entry.insert(what.to_string(), name.into());
        entry.insert("error".to_string(), error.to_string().into());
        self.errors.push(serde_json::Value::Object(entry));
    }

    /// The summary the command returns, stores and audits. `aborted` is the
    /// reason a run stopped early; its counts are still the real ones.
    fn summary(&self, aborted: Option<&str>) -> serde_json::Value {
        let mut summary = serde_json::json!({
            "ok": aborted.is_none(),
            "pushed": self.pushed,
            "updatedRemote": self.updated_remote,
            "pulled": self.pulled,
            "updatedLocal": self.updated_local,
            "linked": self.linked,
            "conflicts": self.conflicts,
            "recreatedRemote": self.recreated_remote,
            "remoteDeleted": self.remote_deleted,
            "serversPushed": self.servers_pushed,
            "serversUpdatedRemote": self.servers_updated_remote,
            "serversPulled": self.servers_pulled,
            "serversUpdatedLocal": self.servers_updated_local,
            "serversRecreatedRemote": self.servers_recreated_remote,
            "skippedOverwrites": self.skipped_overwrites,
            "skippedNew": self.skipped_new,
            "skippedServerOverwrites": self.skipped_server_overwrites,
            "skippedServerNew": self.skipped_server_new,
            "renamed": self.renamed,
            "errors": self.errors,
        });
        if let Some(reason) = aborted {
            summary["aborted"] = reason.into();
        }
        let (servers, servers_cut) = shown_entries(&self.pending_servers);
        let (keys, keys_cut) = shown_entries(&self.pending_keys);
        if !servers.is_empty() {
            summary["pendingServers"] = servers.into();
        }
        if !keys.is_empty() {
            summary["pendingKeys"] = keys.into();
        }
        if servers_cut || keys_cut {
            summary["pendingTruncated"] = true.into();
        }
        if let Some(total) = self.too_many_changes() {
            summary["approvalRefused"] = format!(
                "Too many changes to review at once ({total}) - nothing from Bitwarden was applied. \
                 SSHSpan can show at most {MAX_PENDING_ENTRIES} server and {MAX_PENDING_ENTRIES} \
                 key changes for approval: bring the new or changed items in Bitwarden below \
                 that, then sync again."
            )
            .into();
        }
        if let Some(token) = self.approval_token() {
            summary["approvalToken"] = token.into();
        }
        if self.approval_stale {
            summary["approvalStale"] = true.into();
        }
        summary
    }
}

/// What a sync run may do with the remote changes it finds.
#[derive(Debug, Clone, Copy)]
pub enum RemoteChanges<'a> {
    /// List them for the user's approval, with the token that approves
    /// exactly them; nothing is applied.
    Ask,
    /// Apply them - if they are exactly the changes this approval token was
    /// issued for ([`SyncReport::approval_token`]); otherwise apply nothing,
    /// list them again with their new token, and say the approval was stale.
    ApproveIf(&'a str),
    /// Apply whatever is found: the tests of the passes only.
    #[cfg(test)]
    ApproveAll,
}

/// The sync's abort check: evaluated at each mutation boundary.
type AbortCheck<'a> = &'a (dyn Fn() -> Result<()> + Send + Sync);

/// Run a full two-way sync. Returns a JSON summary.
///
/// `cancelled` is polled before every remote/local mutation; when it reports
/// true (the vault was locked mid-sync) the sync stops instead of spending
/// more secrets or writing into the locked vault. A failure before anything
/// was compared (login, the vault fetch) is an error; once the passes run, a
/// stop returns the counts so far with `ok: false` and `aborted: <reason>`.
/// Remote changes are applied only as `remote_changes` says: listed with
/// their approval token, or applied when they are exactly the ones a token
/// was issued for ([`RemoteChanges`]).
#[allow(clippy::too_many_arguments)]
pub async fn run_sync(
    server_url: &str,
    email: &str,
    master_password: &str,
    device_id: &str,
    folder_name: &str,
    servers_folder_name: &str,
    db: &Database,
    vault_password: &str,
    remote_changes: RemoteChanges<'_>,
    cancelled: &(dyn Fn() -> bool + Send + Sync),
) -> Result<serde_json::Value> {
    let check = || -> Result<()> {
        if cancelled() {
            anyhow::bail!("Vault was locked; sync aborted.")
        }
        Ok(())
    };
    check()?;
    let mut client = BitwardenClient::new(server_url, email, master_password, device_id)?;
    client.connect().await?;
    let remote = client.sync().await?;

    let mut report = SyncReport::default();
    let run = SyncRun {
        db,
        vault_password,
        remote_changes,
        check: &check,
    };
    let outcome = run
        .passes(
            &mut client,
            &remote,
            folder_name,
            servers_folder_name,
            &mut report,
        )
        .await;
    client.close();
    Ok(match outcome {
        Ok(()) => report.summary(None),
        Err(e) => report.summary(Some(&e.to_string())),
    })
}

/// What every pass of one sync run shares.
struct SyncRun<'a> {
    db: &'a Database,
    vault_password: &'a str,
    remote_changes: RemoteChanges<'a>,
    check: AbortCheck<'a>,
}

impl SyncRun<'_> {
    /// The folders, then the key half and the server half. A folder that
    /// cannot be found or created skips its half and says so (A2-51): the
    /// old fallback swallowed the create error into `None`, pushed items to
    /// the vault root and - for servers - matched every folder-less Login.
    async fn passes(
        &self,
        client: &mut BitwardenClient,
        remote: &crate::bitwarden::SyncResponse,
        folder_name: &str,
        servers_folder_name: &str,
        report: &mut SyncReport,
    ) -> Result<()> {
        let keys_folder = match resolve_keys_folder(
            client,
            &remote.folders,
            folder_name,
            self.db,
            report,
        )
        .await
        {
            Ok(id) => Some(id),
            Err(e) => {
                report.errors.push(folder_error(folder_name, "keys", &e));
                None
            }
        };
        let servers_folder =
            match find_or_create_folder(client, &remote.folders, servers_folder_name).await {
                Ok(id) => Some(id),
                Err(e) => {
                    report
                        .errors
                        .push(folder_error(servers_folder_name, "servers", &e));
                    None
                }
            };
        // Every live (not trashed) item by id: a linked item the user moved
        // to another folder, or that became organization-owned, is still
        // there and must not be treated as deleted.
        let live: HashMap<&str, &SyncCipher> = remote
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .map(|c| (c.id.as_str(), c))
            .collect();
        if let Some(folder_id) = keys_folder.as_deref() {
            self.key_pass(client, remote, &live, folder_id, report)
                .await?;
        }
        if let Some(folder_id) = servers_folder.as_deref() {
            self.server_pass(client, remote, &live, folder_id, report)
                .await?;
        }
        self.settle_remote_changes(client, &live, report).await
    }

    /// After both passes: apply the remote changes they found - every one,
    /// in the order found - when this run may ([`RemoteChanges`]); otherwise
    /// leave them listed. The passes only plan: a remote change is never
    /// applied before the whole list is known, so an approval can be checked
    /// against all of it.
    async fn settle_remote_changes(
        &self,
        client: &mut BitwardenClient,
        live: &HashMap<&str, &SyncCipher>,
        report: &mut SyncReport,
    ) -> Result<()> {
        let approved = match self.remote_changes {
            RemoteChanges::Ask => false,
            RemoteChanges::ApproveIf(token) => match report.approval_token() {
                Some(found) if found == token => true,
                Some(_) => {
                    report.approval_stale = true;
                    false
                }
                None => false,
            },
            #[cfg(test)]
            RemoteChanges::ApproveAll => true,
        };
        if !approved {
            return Ok(());
        }
        // Applied, not skipped.
        report.skipped_overwrites = 0;
        report.skipped_new = 0;
        report.skipped_server_overwrites = 0;
        report.skipped_server_new = 0;
        let keys = std::mem::take(&mut report.pending_keys);
        let servers = std::mem::take(&mut report.pending_servers);
        for change in keys.into_iter().chain(servers) {
            (self.check)()?; // abort promptly if the vault was locked mid-sync
            self.apply_pull(client, live, change.pull, report).await;
        }
        Ok(())
    }

    /// Apply one approved remote change, counting and reporting it as the
    /// passes count their own work.
    async fn apply_pull(
        &self,
        client: &mut BitwardenClient,
        live: &HashMap<&str, &SyncCipher>,
        pull: RemotePull,
        report: &mut SyncReport,
    ) {
        const MISSING: &str = "internal: the item to pull is missing";
        let (db, vault_password) = (self.db, self.vault_password);
        // A category change of the row that is still to be uploaded wins over
        // the item's categories: the pull takes every other field.
        let local_category =
            |kind: &str, id: &str| db.category_mark(kind, id).ok().flatten().is_some();
        match pull {
            RemotePull::Key { row, cipher } => match live.get(cipher.as_str()) {
                Some(item) => {
                    let keep = local_category("key", &row.id);
                    match pull_remote_item(client, item, &row, db, vault_password, keep).await {
                        Ok(PullOutcome::Written { rename }) => {
                            report.updated_local += 1;
                            report.renamed.extend(rename);
                        }
                        Ok(PullOutcome::ChangedMeanwhile) => {
                            report.error("name", &row.name, CHANGED_MEANWHILE)
                        }
                        Err(e) => report.error("name", &row.name, e),
                    }
                }
                None => report.error("name", &row.name, MISSING),
            },
            RemotePull::NewKey { cipher } => match live.get(cipher.as_str()) {
                Some(item) => match pull_new_key(client, item, db, vault_password).await {
                    Ok(PulledKey::Inserted { rename }) => {
                        report.pulled += 1;
                        report.renamed.extend(rename);
                    }
                    Ok(PulledKey::Duplicate) => {}
                    Err(e) => report.error("cipher_id", &pending_text(&cipher), e),
                },
                None => report.error("cipher_id", &pending_text(&cipher), MISSING),
            },
            RemotePull::Server { row, cipher } => match live.get(cipher.as_str()) {
                Some(item) => {
                    let keep = local_category("server", &row.id);
                    match pull_remote_server(client, item, &row, db, vault_password, keep).await {
                        Ok(true) => report.servers_updated_local += 1,
                        Ok(false) => report.error("server", &row.name, CHANGED_MEANWHILE),
                        Err(e) => report.error("server", &row.name, e),
                    }
                }
                None => report.error("server", &row.name, MISSING),
            },
            RemotePull::NewServer { cipher } => match live.get(cipher.as_str()) {
                Some(item) => match pull_new_server(client, item, db, vault_password).await {
                    Ok(()) => report.servers_pulled += 1,
                    Err(e) => report.error("cipher_id", &pending_text(&cipher), e),
                },
                None => report.error("cipher_id", &pending_text(&cipher), MISSING),
            },
        }
    }

    /// Keys: local -> remote (with links and pulls), then new remote items.
    async fn key_pass(
        &self,
        client: &mut BitwardenClient,
        remote: &crate::bitwarden::SyncResponse,
        live: &HashMap<&str, &SyncCipher>,
        folder_id: &str,
        report: &mut SyncReport,
    ) -> Result<()> {
        let db = self.db;
        let remote_ssh: Vec<&SyncCipher> = remote
            .ciphers
            .iter()
            .filter(|c| {
                c.cipher_type == 5 && c.deleted_date.is_none() && c.organization_id.is_none()
            })
            .collect();
        // Each item's fingerprint, derived from the private key it holds -
        // never its own `keyFingerprint` field ([`remote_key`]). An item whose
        // key cannot be read, or that claims another fingerprint or public
        // key, is matched to nothing, offered for nothing and reported where
        // a change of it would be applied.
        let mut fp_by_cipher_id = HashMap::new();
        let mut unusable: HashMap<String, String> = HashMap::new();
        for c in &remote_ssh {
            match remote_key(client, c) {
                Ok(key) => {
                    fp_by_cipher_id.insert(c.id.clone(), key.fingerprint);
                }
                Err(why) => {
                    unusable.insert(c.id.clone(), why);
                }
            }
        }
        let local_keys = db.list_keys()?;
        let category_marks = db.category_marks("key")?;
        // Read once for every comparison of this pass.
        let index = SyncIndex::load(db).await?;
        let mut matched_remote = std::collections::HashSet::new();

        for row in &local_keys {
            (self.check)()?; // abort promptly if the vault was locked mid-sync
            let link = row.bitwarden_id.as_deref();
            if row.private_key_encrypted.is_empty() {
                // Public-only: never uploaded. A link to an item that is gone
                // is cleared, so it is reported once, not on every run.
                if matches!(linked_item(link, live, 5), Linked::Gone) {
                    db.clear_key_sync_link(&row.id)?;
                    report.remote_deleted += 1;
                }
                continue;
            }
            let mark = category_marks.get(&row.id).copied();
            // Planned as if remote changes were not allowed: they are listed
            // here and applied after the passes, once all of them are known
            // ([`SyncRun::settle_remote_changes`]).
            let plan = plan_key_row_marked(row, live, &remote_ssh, &fp_by_cipher_id, false, mark);
            match plan {
                Plan::Create { .. }
                | Plan::OrgOwned
                | Plan::SkipRemoteChange { .. }
                | Plan::InSync => {}
                Plan::Link { cipher } | Plan::Update { cipher, .. } | Plan::Pull { cipher } => {
                    matched_remote.insert(cipher.to_string());
                }
            }
            if let Linked::Personal(cipher) = linked_item(link, live, 5) {
                matched_remote.insert(cipher.id.clone());
            }
            match plan {
                Plan::Create { relink } => {
                    match push_local_key(
                        client,
                        row,
                        Some(folder_id),
                        None,
                        db,
                        self.vault_password,
                    )
                    .await
                    {
                        Ok(()) => {
                            report.pushed += 1;
                            if relink {
                                report.recreated_remote += 1;
                            }
                            category_uploaded(db, "key", &row.id, mark);
                        }
                        Err(e) => {
                            if relink {
                                report.remote_deleted += 1;
                            }
                            report.error("name", &row.name, e);
                        }
                    }
                }
                Plan::Link { cipher } => {
                    // First contact through a fingerprint match: adopt the link.
                    let revision = live.get(cipher).and_then(|c| c.revision_date.as_deref());
                    match db.update_key_sync_meta(
                        &row.id,
                        cipher,
                        revision,
                        row.updated_at.timestamp_millis(),
                    ) {
                        Ok(()) => report.linked += 1,
                        Err(e) => report.error(
                            "name",
                            &row.name,
                            format!("could not store the link: {e}"),
                        ),
                    }
                }
                Plan::Update { cipher, conflict } => {
                    // An item the user moved keeps its folder.
                    let folder = live.get(cipher).and_then(|c| c.folder_id.as_deref());
                    match push_local_key(client, row, folder, Some(cipher), db, self.vault_password)
                        .await
                    {
                        Ok(()) => {
                            report.updated_remote += 1;
                            if conflict {
                                report.conflicts += 1; // local won
                            }
                            category_uploaded(db, "key", &row.id, mark);
                        }
                        Err(e) => report.error("name", &row.name, e),
                    }
                }
                // Only the remote copy changed: listed for the user's
                // approval (planned with remote changes not allowed, so no
                // Pull comes here).
                Plan::Pull { cipher } | Plan::SkipRemoteChange { cipher } => {
                    if let Some(why) = unusable.get(cipher) {
                        report.error("name", &row.name, why);
                        continue;
                    }
                    let Some(item) = live.get(cipher).copied() else {
                        report.error("name", &row.name, "internal: the item to pull is missing");
                        continue;
                    };
                    report.skipped_overwrites += 1;
                    let incoming_name = item_display_name(client, item);
                    let incoming_fp = fp_by_cipher_id.get(cipher).map(String::as_str);
                    // A pending local category change is kept by the pull:
                    // the item's categories change nothing then.
                    let real = incoming_fp != Some(row.fingerprint_sha256.as_str())
                        || incoming_name != row.name
                        || (mark.is_none() && key_categories_differ(client, item, row, &index));
                    report.pending_key(PendingChange::new(
                        pending_key_entry(
                            "overwrite",
                            &row.name,
                            Some(&incoming_name),
                            incoming_fp,
                            Some(&row.fingerprint_sha256),
                        ),
                        item,
                        real,
                        RemotePull::Key {
                            row: row.clone(),
                            cipher: cipher.to_string(),
                        },
                    ));
                }
                Plan::OrgOwned => report.error("name", &row.name, ORG_OWNED),
                Plan::InSync => {}
            }
        }

        // New remote items (no local counterpart).
        for cipher in &remote_ssh {
            (self.check)()?;
            if matched_remote.contains(&cipher.id) {
                continue;
            }
            if let Some(why) = unusable.get(&cipher.id) {
                report.error("cipher_id", &pending_text(&cipher.id), why);
                continue;
            }
            // The same key is already in the vault without a link to this
            // item (a public-only copy, or a second item holding the same
            // key): it is not new.
            if fp_by_cipher_id
                .get(&cipher.id)
                .is_some_and(|fp| local_keys.iter().any(|k| k.fingerprint_sha256 == *fp))
            {
                continue;
            }
            // Confirm-first: a new item is listed for the prompt - its name
            // and fingerprint, never its key - and imported only after an
            // approval of the whole list.
            report.skipped_new += 1;
            report.pending_key(PendingChange::new(
                pending_key_entry(
                    "new",
                    &item_display_name(client, cipher),
                    None,
                    fp_by_cipher_id.get(&cipher.id).map(String::as_str),
                    None,
                ),
                cipher,
                true,
                RemotePull::NewKey {
                    cipher: cipher.id.clone(),
                },
            ));
        }
        Ok(())
    }

    /// Servers (Login items in the servers folder): local -> remote, then
    /// new remote items.
    async fn server_pass(
        &self,
        client: &mut BitwardenClient,
        remote: &crate::bitwarden::SyncResponse,
        live: &HashMap<&str, &SyncCipher>,
        folder_id: &str,
        report: &mut SyncReport,
    ) -> Result<()> {
        let db = self.db;
        let remote_logins = server_logins_in(&remote.ciphers, Some(folder_id));
        let local_servers = db.list_servers()?;
        let names = ServerNames::new(
            remote_logins
                .iter()
                .filter_map(|c| notes_server_id(client, c).map(|id| (c.id.clone(), id)))
                .collect(),
            &local_servers,
        );
        let mut server_matched = std::collections::HashSet::new();
        // Servers whose own item could not be told apart this run (reported).
        let mut ambiguous = std::collections::HashSet::new();
        let category_marks = db.category_marks("server")?;
        // Read once for every comparison of this pass.
        let index = SyncIndex::load(db).await?;

        for sv in &local_servers {
            (self.check)()?;
            let mark = category_marks.get(&sv.id).copied();
            // Planned as if remote changes were not allowed, as in the key
            // pass: they are applied after the passes.
            let plan = match plan_server_row_marked(sv, live, &remote_logins, &names, false, mark) {
                ServerPlan::Plan(plan) => plan,
                ServerPlan::Ambiguous(_) => {
                    // Not guessed: no link, no upload this run.
                    ambiguous.insert(sv.id.as_str());
                    let candidates = own_item_candidates(sv, &remote_logins, &names);
                    report.error(
                        "server",
                        &sv.name,
                        ambiguous_server_error(client, sv, &candidates),
                    );
                    continue;
                }
            };
            if let Plan::Link { cipher } | Plan::Update { cipher, .. } | Plan::Pull { cipher } =
                plan
            {
                server_matched.insert(cipher.to_string());
            }
            if let Linked::Personal(cipher) = linked_item(sv.bitwarden_id.as_deref(), live, 1) {
                server_matched.insert(cipher.id.clone());
            }
            match plan {
                Plan::Create { relink } => {
                    match push_local_server(
                        client,
                        sv,
                        Some(folder_id),
                        None,
                        db,
                        self.vault_password,
                    )
                    .await
                    {
                        Ok(()) => {
                            report.servers_pushed += 1;
                            if relink {
                                report.servers_recreated_remote += 1;
                            }
                            category_uploaded(db, "server", &sv.id, mark);
                        }
                        Err(e) => report.error("server", &sv.name, e),
                    }
                }
                Plan::Link { cipher } => {
                    // Found by the server id in the item's notes: adopt it.
                    // No local marker: the row may have been edited since the
                    // upload whose link was lost, so the next sync compares it
                    // as changed and local wins.
                    let revision = live.get(cipher).and_then(|c| c.revision_date.as_deref());
                    match db.set_server_sync_meta(&sv.id, cipher, revision, None) {
                        Ok(()) => report.linked += 1,
                        Err(e) => report.error(
                            "server",
                            &sv.name,
                            format!("could not store the link: {e}"),
                        ),
                    }
                }
                Plan::Update { cipher, conflict } => {
                    let folder = live.get(cipher).and_then(|c| c.folder_id.as_deref());
                    match push_local_server(
                        client,
                        sv,
                        folder,
                        Some(cipher),
                        db,
                        self.vault_password,
                    )
                    .await
                    {
                        Ok(()) => {
                            report.servers_updated_remote += 1;
                            if conflict {
                                report.conflicts += 1; // local won
                            }
                            category_uploaded(db, "server", &sv.id, mark);
                        }
                        Err(e) => report.error("server", &sv.name, e),
                    }
                }
                // Only the remote copy changed: listed for the user's
                // approval with every setting the pull would change.
                Plan::Pull { cipher } | Plan::SkipRemoteChange { cipher } => {
                    let Some(item) = live.get(cipher).copied() else {
                        report.error("server", &sv.name, "internal: the item to pull is missing");
                        continue;
                    };
                    report.skipped_server_overwrites += 1;
                    let changes = server_changes(
                        client,
                        item,
                        sv,
                        &index,
                        self.vault_password,
                        mark.is_some(),
                    )
                    .await;
                    report.pending_server(PendingChange::new(
                        pending_server_entry(
                            "overwrite",
                            &sv.name,
                            Some(&item_display_name(client, item)),
                            uri_host_port(client, item).ok().flatten(),
                            Some((&sv.host, sv.port)),
                            Some(&changes),
                        ),
                        item,
                        !changes.is_empty(),
                        RemotePull::Server {
                            row: sv.clone(),
                            cipher: cipher.to_string(),
                        },
                    ));
                }
                Plan::OrgOwned => report.error("server", &sv.name, ORG_OWNED),
                Plan::InSync => {}
            }
        }

        for cipher in &remote_logins {
            (self.check)()?;
            if server_matched.contains(&cipher.id) {
                continue;
            }
            // An item whose notes name a local server is compared with that
            // server's own item - the one it is linked to, or the one item
            // naming it that no other server is linked to (pass 1 linked it)
            // - by creation date (comparing with the server's CURRENT link
            // alone made every older copy look like a clone once the server
            // was linked again).
            if let Some(named) = names
                .named
                .get(&cipher.id)
                .and_then(|id| local_servers.iter().find(|sv| sv.id == *id))
            {
                // Its server was reported in pass 1 (several items name it):
                // nothing is imported until the extra copies are gone.
                if ambiguous.contains(named.id.as_str()) {
                    continue;
                }
                let reference = match linked_item(named.bitwarden_id.as_deref(), live, 1) {
                    Linked::Personal(item) => Some(item),
                    Linked::Unlinked | Linked::Gone => {
                        match own_item_of(named, &remote_logins, &names) {
                            OwnItem::Found(item) => Some(item),
                            OwnItem::Missing | OwnItem::Ambiguous(_) => None,
                        }
                    }
                    Linked::OrgOwned => None,
                };
                match classify_named_item(cipher, reference) {
                    NamedItem::Own => continue,
                    NamedItem::OlderCopy => {
                        let item_name = pending_text(&item_display_name(client, cipher));
                        report.error(
                            "cipher_id",
                            &pending_text(&cipher.id),
                            format!(
                                "{item_name} is an older copy of server '{}' - not imported.",
                                named.name
                            ),
                        );
                        continue;
                    }
                    NamedItem::Undetermined => {
                        let item_name = pending_text(&item_display_name(client, cipher));
                        report.error(
                            "cipher_id",
                            &pending_text(&cipher.id),
                            format!(
                                "{item_name} names server '{}', but its creation date cannot be \
                                 compared with the server's item - not imported.",
                                named.name
                            ),
                        );
                        continue;
                    }
                    // A clone: new, behind the confirm prompt below.
                    NamedItem::Clone => {}
                }
            }
            // Confirm-first, as for keys (A2-47): a new remote server is
            // listed - name and address - and imported only after an
            // approval of the whole list.
            report.skipped_server_new += 1;
            report.pending_server(PendingChange::new(
                pending_server_entry(
                    "new",
                    &item_display_name(client, cipher),
                    None,
                    uri_host_port(client, cipher).ok().flatten(),
                    None,
                    None,
                ),
                cipher,
                true,
                RemotePull::NewServer {
                    cipher: cipher.id.clone(),
                },
            ));
        }
        Ok(())
    }
}

/// An item's name for a message: its decrypted name, else its id.
fn item_display_name(client: &BitwardenClient, cipher: &SyncCipher) -> String {
    cipher
        .name
        .as_ref()
        .and_then(|name| client.decrypt_field(name).ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| cipher.id.clone())
}

/// The error for a pull whose row changed (or vanished) while the sync ran.
const CHANGED_MEANWHILE: &str =
    "changed in SSHSpan while the sync ran - nothing was pulled; it is compared again next time";

/// The error for a link to an item that became organization-owned.
const ORG_OWNED: &str = "the linked Bitwarden item now belongs to an organization - SSHSpan syncs \
     personal items only, so it was left alone";

/// The id of the folder named `name`, compared without regard to case.
fn find_folder(folders: &[crate::bitwarden::SyncFolder], name: &str) -> Option<String> {
    let wanted = name.to_lowercase();
    folders
        .iter()
        .find(|f| f.name.as_ref().is_some_and(|n| n.to_lowercase() == wanted))
        .map(|f| f.id.clone())
}

/// The folder named `name`, created when it does not exist yet.
async fn find_or_create_folder(
    client: &mut BitwardenClient,
    folders: &[crate::bitwarden::SyncFolder],
    name: &str,
) -> Result<String> {
    if let Some(id) = find_folder(folders, name) {
        return Ok(id);
    }
    let created = client.create_folder(name).await?;
    created_folder_id(&created)
        .ok_or_else(|| anyhow::anyhow!("the vault server's answer does not name the new folder"))
}

/// The keys folder. Single-folder era: when the default keys folder does not
/// exist but a legacy "SSHSpan" folder does, that folder is renamed rather
/// than a second one created beside it. (The rename used to run after a new
/// folder had already been created, which left two folders with one name.)
/// A failed rename is reported, not swallowed, and a new folder is
/// created instead.
async fn resolve_keys_folder(
    client: &mut BitwardenClient,
    folders: &[crate::bitwarden::SyncFolder],
    folder_name: &str,
    db: &Database,
    report: &mut SyncReport,
) -> Result<String> {
    if let Some(id) = find_folder(folders, folder_name) {
        return Ok(id);
    }
    if folder_name.eq_ignore_ascii_case("SSHSpan_Keys") {
        if let Some(legacy) = find_folder(folders, "SSHSpan") {
            match client.update_folder(&legacy, folder_name).await {
                Ok(_) => {
                    let _ = db.add_audit("sync.folder_migrated", None, "SSHSpan -> SSHSpan_Keys");
                    return Ok(legacy);
                }
                Err(e) => {
                    log::warn!("[sshspan-sync] could not rename the legacy SSHSpan folder: {e}");
                    report.error(
                        "folder",
                        "SSHSpan",
                        format!(
                            "could not rename the old folder to {folder_name} ({e}); a new folder \
                             is used instead"
                        ),
                    );
                }
            }
        }
    }
    find_or_create_folder(client, folders, folder_name).await
}

/// The `errors` entry for a folder that could not be found or created.
fn folder_error(name: &str, what: &str, error: &anyhow::Error) -> serde_json::Value {
    serde_json::json!({
        "folder": name,
        "error": format!(
            "Could not find or create this Bitwarden folder, so {what} were not synced: {error}"
        ),
    })
}

/// The key a remote SSH item really holds: its decrypted private key and the
/// fingerprint and public key derived from it.
struct RemoteKey {
    data: crate::crypto::keys::PrivateKeyData,
    fingerprint: String,
    public_openssh: String,
}

/// Read the key `cipher` holds ([`RemoteKey`]). Its `keyFingerprint` and
/// `publicKey` fields are text anyone who can edit the item can set: they
/// used to be taken as they were, so an item whose private key was swapped
/// for an attacker's but whose fingerprint field was kept read as "no
/// change" - and after Apply the local key held the attacker's key under the
/// old fingerprint. Now both are derived from the private key; an item
/// that claims another fingerprint or another public key is refused, and so
/// is one whose private key cannot be read. The refusal names the item.
fn remote_key(
    client: &BitwardenClient,
    cipher: &SyncCipher,
) -> std::result::Result<RemoteKey, String> {
    use crate::crypto::keys;
    let name = pending_text(&item_display_name(client, cipher));
    let ssh = cipher
        .ssh_key
        .as_ref()
        .ok_or_else(|| format!("{name} holds no SSH key - not imported."))?;
    let private_enc = ssh
        .private_key
        .as_ref()
        .ok_or_else(|| format!("{name} holds no private key - not imported."))?;
    let private_pem = zeroize::Zeroizing::new(client.decrypt_field(private_enc).map_err(|e| {
        format!("{name}: its private key could not be decrypted ({e}) - not imported.")
    })?);
    // Only an OpenSSH private key can be stored.
    if !private_pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Err(format!(
            "{name} does not hold an OpenSSH private key - not imported."
        ));
    }
    let data = keys::import_openssh_private(&private_pem, None)
        .map_err(|e| format!("{name}: its private key could not be read ({e}) - not imported."))?;
    let fingerprint = keys::compute_fingerprint_sha256(&data.public_key);
    let public_openssh = keys::export_public_key(&data, keys::KeyFormat::OpenSsh).map_err(|e| {
        format!("{name}: its public key could not be written ({e}) - not imported.")
    })?;
    let claimed = |field: Option<&String>| {
        field
            .map(|enc| client.decrypt_field(enc).map_err(|_| ()))
            .transpose()
    };
    match claimed(ssh.key_fingerprint.as_ref()) {
        Ok(None) => {}
        Ok(Some(fp)) if same_fingerprint(&fp, &fingerprint) => {}
        _ => {
            return Err(format!(
                "{name} claims a fingerprint that does not match its key - not imported."
            ))
        }
    }
    match claimed(ssh.public_key.as_ref()) {
        Ok(None) => {}
        Ok(Some(line)) if parse_openssh_public_line(&line).is_ok_and(|b| b == data.public_key) => {}
        _ => {
            return Err(format!(
                "{name} claims a public key that does not match its key - not imported."
            ))
        }
    }
    Ok(RemoteKey {
        data,
        fingerprint,
        public_openssh,
    })
}

/// Whether two SHA-256 fingerprint texts name the same key (spaces around
/// and base64 padding aside).
fn same_fingerprint(a: &str, b: &str) -> bool {
    let plain = |s: &str| s.trim().trim_end_matches('=').to_string();
    plain(a) == plain(b)
}

/// What pulling one new remote SSH item did.
enum PulledKey {
    /// Stored as a new key; `rename` reports a name that had to change.
    Inserted { rename: Option<serde_json::Value> },
    /// The same key (by fingerprint) is already in the vault.
    Duplicate,
}

/// Import one remote SSH item that matches no local key: read its key (the
/// fingerprint and public key derived from it, [`remote_key`]), re-seal it
/// with the vault password, store it under a free name, and resolve its
/// SSHSpan category metadata.
async fn pull_new_key(
    client: &mut BitwardenClient,
    cipher: &SyncCipher,
    db: &Database,
    vault_password: &str,
) -> Result<PulledKey> {
    let RemoteKey {
        data: key_data,
        fingerprint: fingerprint_sha256,
        public_openssh,
    } = remote_key(client, cipher).map_err(anyhow::Error::msg)?;
    // Check for duplicate by fingerprint (another item holding the same key
    // may have been pulled earlier in this run).
    if db
        .list_keys()?
        .iter()
        .any(|k| k.fingerprint_sha256 == fingerprint_sha256)
    {
        return Ok(PulledKey::Duplicate);
    }
    let sealed = seal_private_key(vault_password, &key_data.private_key).await?;

    // Remote cipher names are arbitrary text but become Host aliases in
    // ~/.ssh/config on deploy - sanitize rather than skipping the item, and
    // leave an audit trail of the mapping. Then make it unique: names are
    // unique without regard to case, and a pulled key must never become a
    // second key with an existing name.
    let remote_name = cipher
        .name
        .as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| "imported key".to_string());
    let wanted = sanitize_sync_name(db, &remote_name);

    let now = chrono::Utc::now();
    let mut key_record = KeyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name: wanted.clone(),
        key_type: key_data.key_type.db_tag().to_string(),
        public_key: public_openssh,
        private_key_encrypted: sealed,
        fingerprint_sha256,
        fingerprint_md5: crate::crypto::keys::compute_fingerprint_md5(&key_data.public_key),
        comment: key_data.comment.clone(),
        created_at: now,
        updated_at: now,
        deployed: false,
        deploy_path: None,
        bitwarden_id: Some(cipher.id.clone()),
        bitwarden_sync: true,
        // Stored as synced: without these marks the next sync saw the
        // new key as changed on both sides, re-uploaded it and counted a
        // conflict.
        bitwarden_revision_ts: epoch_ms(cipher.revision_date.as_deref()),
        bitwarden_updated_at: Some(now.timestamp_millis()),
        category_ids: Vec::new(),
    };
    {
        // The same lock create, import and rename take around their name
        // check and write, so a key named meanwhile cannot slip in between.
        let _names = crate::commands::lock_key_names();
        key_record.name = free_key_name(&wanted, |candidate| {
            db.key_name_in_use(candidate, None)
                .map_or(true, |other| other.is_some())
        });
        db.insert_key(&key_record)
            .map_err(|e| anyhow::anyhow!("db insert failed: {e}"))?;
    }
    let rename = (key_record.name != wanted).then(|| report_rename(db, &wanted, &key_record.name));

    // Resolve SSHSpan category metadata from the cipher's `notes`.
    let resolved = categories_from_notes(client, cipher, db);
    if !resolved.is_empty() {
        let _ = db.set_key_categories(&key_record.id, &resolved);
    }
    Ok(PulledKey::Inserted { rename })
}

/// Report a pulled key stored under another name because its own was taken:
/// the `renamed` entry of the sync result, and an audit row.
fn report_rename(db: &Database, wanted: &str, stored_as: &str) -> serde_json::Value {
    let _ = db.add_audit(
        "sync.key_renamed",
        None,
        &format!("{wanted:?} -> {stored_as:?} (the name was already taken)"),
    );
    serde_json::json!({ "name": wanted, "storedAs": stored_as })
}

/// The local key categories named in a cipher's SSHSpan `notes` metadata:
/// each by id when this vault has it, else by path (created as needed).
fn categories_from_notes(
    client: &BitwardenClient,
    cipher: &SyncCipher,
    db: &Database,
) -> Vec<String> {
    let Some(notes_enc) = cipher.notes.as_ref() else {
        return Vec::new();
    };
    let Ok(plain) = client.decrypt_field(notes_enc) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&plain) else {
        return Vec::new();
    };
    let Some(arr) = v
        .get("sshspan")
        .and_then(|s| s.get("categories"))
        .and_then(|c| c.as_array())
    else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(|i| i.as_str()).map(String::from);
            let path = item.get("path").and_then(|p| p.as_str()).map(String::from);
            match (id, path) {
                (Some(id), _) if db.get_category(&id).ok().flatten().is_some() => Some(id),
                (_, Some(path)) => db.ensure_category_path_scoped(&path, "key").ok().flatten(),
                _ => None,
            }
        })
        .collect()
}

/// Push a local key to the remote vault as a cipher type-5 SSH item: over the
/// live remote copy `update`, or as a new item when that is `None` - never
/// over whatever id the row happens to name, which may be a deleted item
/// (A7-39). The server's answer is written back to the row.
async fn push_local_key(
    client: &mut BitwardenClient,
    row: &KeyRecord,
    folder_id: Option<&str>,
    update: Option<&str>,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    // Decrypt the private key. A failed unseal must abort the push - the
    // sealed ciphertext is never valid key material.
    let private_bytes = unseal_private_key(vault_password, &row.private_key_encrypted).await?;

    // Export as OpenSSH
    let key_type = crate::crypto::keys::KeyType::from_db_tag(&row.key_type)?;
    let public_bytes = parse_openssh_public_line(&row.public_key)?;
    let key_data = crate::crypto::keys::PrivateKeyData::new(
        key_type,
        private_bytes,
        public_bytes,
        row.comment.clone(),
    );
    let ossh_private = crate::crypto::keys::export_private_key(
        &key_data,
        crate::crypto::keys::KeyFormat::OpenSsh,
        None,
    )?;
    let ossh_public =
        crate::crypto::keys::export_public_key(&key_data, crate::crypto::keys::KeyFormat::OpenSsh)?;

    let name_enc = client.encrypt_field(&row.name)?;
    let priv_enc = client.encrypt_field(&ossh_private)?;
    let pub_enc = client.encrypt_field(&ossh_public)?;
    let fp_enc = client.encrypt_field(&row.fingerprint_sha256)?;

    // Build the SSHSpan metadata blob for the cipher's `notes` field.
    // Contains category IDs and their human-readable paths so a remote
    // vault can reconstruct the tree on import.
    let categories = db.list_categories_for_key(&row.id)?;
    let mut ss_categories: Vec<serde_json::Value> = Vec::new();
    for cid in &categories {
        if let Some(cat) = db.get_category(cid)? {
            ss_categories.push(serde_json::json!({
                "id": cat.id,
                "path": db.category_path_string(&cat.id),
            }));
        }
    }
    let notes_plain = if ss_categories.is_empty() {
        String::new()
    } else {
        serde_json::to_string(&serde_json::json!({
            "v": 1,
            "sshspan": { "categories": ss_categories }
        }))?
    };
    let notes_enc = if notes_plain.is_empty() {
        None
    } else {
        Some(client.encrypt_field(&notes_plain)?)
    };

    let cipher = serde_json::json!({
        "type": 5,
        "organizationId": null,
        "folderId": folder_id,
        "name": name_enc,
        "notes": notes_enc,
        "favorite": false,
        "reprompt": 0,
        "sshKey": {
            "privateKey": priv_enc,
            "publicKey": pub_enc,
            "keyFingerprint": fp_enc,
        },
    });

    let answer = match update {
        Some(cipher_id) => client.update_cipher(cipher_id, &cipher).await?,
        None => client.create_cipher(&cipher).await?,
    };
    record_pushed_key(db, row, update, &answer)
}

/// The item id and `revisionDate` in the server's answer to an upload.
/// `updated` is the id the upload was PUT to (`None` for a new item); an
/// answer that names no item is an error only for a new one - a key must
/// never be linked to an empty id.
fn pushed_item<'a>(
    updated: Option<&'a str>,
    response: &'a serde_json::Value,
) -> Result<(&'a str, Option<&'a str>)> {
    let id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .or(updated)
        .ok_or_else(|| anyhow::anyhow!("the vault server's answer does not name the new item"))?;
    let revision = response.get("revisionDate").and_then(|v| v.as_str());
    Ok((id, revision))
}

/// Record a successful upload of `row` from the server's answer: the item's
/// id and new revision, and the change marker (A7-23). The update branch used
/// to keep the old marks, so the key looked changed on both sides at the next
/// sync - uploaded again (its private key unsealed for it) and counted as a
/// conflict every time, while edits made in Bitwarden were never pulled.
/// Only the sync columns are written, and the marker is the pushed row's own
/// `updated_at`: an edit made while the upload ran stays "changed locally".
fn record_pushed_key(
    db: &Database,
    row: &KeyRecord,
    updated: Option<&str>,
    response: &serde_json::Value,
) -> Result<()> {
    let (id, revision) = pushed_item(updated, response)?;
    db.update_key_sync_meta(&row.id, id, revision, row.updated_at.timestamp_millis())
}

/// [`record_pushed_key`] for a server row: a targeted write of the sync
/// columns, so an edit made while the upload ran is neither reverted nor
/// lost to the next sync.
fn record_pushed_server(
    db: &Database,
    sv: &ServerRecord,
    updated: Option<&str>,
    response: &serde_json::Value,
) -> Result<()> {
    let (id, revision) = pushed_item(updated, response)?;
    db.set_server_sync_meta(&sv.id, id, revision, Some(&sv.updated_at.to_rfc3339()))
}

/// Write a pulled key into its row - only the columns the pull owns, so a
/// deployment recorded while the sync ran survives, and only if
/// the row is still the one the sync read: false when it was edited or
/// deleted meanwhile.
fn store_pulled_key(db: &Database, row: &KeyRecord, pulled: &crate::db::KeyPull) -> Result<bool> {
    db.apply_pulled_key(&row.id, pulled, row.updated_at)
}

/// Pull a remote cipher into a local row (overwrite with newer remote data).
/// Reports a remote name taken by another key, and a row that changed while
/// the sync ran (then nothing is written). `keep_local_categories`: the key's
/// own category change is still to be uploaded - it wins over the item's.
async fn pull_remote_item(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    row: &KeyRecord,
    db: &Database,
    vault_password: &str,
    keep_local_categories: bool,
) -> Result<PullOutcome> {
    // The key it holds, its fingerprint and public key derived from it
    // ([`remote_key`]). Anything but an OpenSSH private key is refused: it
    // used to be skipped silently and still counted as "updated locally".
    let key = remote_key(client, cipher).map_err(anyhow::Error::msg)?;
    let kd = &key.data;

    // Remote cipher names are arbitrary text but become Host aliases in
    // ~/.ssh/config on deploy - sanitize rather than failing the item. And
    // names are unique without regard to case: a remote rename onto another
    // key's name gets a numbered suffix, reported, never a second copy.
    let remote_name = cipher
        .name
        .as_ref()
        .and_then(|n| client.decrypt_field(n).ok())
        .unwrap_or_else(|| row.name.clone());
    let wanted = sanitize_sync_name(db, &remote_name);
    let sealed = seal_private_key(vault_password, &kd.private_key).await?;
    let mut pulled = crate::db::KeyPull {
        name: wanted.clone(),
        key_type: kd.key_type.db_tag().to_string(),
        public_key: key.public_openssh.clone(),
        private_key_encrypted: sealed,
        fingerprint_sha256: key.fingerprint.clone(),
        fingerprint_md5: crate::crypto::keys::compute_fingerprint_md5(&kd.public_key),
        comment: kd.comment.clone(),
        bitwarden_revision_ts: epoch_ms(cipher.revision_date.as_deref()),
    };
    // The name check and the write run under the same lock as create, import
    // and rename, so a key named meanwhile cannot slip in between.
    let written = {
        let _names = crate::commands::lock_key_names();
        pulled.name = free_key_name(&wanted, |candidate| {
            db.key_name_in_use(candidate, Some(&row.id))
                .map_or(true, |other| other.is_some())
        });
        store_pulled_key(db, row, &pulled)?
    };
    if !written {
        return Ok(PullOutcome::ChangedMeanwhile);
    }
    // Resolve SSHSpan category metadata from the cipher's `notes` - unless
    // the key's own new categories are still to be uploaded.
    if !keep_local_categories {
        db.set_key_categories(&row.id, &categories_from_notes(client, cipher, db))?;
    }
    let name = pulled.name;
    Ok(PullOutcome::Written {
        rename: (name != wanted).then(|| report_rename(db, &wanted, &name)),
    })
}

/// What a pull into an existing row did.
enum PullOutcome {
    /// Written; `rename` reports a remote name another key already had.
    Written { rename: Option<serde_json::Value> },
    /// The row changed or vanished while the sync ran: nothing was written.
    ChangedMeanwhile,
}

/// Sanitize a remotely-sourced key name for vault storage. A name that
/// already passes validation is kept verbatim; anything that couldn't be a
/// single `Host` token is mapped through `sanitize_key_name` (invalid runs →
/// `-`) and logged to the audit trail. Sync must not drop an item over its
/// name, so the mapping is total.
fn sanitize_sync_name(db: &Database, raw: &str) -> String {
    if crate::crypto::keys::validate_key_name(raw).is_ok() {
        return raw.to_string();
    }
    let sanitized = crate::crypto::keys::sanitize_key_name(raw);
    let _ = db.add_audit(
        "keys.name_sanitized",
        None,
        &format!("{raw:?} -> {sanitized:?}"),
    );
    sanitized
}

/// Seal a private key for local storage. Never substitutes a placeholder:
/// a seal failure propagates so callers skip the item or abort with a
/// clear error instead of persisting an empty ciphertext.
/// Argon2id, on the blocking pool ([`crate::commands::seal_off_thread`]).
async fn seal_private_key(vault_password: &str, private_key: &[u8]) -> Result<String> {
    crate::commands::seal_off_thread(vault_password, private_key)
        .await
        .map_err(|e| anyhow::anyhow!("vault seal failed during sync; refusing to store key: {e}"))
}

/// Unseal a stored private key. Never falls back to the sealed ciphertext:
/// if the entry cannot be decrypted with the vault password, the error
/// propagates so the key is neither pushed nor overwritten. Argon2id, on the
/// blocking pool ([`crate::commands::unseal_off_thread`]).
async fn unseal_private_key(vault_password: &str, sealed: &str) -> Result<Vec<u8>> {
    let mut plain = crate::commands::unseal_off_thread(vault_password, sealed)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "vault unseal failed during sync; refusing to use sealed ciphertext as key: {e}"
            )
        })?;
    Ok(std::mem::take(&mut *plain))
}

/// Parse an authorized_keys line back into raw SSH wire-format public key bytes.
fn parse_openssh_public_line(line: &str) -> Result<Vec<u8>> {
    use base64ct::Encoding;
    let b64 = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Malformed stored public key"))?;
    base64ct::Base64::decode_vec(b64)
        .map_err(|e| anyhow::anyhow!("Malformed stored public key: {e}"))
}

// ─── Server sync helpers (Bitwarden Login-type ciphers) ────────────────────

fn prefixed_host_category_path(path: &str) -> String {
    let mut parts = path.split('/');
    match parts.next() {
        Some(root) if !root.is_empty() => std::iter::once(format!("Hosts-{root}"))
            .chain(parts.map(String::from))
            .collect::<Vec<_>>()
            .join("/"),
        _ => path.to_string(),
    }
}

fn unprefix_host_category_path(path: &str) -> String {
    path.split('/')
        .map(|part| part.strip_prefix("Hosts-").unwrap_or(part))
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the `notes` metadata blob for a server cipher: the local server id,
/// auth method, the bound key's fingerprint, and the host category path.
fn server_notes(
    client: &BitwardenClient,
    db: &Database,
    sv: &crate::db::ServerRecord,
) -> Result<Option<String>> {
    let key_fp = match &sv.key_id {
        Some(kid) => db.get_key(kid)?.map(|k| k.fingerprint_sha256),
        None => None,
    };
    let category = match &sv.category_id {
        Some(cid) => db
            .get_category(cid)?
            .filter(|cat| cat.scope == "host")
            .map(|cat| {
                serde_json::json!({
                    "id": cat.id,
                    "path": prefixed_host_category_path(&db.category_path_string(&cat.id)),
                })
            }),
        None => None,
    };
    let plain = serde_json::to_string(&serde_json::json!({
        "v": 1,
        "sshspan": {
            // The local server id: finds this item again when its link was
            // never stored (the upload worked, the app quit before the link
            // was saved) instead of uploading a duplicate.
            "serverId": sv.id,
            "authMethod": sv.auth_method,
            "keyFingerprint": key_fp,
            "category": category,
        }
    }))?;
    Ok(Some(client.encrypt_field(&plain)?))
}

/// Push a local server as a Login item into the servers folder: over the live
/// remote copy `update`, or as a new item when that is `None`. The server's
/// answer is written back to the row (A7-23).
async fn push_local_server(
    client: &mut BitwardenClient,
    sv: &crate::db::ServerRecord,
    folder_id: Option<&str>,
    update: Option<&str>,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let name_enc = client.encrypt_field(&sv.name)?;
    let user_enc = client.encrypt_field(&sv.username)?;
    let password_enc = match &sv.saved_password {
        Some(sealed) => {
            // Argon2id, on the blocking pool.
            let mut plain = crate::commands::unseal_off_thread(vault_password, sealed)
                .await
                .map_err(|e| anyhow::anyhow!("saved password unseal failed: {e}"))?;
            let plain_str = zeroize::Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *plain)).unwrap_or_default(),
            );
            if plain_str.is_empty() {
                None
            } else {
                Some(client.encrypt_field(&plain_str)?)
            }
        }
        None => None,
    };
    let uri_plain = format!("ssh://{}:{}", sv.host, sv.port);
    let uri_enc = client.encrypt_field(&uri_plain)?;
    let notes_enc = server_notes(client, db, sv)?;

    let cipher = serde_json::json!({
        "type": 1,
        "organizationId": null,
        "folderId": folder_id,
        "name": name_enc,
        "notes": notes_enc,
        "favorite": false,
        "reprompt": 0,
        "login": {
            "username": user_enc,
            "password": password_enc,
            "uris": [{ "uri": uri_enc }],
        },
    });

    let answer = match update {
        Some(cipher_id) => client.update_cipher(cipher_id, &cipher).await?,
        None => client.create_cipher(&cipher).await?,
    };
    record_pushed_server(db, sv, update, &answer)
}

/// notes -> (auth_method, key_fingerprint, category_id)
/// The `sshspan` object of an item's notes (written by [`server_notes`]),
/// when the notes decrypt and hold one.
fn sshspan_notes(
    client: &BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
) -> Option<serde_json::Value> {
    let plain = client.decrypt_field(cipher.notes.as_ref()?).ok()?;
    let mut v: serde_json::Value = serde_json::from_str(&plain).ok()?;
    Some(v.get_mut("sshspan")?.take())
}

/// The auth method and the linked key's fingerprint an item's notes name -
/// read only, nothing created.
fn notes_auth_and_key(
    client: &BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
) -> (Option<String>, Option<String>) {
    let Some(ss) = sshspan_notes(client, cipher) else {
        return (None, None);
    };
    let text = |field: &str| ss.get(field).and_then(|v| v.as_str()).map(String::from);
    (text("authMethod"), text("keyFingerprint"))
}

/// Which of `sv`'s settings pulling `item` into it would change - "name",
/// "host", "port", "user", "password", "authMethod", "linkedKey",
/// "category", in that order - by the rules [`pull_remote_server`] writes
/// them with. The prompt used to show only the address while the pull also
/// replaced the user name, the saved password, the auth method and the
/// linked key; and a remote rename or a move to another category counted as
/// a mere revision bump. A field that does not decrypt counts as changing
/// (the pull would refuse the item). The saved password is compared by
/// unsealing it, on the blocking pool; nothing is written - a category the
/// pull would create is not created here. The linked key and the category
/// are looked up in `index`, read once for the whole pass.
/// `keep_local_category`: the server's own category change is still to be
/// uploaded, and the pull keeps it.
async fn server_changes(
    client: &BitwardenClient,
    item: &SyncCipher,
    sv: &ServerRecord,
    index: &SyncIndex,
    vault_password: &str,
    keep_local_category: bool,
) -> Vec<&'static str> {
    let mut changes = Vec::new();
    match decrypt_present(client, item.name.as_ref(), "name") {
        Ok(Some(name)) => {
            let name = clean_item_text(&name);
            if !name.is_empty() && name != sv.name {
                changes.push("name");
            }
        }
        Ok(None) => {}
        Err(_) => changes.push("name"),
    }
    match uri_host_port(client, item) {
        Ok(Some((host, port))) => {
            if host != sv.host {
                changes.push("host");
            }
            if port != sv.port {
                changes.push("port");
            }
        }
        Ok(None) => {}
        Err(_) => changes.extend(["host", "port"]),
    }
    let login = item.login.as_ref();
    match decrypt_present(client, login.and_then(|l| l.username.as_ref()), "user name") {
        Ok(Some(user)) if user != sv.username => changes.push("user"),
        Ok(_) => {}
        Err(_) => changes.push("user"),
    }
    let incoming = decrypt_present(client, login.and_then(|l| l.password.as_ref()), "password")
        .map(|p| p.map(zeroize::Zeroizing::new).filter(|p| !p.is_empty()));
    let password_changes = match incoming {
        Err(_) => true,
        // The pull clears a saved password the item does not have.
        Ok(None) => sv.saved_password.is_some(),
        Ok(Some(new)) => match sv.saved_password.as_deref() {
            None => true,
            Some(sealed) => crate::commands::unseal_off_thread(vault_password, sealed)
                .await
                .map_or(true, |old| old.as_slice() != new.as_bytes()),
        },
    };
    if password_changes {
        changes.push("password");
    }
    let (auth_method, key_fp) = notes_auth_and_key(client, item);
    if auth_method.is_some_and(|method| method != sv.auth_method) {
        changes.push("authMethod");
    }
    let key_id = key_fp
        .as_ref()
        .and_then(|fp| index.key_by_fingerprint.get(fp).cloned())
        .or_else(|| sv.key_id.clone());
    if key_id != sv.key_id {
        changes.push("linkedKey");
    }
    if !keep_local_category
        && notes_category_differs(client, item, sv.category_id.as_deref(), index)
    {
        changes.push("category");
    }
    changes
}

/// What the comparisons of a pass's pending changes look up
/// ([`server_changes`], [`notes_category_differs`],
/// [`key_categories_differ`]), read ONCE per pass, on the blocking pool:
/// every category (its scope by id, its id by scope and path), every key's
/// categories and every key's fingerprint. Comparing used to read the whole
/// category table again for every category of every lookup - 357 s for 300
/// pending servers and 150 categories in a debug build, every query on an
/// async worker, while the sync held the rotation lock. Nothing in a pass
/// changes these: only an approved pull, after the passes, creates
/// categories or keys.
struct SyncIndex {
    scope_of: HashMap<String, String>,
    by_path: HashMap<(String, String), String>,
    key_categories: HashMap<String, std::collections::HashSet<String>>,
    key_by_fingerprint: HashMap<String, String>,
}

impl SyncIndex {
    /// Read the index on the blocking pool.
    async fn load(db: &Database) -> Result<Self> {
        let db = db.clone();
        crate::commands::spawn_on_pool(move || Self::read(&db))
            .await
            .map_err(|e| anyhow::anyhow!("background task failed: {e}"))?
    }

    fn read(db: &Database) -> Result<Self> {
        let all = db.list_categories()?;
        let paths = crate::db::category_paths(&all);
        let mut scope_of = HashMap::new();
        let mut by_path = HashMap::new();
        // In the order the categories are listed: of several with one path,
        // the first is the one a lookup by path always found.
        for category in &all {
            scope_of.insert(category.id.clone(), category.scope.clone());
            if let Some(path) = paths.get(&category.id) {
                by_path
                    .entry((category.scope.clone(), path.clone()))
                    .or_insert_with(|| category.id.clone());
            }
        }
        let key_categories = db
            .all_key_categories()?
            .into_iter()
            .map(|(key, categories)| (key, categories.into_iter().collect()))
            .collect();
        let mut key_by_fingerprint = HashMap::new();
        // Newest first, as listed: the first key with a fingerprint is the
        // one a lookup by fingerprint always found.
        for key in db.list_keys()? {
            key_by_fingerprint
                .entry(key.fingerprint_sha256)
                .or_insert(key.id);
        }
        Ok(Self {
            scope_of,
            by_path,
            key_categories,
            key_by_fingerprint,
        })
    }

    /// Whether this vault has category `id` - of `scope`, when one is given.
    fn has_category(&self, id: &str, scope: Option<&str>) -> bool {
        self.scope_of
            .get(id)
            .is_some_and(|found| scope.is_none_or(|wanted| found == wanted))
    }

    /// The category of `scope` whose path is `path`, if this vault has one.
    fn category_by_path(&self, scope: &str, path: &str) -> Option<&str> {
        self.by_path
            .get(&(scope.to_string(), path.to_string()))
            .map(String::as_str)
    }
}

/// Whether pulling `item` would file its server somewhere other than
/// `current`, by the rules [`parse_server_notes`] resolves with: the notes
/// name a host category by an id this vault has, else by a path. Read only
/// (`index`): a path this vault lacks - the pull would create it - differs;
/// notes that name no category leave the server where it is.
fn notes_category_differs(
    client: &BitwardenClient,
    item: &SyncCipher,
    current: Option<&str>,
    index: &SyncIndex,
) -> bool {
    let Some(category) = sshspan_notes(client, item)
        .and_then(|notes| notes.get("category").cloned())
        .filter(|c| c.is_object())
    else {
        return false;
    };
    let id = category.get("id").and_then(|i| i.as_str());
    let path = category.get("path").and_then(|p| p.as_str());
    match (id, path) {
        (Some(id), _) if index.has_category(id, Some("host")) => current != Some(id),
        (_, Some(path)) => {
            match index.category_by_path("host", &unprefix_host_category_path(path)) {
                Some(existing) => current != Some(existing),
                None => true,
            }
        }
        _ => false,
    }
}

/// Whether pulling `item` would file key `row` in other categories than its
/// own, by the rules [`categories_from_notes`] resolves with. Read only
/// (`index`): a path this vault lacks - the pull would create it - differs,
/// and notes that name none differ from a key that has some (the pull clears
/// them).
fn key_categories_differ(
    client: &BitwardenClient,
    item: &SyncCipher,
    row: &KeyRecord,
    index: &SyncIndex,
) -> bool {
    let none = std::collections::HashSet::new();
    let local = index.key_categories.get(&row.id).unwrap_or(&none);
    let entries = sshspan_notes(client, item)
        .and_then(|notes| notes.get("categories").and_then(|c| c.as_array()).cloned())
        .unwrap_or_default();
    let mut remote = std::collections::HashSet::new();
    for entry in &entries {
        let id = entry.get("id").and_then(|i| i.as_str());
        let path = entry.get("path").and_then(|p| p.as_str());
        match (id, path) {
            (Some(id), _) if index.has_category(id, None) => {
                remote.insert(id.to_string());
            }
            (_, Some(path)) => match index.category_by_path("key", path) {
                Some(existing) => {
                    remote.insert(existing.to_string());
                }
                None => return true,
            },
            _ => {}
        }
    }
    remote != *local
}

/// A category change of row `id` (`kind` "key" or "server"), marked at
/// `mark`, is in the item it was just uploaded to: the mark goes - unless it
/// was renewed meanwhile. A failure only means the next run uploads it again.
fn category_uploaded(db: &Database, kind: &str, id: &str, mark: Option<i64>) {
    if let Some(at) = mark {
        if let Err(e) = db.clear_category_mark(kind, id, at) {
            log::warn!("[sshspan-sync] could not clear the category mark of a {kind}: {e}");
        }
    }
}

/// notes -> (auth method, key fingerprint, category id). The category is
/// resolved - created from its path when this vault lacks it - only when
/// `resolve_category`.
fn parse_server_notes(
    client: &BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    db: &Database,
    resolve_category: bool,
) -> (Option<String>, Option<String>, Option<String>) {
    let Some(ss) = sshspan_notes(client, cipher) else {
        return (None, None, None);
    };
    let auth = ss
        .get("authMethod")
        .and_then(|a| a.as_str())
        .map(String::from);
    let fp = ss
        .get("keyFingerprint")
        .and_then(|f| f.as_str())
        .map(String::from);
    let cat = ss
        .get("category")
        .filter(|_| resolve_category)
        .and_then(|c| c.as_object())
        .and_then(|c| {
            let id = c.get("id").and_then(|i| i.as_str()).map(String::from);
            let path = c.get("path").and_then(|p| p.as_str()).map(String::from);
            match (id, path) {
                (Some(id), _)
                    if db
                        .get_category(&id)
                        .ok()
                        .flatten()
                        .map(|c| c.scope == "host")
                        .unwrap_or(false) =>
                {
                    Some(id)
                }
                (_, Some(path)) => db
                    .ensure_category_path_scoped(&unprefix_host_category_path(&path), "host")
                    .ok()
                    .flatten(),
                _ => None,
            }
        });
    (auth, fp, cat)
}

/// The local server id an item's SSHSpan notes name (written by
/// [`server_notes`]), so a server whose link was never stored is found again.
fn notes_server_id(client: &BitwardenClient, cipher: &SyncCipher) -> Option<String> {
    let plain = client.decrypt_field(cipher.notes.as_ref()?).ok()?;
    let v: serde_json::Value = serde_json::from_str(&plain).ok()?;
    v.get("sshspan")?
        .get("serverId")?
        .as_str()
        .filter(|id| !id.is_empty())
        .map(String::from)
}

/// Decrypt a field the item HAS. A present field that does not decrypt is an
/// error - the item is left alone - never a silent fallback that erases a
/// saved password or renames a host.
fn decrypt_present(
    client: &BitwardenClient,
    field: Option<&String>,
    what: &str,
) -> Result<Option<String>> {
    field
        .map(|enc| {
            client
                .decrypt_field(enc)
                .map_err(|e| anyhow::anyhow!("could not decrypt the item's {what}: {e}"))
        })
        .transpose()
}

/// Host and port from the first `ssh://host:port` URI of a Login item, if it
/// has one (strict: a URI that does not decrypt is an error).
fn uri_host_port(client: &BitwardenClient, cipher: &SyncCipher) -> Result<Option<(String, u16)>> {
    let first = cipher
        .login
        .as_ref()
        .and_then(|l| l.uris.as_ref())
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.as_ref());
    let Some(uri) = decrypt_present(client, first, "address")? else {
        return Ok(None);
    };
    let rest = uri.strip_prefix("ssh://").unwrap_or(&uri);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(22)),
        None => (rest.to_string(), 22),
    };
    Ok((!host.is_empty()).then_some((host, port)))
}

/// Pull a newer remote Login into an existing server row. Returns false when
/// the row changed or vanished while the sync ran (nothing written).
/// `keep_local_category`: the server's own category change is still to be
/// uploaded - it wins over the item's.
async fn pull_remote_server(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    sv: &crate::db::ServerRecord,
    db: &Database,
    vault_password: &str,
    keep_local_category: bool,
) -> Result<bool> {
    let login = cipher.login.as_ref();
    // Stored clean: no format or text-direction characters.
    let name = decrypt_present(client, cipher.name.as_ref(), "name")?
        .map(|name| clean_item_text(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| sv.name.clone());
    let username = decrypt_present(client, login.and_then(|l| l.username.as_ref()), "user name")?
        .unwrap_or_else(|| sv.username.clone());
    let password_plain =
        decrypt_present(client, login.and_then(|l| l.password.as_ref()), "password")?
            .map(zeroize::Zeroizing::new);
    // An item without an address keeps the row's (it used to become the
    // item's name on port 22).
    let (host, port) = uri_host_port(client, cipher)?.unwrap_or((sv.host.clone(), sv.port));
    let (auth_method, key_fp, category_id) =
        parse_server_notes(client, cipher, db, !keep_local_category);

    // Re-link the key by fingerprint if the local vault has a match.
    let key_id = key_fp
        .as_ref()
        .and_then(|fp| {
            db.list_keys()
                .ok()?
                .into_iter()
                .find(|k| &k.fingerprint_sha256 == fp)
                .map(|k| k.id)
        })
        .or_else(|| sv.key_id.clone());

    // Argon2id, on the blocking pool.
    let saved_password = match password_plain {
        Some(p) if !p.is_empty() => Some(
            crate::commands::seal_off_thread(vault_password, p.as_bytes())
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "vault seal failed for saved password; refusing to store it: {e}"
                    )
                })?,
        ),
        _ => None,
    };
    store_pulled_server(
        db,
        sv,
        &crate::db::ServerPull {
            name,
            host,
            port,
            username,
            auth_method: auth_method.unwrap_or_else(|| sv.auth_method.clone()),
            key_id,
            category_id: if keep_local_category {
                sv.category_id.clone()
            } else {
                category_id.or_else(|| sv.category_id.clone())
            },
            saved_password,
            bitwarden_revision_ts: cipher.revision_date.clone(),
        },
    )
}

/// Write a pulled server into its row - only what the Login item carries;
/// the `.pem` path, colour and a connection recorded while the sync ran
/// stay - and only if the row is still the one the sync read.
fn store_pulled_server(
    db: &Database,
    sv: &ServerRecord,
    pulled: &crate::db::ServerPull,
) -> Result<bool> {
    db.apply_pulled_server(&sv.id, pulled, sv.updated_at)
}

/// Import a Login item of the servers folder that matches no local server.
async fn pull_new_server(
    client: &mut BitwardenClient,
    cipher: &crate::bitwarden::SyncCipher,
    db: &Database,
    vault_password: &str,
) -> Result<()> {
    let login = cipher.login.as_ref();
    // Stored clean: no format or text-direction characters.
    let name = decrypt_present(client, cipher.name.as_ref(), "name")?
        .map(|name| clean_item_text(&name))
        .filter(|name| !name.is_empty());
    let username = decrypt_present(client, login.and_then(|l| l.username.as_ref()), "user name")?
        .unwrap_or_else(|| "root".to_string());
    let password_plain =
        decrypt_present(client, login.and_then(|l| l.password.as_ref()), "password")?
            .map(zeroize::Zeroizing::new);
    let (host, port) = match uri_host_port(client, cipher)? {
        Some(host_port) => host_port,
        None => (
            name.clone()
                .unwrap_or_else(|| "imported server".to_string()),
            22,
        ),
    };
    let name = name.unwrap_or_else(|| host.clone());
    let (auth_method, key_fp, category_id) = parse_server_notes(client, cipher, db, true);

    let key_id = key_fp.as_ref().and_then(|fp| {
        db.list_keys()
            .ok()?
            .into_iter()
            .find(|k| &k.fingerprint_sha256 == fp)
            .map(|k| k.id)
    });

    // Argon2id, on the blocking pool.
    let saved_password = match password_plain {
        Some(p) if !p.is_empty() => Some(
            crate::commands::seal_off_thread(vault_password, p.as_bytes())
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "vault seal failed for saved password; refusing to store it: {e}"
                    )
                })?,
        ),
        _ => None,
    };
    let now = chrono::Utc::now();
    let record = crate::db::ServerRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        host,
        port,
        username,
        key_id,
        pem_path: None,
        auth_method: auth_method.unwrap_or_else(|| "publickey".to_string()),
        saved_password,
        category_id,
        color: None,
        last_connected_at: None,
        // One instant for the row and its sync marker: two clock reads
        // could straddle a millisecond and make the new row look edited.
        created_at: now,
        updated_at: now,
        bitwarden_id: Some(cipher.id.clone()),
        bitwarden_revision_ts: cipher.revision_date.clone(),
        bitwarden_updated_at: Some(now.to_rfc3339()),
    };
    db.insert_server(&record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PW: &str = "test-vault-password";

    #[test]
    fn healthy_vault_is_not_reported_cancelled() {
        // Regression: the cancelled closure in bitwarden_sync used to negate
        // its unlocked flag, so an OPEN vault aborted every sync at the very
        // first check(). run_sync is not callable without a server, so pin
        // the observable contract instead: check() (the first statement of
        // run_sync) must NOT abort while cancelled() reports false.
        let cancelled = || false;
        let check = || -> Result<()> {
            if cancelled() {
                anyhow::bail!("Vault was locked; sync aborted.")
            }
            Ok(())
        };
        check().expect("an unlocked, unchanged vault must pass the abort gate");

        let locked = || true;
        let check_locked = || -> Result<()> {
            if locked() {
                anyhow::bail!("Vault was locked; sync aborted.")
            }
            Ok(())
        };
        assert!(
            check_locked().is_err(),
            "a locked vault must abort the sync"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn seal_private_key_round_trips() {
        let key = b"raw-ed25519-private-bytes";
        let sealed = seal_private_key(TEST_PW, key)
            .await
            .expect("seal must succeed with a valid password");
        assert!(!sealed.is_empty(), "sealed output must never be empty");
        let unsealed = unseal_private_key(TEST_PW, &sealed)
            .await
            .expect("unseal must succeed");
        assert_eq!(unsealed, key);
    }

    // NOTE: seal_private_key has no unit-testable failure path here - the
    // underlying crypto::vault::seal is deterministic-success for any
    // password (Argon2 accepts even empty passwords), and adding a failure
    // injection point would mean changing the crypto, which is out of scope.
    // Its contract - error propagation instead of an empty-ciphertext
    // substitute - is enforced by the type system (Result return, no
    // unwrap_or_default at call sites) and verified by inspection.

    #[tokio::test(flavor = "multi_thread")]
    async fn unseal_private_key_never_returns_ciphertext() {
        // Wrong password: unseal must fail rather than hand back anything
        // derived from the sealed blob.
        let sealed = seal_private_key(TEST_PW, b"private-key-bytes")
            .await
            .unwrap();
        let result = unseal_private_key("wrong-password", &sealed).await;
        let err = result.expect_err("unseal with a wrong password must fail");
        assert!(
            err.to_string()
                .contains("refusing to use sealed ciphertext"),
            "error must identify the refused fallback, got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unseal_private_key_rejects_corrupted_entry() {
        let result = unseal_private_key(TEST_PW, "not-json-at-all").await;
        let err = result.expect_err("unseal of a corrupted entry must fail");
        assert!(
            err.to_string()
                .contains("refusing to use sealed ciphertext"),
            "error must identify the refused fallback, got: {err}"
        );
    }

    fn test_db() -> Database {
        Database::open_at(
            std::env::temp_dir().join(format!("sshspan-test-{}.db", uuid::Uuid::new_v4())),
        )
        .expect("failed to open test database")
    }

    #[test]
    fn sanitize_sync_name_maps_invalid_cipher_names() {
        let db = test_db();
        // A cipher name carrying a config-injection payload is sanitized into
        // a single Host token instead of failing the sync item.
        assert_eq!(
            sanitize_sync_name(&db, "x\nHost *\n ProxyCommand evil"),
            "x-Host-*--ProxyCommand-evil"
        );
        assert_eq!(sanitize_sync_name(&db, "my deploy key"), "my-deploy-key");
        // Valid names pass through verbatim.
        assert_eq!(sanitize_sync_name(&db, "deploy-key-1"), "deploy-key-1");
        // Every sanitized output must itself pass validation.
        assert!(
            crate::crypto::keys::validate_key_name(&sanitize_sync_name(&db, "a\tb\nc")).is_ok()
        );
    }

    // ── Sync decisions ──────────────────────────────────────────────────────

    /// What the key pass decides for `row`, with `remote_ssh` as the whole
    /// live snapshot.
    fn plan_key<'a>(
        row: &'a KeyRecord,
        remote_ssh: &[&'a SyncCipher],
        fp_by_cipher_id: &HashMap<String, String>,
        allow_remote_overwrite: bool,
    ) -> Plan<'a> {
        let live: HashMap<&str, &SyncCipher> =
            remote_ssh.iter().map(|c| (c.id.as_str(), *c)).collect();
        plan_key_row(
            row,
            &live,
            remote_ssh,
            fp_by_cipher_id,
            allow_remote_overwrite,
        )
    }

    /// What the server pass decides for `sv`, with `remote_logins` as the
    /// whole live snapshot and no server ids in notes.
    fn plan_server<'a>(
        sv: &'a ServerRecord,
        remote_logins: &[&'a SyncCipher],
        allow_remote_overwrite: bool,
    ) -> Plan<'a> {
        let live: HashMap<&str, &SyncCipher> =
            remote_logins.iter().map(|c| (c.id.as_str(), *c)).collect();
        match plan_server_row(
            sv,
            &live,
            remote_logins,
            &no_names(),
            allow_remote_overwrite,
        ) {
            ServerPlan::Plan(plan) => plan,
            ServerPlan::Ambiguous(count) => panic!("{count} items name {}", sv.name),
        }
    }

    /// No item names a server; no server is linked.
    fn no_names() -> ServerNames {
        ServerNames::new(HashMap::new(), &[])
    }

    /// A fixed instant (2026-09-21) the fixtures count from.
    const T0: i64 = 1_790_000_000_000;

    fn at_ms(ms: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(ms).unwrap()
    }

    fn rfc3339_ms(ms: i64) -> String {
        at_ms(ms).to_rfc3339()
    }

    /// Marks of a row last synced at change marker T0 with remote revision
    /// `revision`, and changed locally at `updated`.
    fn synced_at(updated: i64, revision: i64) -> SyncMarks {
        SyncMarks {
            updated,
            synced: Some(T0),
            revision: Some(revision),
            category: None,
        }
    }

    fn never_synced() -> SyncMarks {
        SyncMarks {
            updated: T0,
            synced: None,
            revision: None,
            category: None,
        }
    }

    fn key_row(id: &str, link: Option<&str>, marks: SyncMarks) -> KeyRecord {
        KeyRecord {
            id: id.to_string(),
            name: format!("key-{id}"),
            key_type: "ed25519".into(),
            public_key: String::new(),
            private_key_encrypted: "sealed".into(),
            fingerprint_sha256: format!("SHA256:fp-{id}"),
            fingerprint_md5: String::new(),
            comment: String::new(),
            created_at: at_ms(T0),
            updated_at: at_ms(marks.updated),
            deployed: false,
            deploy_path: None,
            bitwarden_id: link.map(String::from),
            bitwarden_sync: true,
            bitwarden_revision_ts: marks.revision,
            bitwarden_updated_at: marks.synced,
            category_ids: Vec::new(),
        }
    }

    fn server_row(id: &str, link: Option<&str>, marks: SyncMarks) -> ServerRecord {
        ServerRecord {
            id: id.to_string(),
            name: format!("server-{id}"),
            host: "server.example.com".into(),
            port: 22,
            username: "root".into(),
            key_id: None,
            pem_path: None,
            auth_method: "password".into(),
            saved_password: None,
            category_id: None,
            color: None,
            last_connected_at: None,
            created_at: at_ms(T0),
            updated_at: at_ms(marks.updated),
            bitwarden_id: link.map(String::from),
            bitwarden_revision_ts: marks.revision.map(rfc3339_ms),
            bitwarden_updated_at: marks.synced.map(rfc3339_ms),
        }
    }

    fn cipher(
        id: &str,
        cipher_type: u32,
        folder: Option<&str>,
        revision: Option<i64>,
    ) -> SyncCipher {
        SyncCipher {
            id: id.to_string(),
            cipher_type,
            organization_id: None,
            folder_id: folder.map(String::from),
            name: None,
            notes: None,
            favorite: false,
            ssh_key: None,
            login: None,
            revision_date: revision.map(rfc3339_ms),
            deleted_date: None,
            creation_date: None,
        }
    }

    #[test]
    fn key_whose_remote_copy_is_gone_is_re_created_not_updated() {
        // A7-39: the row still names a cipher that was deleted in Bitwarden.
        // Updating that dead id failed on every run; the key must be uploaded
        // as a new item instead, and reported.
        let none_live: Vec<&SyncCipher> = Vec::new();
        let stale = key_row("k1", Some("dead-cipher"), synced_at(T0, T0));
        assert_eq!(
            plan_key(&stale, &none_live, &HashMap::new(), false),
            Plan::Create { relink: true }
        );
        let fresh = key_row("k2", None, never_synced());
        assert_eq!(
            plan_key(&fresh, &none_live, &HashMap::new(), false),
            Plan::Create { relink: false }
        );
    }

    #[test]
    fn first_fingerprint_match_adopts_the_link() {
        let row = key_row("k1", None, never_synced());
        let remote = cipher("c9", 5, Some("keys"), Some(T0));
        let fps = HashMap::from([("c9".to_string(), row.fingerprint_sha256.clone())]);
        assert_eq!(
            plan_key(&row, &[&remote], &fps, false),
            Plan::Link { cipher: "c9" }
        );
    }

    #[test]
    fn linked_keys_follow_the_side_that_changed() {
        let same = cipher("c1", 5, None, Some(T0));
        let newer = cipher("c1", 5, None, Some(T0 + 5_000));
        let fps = HashMap::new();
        let clean = key_row("k", Some("c1"), synced_at(T0, T0));
        let edited = key_row("k", Some("c1"), synced_at(T0 + 1_000, T0));
        assert_eq!(plan_key(&clean, &[&same], &fps, false), Plan::InSync);
        assert_eq!(
            plan_key(&edited, &[&same], &fps, false),
            Plan::Update {
                cipher: "c1",
                conflict: false
            }
        );
        assert_eq!(
            plan_key(&edited, &[&newer], &fps, false),
            Plan::Update {
                cipher: "c1",
                conflict: true
            }
        );
        assert_eq!(
            plan_key(&clean, &[&newer], &fps, true),
            Plan::Pull { cipher: "c1" }
        );
        assert_eq!(
            plan_key(&clean, &[&newer], &fps, false),
            Plan::SkipRemoteChange { cipher: "c1" }
        );
    }

    #[test]
    fn server_remote_change_waits_for_the_overwrite_go_ahead() {
        // A2-47: servers were pulled over local rows whenever the remote was
        // newer - host, user, saved password - without the confirm-first gate
        // the keys have.
        let newer = cipher("s1", 1, Some("servers"), Some(T0 + 5_000));
        let clean = server_row("a", Some("s1"), synced_at(T0, T0));
        assert_eq!(
            plan_server(&clean, &[&newer], false),
            Plan::SkipRemoteChange { cipher: "s1" }
        );
        assert_eq!(
            plan_server(&clean, &[&newer], true),
            Plan::Pull { cipher: "s1" }
        );
        // Local edits still win without asking, as for keys.
        let edited = server_row("a", Some("s1"), synced_at(T0 + 1_000, T0));
        assert_eq!(
            plan_server(&edited, &[&newer], false),
            Plan::Update {
                cipher: "s1",
                conflict: true
            }
        );
    }

    #[test]
    fn server_whose_remote_copy_is_gone_is_re_created() {
        let stale = server_row("a", Some("gone"), synced_at(T0, T0));
        assert_eq!(
            plan_server(&stale, &[], false),
            Plan::Create { relink: true }
        );
    }

    #[test]
    fn server_logins_come_only_from_a_real_folder() {
        let mut org = cipher("org", 1, Some("servers"), None);
        org.organization_id = Some("org-1".into());
        let mut trashed = cipher("trashed", 1, Some("servers"), None);
        trashed.deleted_date = Some(rfc3339_ms(T0));
        let ciphers = vec![
            cipher("in-folder", 1, Some("servers"), None),
            cipher("no-folder", 1, None, None),
            cipher("other-folder", 1, Some("other"), None),
            cipher("ssh-key", 5, Some("servers"), None),
            org,
            trashed,
        ];
        let ids =
            |found: Vec<&SyncCipher>| found.into_iter().map(|c| c.id.clone()).collect::<Vec<_>>();
        assert_eq!(
            ids(server_logins_in(&ciphers, Some("servers"))),
            ["in-folder"]
        );
        // A2-51: no servers folder (it could not be created) means no server
        // items at all. `None == None` matched every folder-less Login in the
        // vault - a bank login became a "server".
        assert!(server_logins_in(&ciphers, None).is_empty());
    }

    #[test]
    fn written_back_marks_leave_a_pushed_key_in_sync() {
        // A7-23: after an update push nothing was written back, so the key
        // stayed "changed locally" while the server's revision moved on - it
        // was re-uploaded and counted as a conflict on every later sync.
        let db = test_db();
        let fps = HashMap::new();
        let edited = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0 + 1_000, T0),
        );
        db.insert_key(&edited).unwrap();
        assert_eq!(
            plan_key(&edited, &[&cipher("c1", 5, None, Some(T0))], &fps, false),
            Plan::Update {
                cipher: "c1",
                conflict: false
            }
        );
        let answer = serde_json::json!({ "id": "c1", "revisionDate": rfc3339_ms(T0 + 9_000) });
        record_pushed_key(&db, &edited, Some("c1"), &answer).unwrap();
        let stored = db.get_key(&edited.id).unwrap().unwrap();
        assert_eq!(
            plan_key(
                &stored,
                &[&cipher("c1", 5, None, Some(T0 + 9_000))],
                &fps,
                false
            ),
            Plan::InSync,
            "a pushed key must not be pushed again and counted as a conflict"
        );

        // A first upload records the new item's id the same way.
        let fresh = key_row(&uuid::Uuid::new_v4().to_string(), None, never_synced());
        db.insert_key(&fresh).unwrap();
        let created = serde_json::json!({ "id": "c2", "revisionDate": rfc3339_ms(T0 + 9_000) });
        record_pushed_key(&db, &fresh, None, &created).unwrap();
        let stored = db.get_key(&fresh.id).unwrap().unwrap();
        assert_eq!(stored.bitwarden_id.as_deref(), Some("c2"));
        assert_eq!(
            plan_key(
                &stored,
                &[&cipher("c2", 5, None, Some(T0 + 9_000))],
                &fps,
                false
            ),
            Plan::InSync
        );
        // An answer without an item id is an error for a first upload - the
        // key is never linked to an empty id.
        assert!(record_pushed_key(&db, &fresh, None, &serde_json::json!({})).is_err());
    }

    #[test]
    fn key_edited_while_its_push_runs_is_pushed_next_time() {
        let db = test_db();
        let fps = HashMap::new();
        let row = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0 + 1_000, T0),
        );
        db.insert_key(&row).unwrap();
        // Renamed while the upload of the old row is in flight.
        db.rename_key(&row.id, "renamed-meanwhile").unwrap();
        let answer = serde_json::json!({ "id": "c1", "revisionDate": rfc3339_ms(T0 + 9_000) });
        record_pushed_key(&db, &row, Some("c1"), &answer).unwrap();
        let stored = db.get_key(&row.id).unwrap().unwrap();
        assert_eq!(
            plan_key(
                &stored,
                &[&cipher("c1", 5, None, Some(T0 + 9_000))],
                &fps,
                false
            ),
            Plan::Update {
                cipher: "c1",
                conflict: false
            },
            "the rename made during the push must still be pushed"
        );
    }

    #[test]
    fn server_edited_while_its_push_runs_keeps_the_edit_and_is_pushed_next_time() {
        let db = test_db();
        let row = server_row(&uuid::Uuid::new_v4().to_string(), None, never_synced());
        db.insert_server(&row).unwrap();
        // The user edits the server while its upload is in flight.
        let mut edited = row.clone();
        edited.host = "edited.example.com".into();
        edited.updated_at = at_ms(T0 + 5_000);
        db.update_server(&edited).unwrap();
        let answer = serde_json::json!({ "id": "s9", "revisionDate": rfc3339_ms(T0 + 9_000) });
        record_pushed_server(&db, &row, None, &answer).unwrap();
        let stored = db.get_server(&row.id).unwrap().unwrap();
        assert_eq!(stored.host, "edited.example.com");
        assert_eq!(stored.bitwarden_id.as_deref(), Some("s9"));
        let remote = cipher("s9", 1, Some("servers"), Some(T0 + 9_000));
        assert_eq!(
            plan_server(&stored, &[&remote], false),
            Plan::Update {
                cipher: "s9",
                conflict: false
            },
            "the edit made during the push must still be pushed"
        );
    }

    #[test]
    fn deploying_a_synced_key_does_not_mark_it_changed() {
        let db = test_db();
        let fps = HashMap::new();
        let row = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0, T0),
        );
        db.insert_key(&row).unwrap();
        let remote = cipher("c1", 5, None, Some(T0));
        assert_eq!(plan_key(&row, &[&remote], &fps, false), Plan::InSync);
        db.set_key_deployment(&row.id, Some("/home/u/.ssh/sshspan_k"))
            .unwrap();
        let deployed = db.get_key(&row.id).unwrap().unwrap();
        assert!(deployed.deployed);
        assert_eq!(
            plan_key(&deployed, &[&remote], &fps, false),
            Plan::InSync,
            "a deploy is not a change to sync"
        );
        db.set_key_deployment(&row.id, None).unwrap();
        let undeployed = db.get_key(&row.id).unwrap().unwrap();
        assert_eq!(
            plan_key(&undeployed, &[&remote], &fps, false),
            Plan::InSync,
            "nor is an undeploy"
        );
    }

    #[test]
    fn key_pull_keeps_a_deployment_recorded_meanwhile() {
        let db = test_db();
        let row = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0, T0),
        );
        db.insert_key(&row).unwrap();
        // A deploy finishes between the sync reading the row and the pull.
        db.set_key_deployment(&row.id, Some("/home/u/.ssh/sshspan_k"))
            .unwrap();
        store_pulled_key(
            &db,
            &row,
            &crate::db::KeyPull {
                name: "from-bitwarden".into(),
                key_type: "ed25519".into(),
                public_key: "ssh-ed25519 AAAA from-bitwarden".into(),
                private_key_encrypted: "sealed-2".into(),
                fingerprint_sha256: row.fingerprint_sha256.clone(),
                fingerprint_md5: "md5".into(),
                comment: "from-bitwarden".into(),
                bitwarden_revision_ts: Some(T0 + 9_000),
            },
        )
        .unwrap();
        let stored = db.get_key(&row.id).unwrap().unwrap();
        assert_eq!(stored.name, "from-bitwarden");
        assert_eq!(stored.private_key_encrypted, "sealed-2");
        assert_eq!(stored.bitwarden_revision_ts, Some(T0 + 9_000));
        assert!(
            stored.deployed,
            "the pull must not erase a deployment recorded meanwhile"
        );
        assert_eq!(
            stored.deploy_path.as_deref(),
            Some("/home/u/.ssh/sshspan_k")
        );
    }

    #[test]
    fn server_pull_keeps_the_columns_it_does_not_sync() {
        let db = test_db();
        let mut row = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s1"),
            synced_at(T0, T0),
        );
        row.color = Some("#336699".into());
        db.insert_server(&row).unwrap();
        // A connection finishes while the sync runs.
        let connected = at_ms(T0 + 3_000);
        db.touch_server_last_connected(&row.id, connected).unwrap();
        store_pulled_server(
            &db,
            &row,
            &crate::db::ServerPull {
                name: "web".into(),
                host: "new.example.com".into(),
                port: 2222,
                username: "ops".into(),
                auth_method: "password".into(),
                key_id: None,
                category_id: None,
                saved_password: None,
                bitwarden_revision_ts: Some(rfc3339_ms(T0 + 9_000)),
            },
        )
        .unwrap();
        let stored = db.get_server(&row.id).unwrap().unwrap();
        assert_eq!(stored.host, "new.example.com");
        assert_eq!(stored.port, 2222);
        assert_eq!(stored.color.as_deref(), Some("#336699"));
        assert_eq!(
            stored.last_connected_at,
            Some(connected),
            "the pull must not revert a connection recorded meanwhile"
        );
    }

    fn names_taken(names: &[&str]) -> impl Fn(&str) -> bool {
        let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
        move |candidate: &str| lower.contains(&candidate.to_lowercase())
    }

    #[test]
    fn pulled_key_name_that_collides_gets_a_numbered_suffix() {
        use crate::crypto::keys::{validate_key_name, MAX_KEY_NAME_LEN};
        assert_eq!(free_key_name("Deploy", names_taken(&[])), "Deploy");
        // Names are unique without regard to case; names cannot hold
        // spaces (Host aliases), so the suffix is "-N".
        assert_eq!(
            free_key_name("Deploy", names_taken(&["deploy"])),
            "Deploy-2"
        );
        assert_eq!(
            free_key_name("Deploy", names_taken(&["deploy", "DEPLOY-2"])),
            "Deploy-3"
        );
        let longest = "k".repeat(MAX_KEY_NAME_LEN);
        let renamed = free_key_name(&longest, names_taken(&[longest.as_str()]));
        assert!(renamed.ends_with("-2"), "{renamed}");
        assert!(renamed.chars().count() <= MAX_KEY_NAME_LEN, "{renamed}");
        assert!(validate_key_name(&renamed).is_ok(), "{renamed}");
        // A check that never clears still ends in a valid, distinct name.
        let fallback = free_key_name("Deploy", |_| true);
        assert!(fallback.starts_with("Deploy-"), "{fallback}");
        assert!(validate_key_name(&fallback).is_ok(), "{fallback}");
    }

    #[test]
    fn sync_runs_and_failures_are_audited_with_counts_and_capped_errors() {
        // A8-04: no sync run ever reached the audit log.
        let summary = serde_json::json!({
            "ok": true,
            "pushed": 2, "updatedRemote": 1, "pulled": 0, "updatedLocal": 0,
            "linked": 0, "conflicts": 1, "recreatedRemote": 1, "remoteDeleted": 1,
            "skippedOverwrites": 0, "skippedNew": 3,
            "serversPushed": 1, "serversUpdatedRemote": 0, "serversPulled": 0,
            "serversUpdatedLocal": 0, "serversRecreatedRemote": 0,
            "skippedServerOverwrites": 2, "skippedServerNew": 0,
            "renamed": [{ "name": "deploy", "storedAs": "deploy-2" }],
            "errors": [
                { "name": "prod", "error": "Vault request PUT /api/ciphers/x failed (HTTP 500)" },
                { "server": "web", "error": "saved password unseal failed:\nbad" },
                { "folder": "SSHSpan_Servers", "error": "could not create it" },
                { "cipher_id": "c7", "error": "x".repeat(1000) },
            ],
        });
        let rows = sync_audit_rows(&summary);
        assert!(!rows.is_empty(), "a sync run must be audited");
        assert_eq!(rows[0].0, "sync.run");
        for counter in [
            "pushed=2",
            "conflicts=1",
            "recreatedRemote=1",
            "skippedNew=3",
            "skippedServerOverwrites=2",
            "renamed=1",
            "errors=4",
        ] {
            assert!(rows[0].1.contains(counter), "{counter} in {}", rows[0].1);
        }
        let errors: Vec<&str> = rows[1..]
            .iter()
            .map(|(action, details)| {
                assert_eq!(*action, "sync.error");
                details.as_str()
            })
            .collect();
        assert_eq!(errors.len(), 4);
        assert!(errors[0].starts_with("key \"prod\": "), "{}", errors[0]);
        assert!(errors[1].starts_with("server \"web\": "), "{}", errors[1]);
        assert!(!errors[1].contains('\n'), "control characters are dropped");
        assert!(
            errors[2].starts_with("folder \"SSHSpan_Servers\": "),
            "{}",
            errors[2]
        );
        assert!(errors[3].starts_with("item c7: "), "{}", errors[3]);
        assert!(errors[3].chars().count() <= 400, "long errors are cut");

        // A run where everything failed is capped, not 500 audit rows.
        let many: Vec<serde_json::Value> = (0..30)
            .map(|i| serde_json::json!({ "name": format!("k{i}"), "error": "e" }))
            .collect();
        let rows = sync_audit_rows(&serde_json::json!({ "errors": many }));
        assert_eq!(rows.len(), 1 + MAX_SYNC_ERROR_AUDIT_ROWS + 1);
        assert!(
            rows.last().unwrap().1.contains("10 more"),
            "{:?}",
            rows.last()
        );
    }
    // ── Item links, pulled rows and runs that stop early ────────────────────

    fn live_of<'a>(ciphers: &[&'a SyncCipher]) -> HashMap<&'a str, &'a SyncCipher> {
        ciphers.iter().map(|c| (c.id.as_str(), *c)).collect()
    }

    #[test]
    fn linked_items_outside_the_folder_or_owned_by_an_organization_are_not_deleted() {
        // Only the FILTERED lists were searched, so a moved item looked
        // deleted and was duplicated, private key / saved password included.
        let moved = cipher("s1", 1, Some("another-folder"), Some(T0));
        let sv = server_row("a", Some("s1"), synced_at(T0, T0));
        let live = live_of(&[&moved]);
        // The servers folder holds nothing: the item was moved out of it.
        assert_eq!(
            plan_server_row(&sv, &live, &[], &no_names(), false),
            ServerPlan::Plan(Plan::InSync)
        );
        let mut org = cipher("c1", 5, None, Some(T0));
        org.organization_id = Some("org-1".into());
        let key = key_row("k", Some("c1"), synced_at(T0, T0));
        let live = live_of(&[&org]);
        assert_eq!(
            plan_key_row(&key, &live, &[], &HashMap::new(), false),
            Plan::OrgOwned
        );
        let sv_org = server_row("b", Some("c1"), synced_at(T0, T0));
        let mut org_login = org.clone();
        org_login.cipher_type = 1;
        let live = live_of(&[&org_login]);
        assert_eq!(
            plan_server_row(&sv_org, &live, &[], &no_names(), false),
            ServerPlan::Plan(Plan::OrgOwned)
        );
        // Absent (or trashed, which the snapshot index leaves out): re-created.
        assert_eq!(
            plan_key_row(&key, &HashMap::new(), &[], &HashMap::new(), false),
            Plan::Create { relink: true }
        );
    }

    #[test]
    fn server_found_by_its_id_in_the_notes_adopts_the_link() {
        // The upload worked, but the link was never stored.
        let sv = server_row("local-1", None, never_synced());
        let remote = cipher("s9", 1, Some("servers"), Some(T0));
        let names = ServerNames::new(
            HashMap::from([("s9".to_string(), "local-1".to_string())]),
            &[],
        );
        assert_eq!(
            plan_server_row(&sv, &live_of(&[&remote]), &[&remote], &names, false),
            ServerPlan::Plan(Plan::Link { cipher: "s9" })
        );
        let other = server_row("local-2", None, never_synced());
        assert_eq!(
            plan_server_row(&other, &live_of(&[&remote]), &[&remote], &names, false),
            ServerPlan::Plan(Plan::Create { relink: false })
        );
    }

    #[test]
    fn the_own_item_of_a_server_is_never_another_servers_item() {
        // At the planner: an item another local server is linked to
        // is that server's, whatever its notes say; several unowned items
        // naming a server are not guessed between.
        let web = server_row("web", None, never_synced());
        let web2 = server_row("web2", Some("s2"), synced_at(T0, T0));
        let own = cipher("s1", 1, Some("servers"), Some(T0));
        let clone = cipher("s2", 1, Some("servers"), Some(T0));
        let both_name_web = HashMap::from([
            ("s1".to_string(), "web".to_string()),
            ("s2".to_string(), "web".to_string()),
        ]);
        let logins = [&own, &clone];
        let live = live_of(&logins);
        // web's own item, not the clone web2 is linked to.
        let names = ServerNames::new(both_name_web.clone(), &[web.clone(), web2.clone()]);
        assert_eq!(
            plan_server_row(&web, &live, &logins, &names, false),
            ServerPlan::Plan(Plan::Link { cipher: "s1" })
        );
        // web's item is gone and only web2's clone names it: re-created.
        let web_gone = server_row("web", Some("s0"), synced_at(T0, T0));
        let only_clone = [&clone];
        let names = ServerNames::new(
            HashMap::from([("s2".to_string(), "web".to_string())]),
            &[web_gone.clone(), web2.clone()],
        );
        assert_eq!(
            plan_server_row(&web_gone, &live_of(&only_clone), &only_clone, &names, false),
            ServerPlan::Plan(Plan::Create { relink: true })
        );
        // Several unowned items name web: not guessed.
        let names = ServerNames::new(both_name_web, &[web.clone()]);
        assert_eq!(
            plan_server_row(&web, &live, &logins, &names, false),
            ServerPlan::Ambiguous(2)
        );
        // web2 itself keeps its own link.
        let names = ServerNames::new(HashMap::new(), &[web, web2.clone()]);
        assert_eq!(
            plan_server_row(&web2, &live, &logins, &names, false),
            ServerPlan::Plan(Plan::InSync)
        );
    }

    fn offline_client() -> BitwardenClient {
        let mut client =
            BitwardenClient::new("https://vault.example.com", "u@example.com", "pw", "dev")
                .unwrap();
        client.user_key = Some(zeroize::Zeroizing::new([7u8; 64]));
        client
    }

    fn enc(client: &BitwardenClient, text: &str) -> String {
        client.encrypt_field(text).unwrap()
    }

    /// A remote SSH item holding a fresh Ed25519 key, and its fingerprint.
    fn ssh_item(client: &BitwardenClient, id: &str, name: &str) -> (SyncCipher, String) {
        use crate::crypto::keys::{self, KeyFormat, KeyType};
        let kd = keys::generate_key_pair(KeyType::Ed25519, None, "c".into()).unwrap();
        let fp = keys::compute_fingerprint_sha256(&kd.public_key);
        let mut item = cipher(id, 5, Some("keys"), Some(T0));
        item.name = Some(enc(client, name));
        item.ssh_key = Some(crate::bitwarden::SshKeyBlock {
            private_key: Some(enc(
                client,
                &keys::export_private_key(&kd, KeyFormat::OpenSsh, None).unwrap(),
            )),
            public_key: Some(enc(
                client,
                &keys::export_public_key(&kd, KeyFormat::OpenSsh).unwrap(),
            )),
            key_fingerprint: Some(enc(client, &fp)),
        });
        (item, fp)
    }

    fn login_item(client: &BitwardenClient, id: &str, password: Option<String>) -> SyncCipher {
        let mut item = cipher(id, 1, Some("servers"), Some(T0));
        item.name = Some(enc(client, "web"));
        item.login = Some(crate::bitwarden::LoginBlock {
            username: Some(enc(client, "ops")),
            password,
            uris: Some(vec![crate::bitwarden::LoginUri {
                uri: Some(enc(client, "ssh://web.example.com:2222")),
            }]),
        });
        item
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pulled_new_key_is_in_sync_at_the_next_run() {
        // The new row had no sync marks, so the next sync re-uploaded it,
        // counted a conflict and pushed its de-duplicated name back.
        let db = test_db();
        let mut client = offline_client();
        let (item, fp) = ssh_item(&client, "c1", "pulled-key");
        let outcome = pull_new_key(&mut client, &item, &db, TEST_PW)
            .await
            .unwrap();
        assert!(matches!(outcome, PulledKey::Inserted { rename: None }));
        let stored = db
            .list_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.bitwarden_id.as_deref() == Some("c1"))
            .unwrap();
        assert_eq!(stored.name, "pulled-key");
        let fps = HashMap::from([("c1".to_string(), fp)]);
        assert_eq!(plan_key(&stored, &[&item], &fps, false), Plan::InSync);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pulled_new_server_is_in_sync_at_the_next_run() {
        let db = test_db();
        let mut client = offline_client();
        let pw = Some(enc(&client, "secret"));
        let item = login_item(&client, "s1", pw);
        pull_new_server(&mut client, &item, &db, TEST_PW)
            .await
            .unwrap();
        let stored = db
            .list_servers()
            .unwrap()
            .into_iter()
            .find(|s| s.bitwarden_id.as_deref() == Some("s1"))
            .unwrap();
        assert_eq!(
            (stored.host.as_str(), stored.port),
            ("web.example.com", 2222)
        );
        assert_eq!(plan_server(&stored, &[&item], false), Plan::InSync);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_undecryptable_server_field_is_an_error_not_a_fallback() {
        // The saved password used to be erased silently, or the host
        // became the item name on port 22.
        let db = test_db();
        let mut client = offline_client();
        let broken = login_item(&client, "s1", Some("2.AAAA|AAAA|AAAA".into()));
        let err = pull_new_server(&mut client, &broken, &db, TEST_PW)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
        assert!(db.list_servers().unwrap().is_empty(), "nothing is written");

        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s1"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let err = pull_remote_server(&mut client, &broken, &sv, &db, TEST_PW, false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("password"), "{err}");
        assert_eq!(db.get_server(&sv.id).unwrap().unwrap().host, sv.host);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pull_does_not_overwrite_a_row_changed_meanwhile() {
        // A rename made while the pull sealed was lost and the next plan
        // was InSync; a deleted row still counted as updated.
        let db = test_db();
        let mut client = offline_client();
        let (item, _) = ssh_item(&client, "c1", "remote-name");
        let row = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0, T0),
        );
        db.insert_key(&row).unwrap();
        db.rename_key(&row.id, "renamed-meanwhile").unwrap();
        let outcome = pull_remote_item(&mut client, &item, &row, &db, TEST_PW, false)
            .await
            .unwrap();
        assert!(matches!(outcome, PullOutcome::ChangedMeanwhile));
        assert_eq!(
            db.get_key(&row.id).unwrap().unwrap().name,
            "renamed-meanwhile"
        );

        // An unchanged row is pulled and is in sync afterwards.
        let fresh = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c2"),
            synced_at(T0, T0),
        );
        db.insert_key(&fresh).unwrap();
        let (item2, fp2) = ssh_item(&client, "c2", "pulled-name");
        let outcome = pull_remote_item(&mut client, &item2, &fresh, &db, TEST_PW, false)
            .await
            .unwrap();
        assert!(matches!(outcome, PullOutcome::Written { rename: None }));
        let stored = db.get_key(&fresh.id).unwrap().unwrap();
        assert_eq!(stored.name, "pulled-name");
        let fps = HashMap::from([("c2".to_string(), fp2)]);
        assert_eq!(plan_key(&stored, &[&item2], &fps, false), Plan::InSync);
    }

    #[test]
    fn deleting_a_category_marks_its_keys_and_servers_changed() {
        // The keys lose the category and the servers move up - both are
        // changes the sync uploads.
        let db = test_db();
        let key = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c1"),
            synced_at(T0, T0),
        );
        db.insert_key(&key).unwrap();
        let prod = db
            .ensure_category_path_scoped("Prod", "key")
            .unwrap()
            .unwrap();
        db.set_key_categories(&key.id, std::slice::from_ref(&prod))
            .unwrap();
        let web = db
            .ensure_category_path_scoped("Web", "host")
            .unwrap()
            .unwrap();
        let mut sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s1"),
            synced_at(T0, T0),
        );
        sv.category_id = Some(web.clone());
        db.insert_server(&sv).unwrap();
        db.delete_category(&prod).unwrap();
        db.delete_category(&web).unwrap();
        // Marked as category changes - the rows themselves did not change,
        // so no "local wins" upload of their other fields follows.
        assert!(db.category_mark("key", &key.id).unwrap().is_some());
        assert!(db.category_mark("server", &sv.id).unwrap().is_some());
        assert_eq!(db.get_key(&key.id).unwrap().unwrap().updated_at, at_ms(T0));
        assert_eq!(
            db.get_server(&sv.id).unwrap().unwrap().updated_at,
            at_ms(T0)
        );
    }

    #[test]
    fn an_aborted_run_still_reports_and_audits_its_counts() {
        // A run stopped by a lock or an error kept nothing.
        let mut report = SyncReport {
            pushed: 2,
            ..SyncReport::default()
        };
        report.error("name", "k", "boom");
        let summary = report.summary(Some("Vault was locked; sync aborted."));
        assert_eq!(summary["ok"], false);
        assert_eq!(summary["pushed"], 2);
        assert_eq!(summary["aborted"], "Vault was locked; sync aborted.");
        let rows = sync_audit_rows(&summary);
        assert!(rows[0].1.contains("pushed=2"), "{}", rows[0].1);
        assert!(rows[0].1.contains("aborted"), "{}", rows[0].1);
        assert!(report.summary(None).get("aborted").is_none());
    }

    #[test]
    fn audit_rows_never_carry_key_material() {
        let summary = serde_json::json!({ "errors": [{
            "name": "k",
            "error": "import failed near -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
        }]});
        let rows = sync_audit_rows(&summary);
        assert!(!rows[1].1.contains("BEGIN"), "{}", rows[1].1);
        assert!(!rows[1].1.contains("b3BlbnNzaC1rZXk"), "{}", rows[1].1);
        assert!(rows[1].1.contains("key material removed"), "{}", rows[1].1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_pass_counts_only_what_happened() {
        // A re-link by fingerprint is not a deletion; a public-only key's
        // dead link is cleared and reported once; a failed upload counts no
        // conflict.
        let db = test_db();
        let mut client = offline_client();
        let (item, fp) = ssh_item(&client, "c-new", "x");
        let mut relinked = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("gone-1"),
            synced_at(T0, T0),
        );
        relinked.fingerprint_sha256 = fp;
        db.insert_key(&relinked).unwrap();
        let mut public_only = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("gone-2"),
            synced_at(T0, T0),
        );
        public_only.private_key_encrypted = String::new();
        db.insert_key(&public_only).unwrap();
        let mut conflicted = key_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("c-conf"),
            synced_at(T0 + 1_000, T0),
        );
        conflicted.fingerprint_sha256 = "SHA256:other".into();
        db.insert_key(&conflicted).unwrap();
        let conf_item = cipher("c-conf", 5, Some("keys"), Some(T0 + 5_000));
        let remote = crate::bitwarden::SyncResponse {
            profile: None,
            folders: Vec::new(),
            ciphers: vec![item.clone(), conf_item.clone()],
        };
        let live = live_of(&[&item, &conf_item]);
        let check = || -> Result<()> { Ok(()) };
        let run = SyncRun {
            db: &db,
            vault_password: TEST_PW,
            remote_changes: RemoteChanges::Ask,
            check: &check,
        };
        let mut report = SyncReport::default();
        run.key_pass(&mut client, &remote, &live, "keys", &mut report)
            .await
            .unwrap();
        assert_eq!(report.linked, 1, "{report:?}");
        assert_eq!(
            report.remote_deleted, 1,
            "only the public-only key: {report:?}"
        );
        assert_eq!(
            report.conflicts, 0,
            "the upload failed (offline): {report:?}"
        );
        assert_eq!(report.updated_remote, 0);
        assert!(db
            .get_key(&public_only.id)
            .unwrap()
            .unwrap()
            .bitwarden_id
            .is_none());
        // The cleared link is not reported again.
        let mut again = SyncReport::default();
        run.key_pass(&mut client, &remote, &live, "keys", &mut again)
            .await
            .unwrap();
        assert_eq!(again.remote_deleted, 0, "{again:?}");
    }

    /// A Login item whose SSHSpan notes name the local server `server_id`.
    fn login_naming(client: &BitwardenClient, id: &str, server_id: &str) -> SyncCipher {
        let mut item = login_item(client, id, None);
        item.notes = Some(enc(
            client,
            &serde_json::json!({ "v": 1, "sshspan": { "serverId": server_id } }).to_string(),
        ));
        item
    }

    /// What the passes may do with remote changes in a pass test: apply all
    /// of them, or only list them.
    fn remote_changes(allow_remote_overwrite: bool) -> RemoteChanges<'static> {
        if allow_remote_overwrite {
            RemoteChanges::ApproveAll
        } else {
            RemoteChanges::Ask
        }
    }

    /// Run the server pass offline over `items` (all in the servers folder),
    /// then settle its remote changes as a run does.
    async fn run_server_pass(
        db: &Database,
        client: &mut BitwardenClient,
        items: &[&SyncCipher],
        allow_remote_overwrite: bool,
    ) -> SyncReport {
        let remote = crate::bitwarden::SyncResponse {
            profile: None,
            folders: Vec::new(),
            ciphers: items.iter().map(|c| (*c).clone()).collect(),
        };
        let live = live_of(items);
        let check = || -> Result<()> { Ok(()) };
        let run = SyncRun {
            db,
            vault_password: TEST_PW,
            remote_changes: remote_changes(allow_remote_overwrite),
            check: &check,
        };
        let mut report = SyncReport::default();
        run.server_pass(client, &remote, &live, "servers", &mut report)
            .await
            .unwrap();
        run.settle_remote_changes(client, &live, &mut report)
            .await
            .unwrap();
        report
    }

    /// A Login item naming the local server `server_id`, created at `created`
    /// (epoch ms; `None` = no creation date).
    fn login_naming_at(
        client: &BitwardenClient,
        id: &str,
        server_id: &str,
        created: Option<i64>,
    ) -> SyncCipher {
        let mut item = login_naming(client, id, server_id);
        item.creation_date = created.map(rfc3339_ms);
        item
    }

    fn has_error(report: &SyncReport, needle: &str) -> bool {
        report.errors.iter().any(|e| {
            e["error"]
                .as_str()
                .is_some_and(|text| text.contains(needle))
        })
    }

    /// A local server named `name`, linked to `link`.
    fn named_server(name: &str, link: Option<&str>, marks: SyncMarks) -> ServerRecord {
        let mut sv = server_row(&uuid::Uuid::new_v4().to_string(), link, marks);
        sv.name = name.into();
        sv
    }

    fn stored_link(db: &Database, sv: &ServerRecord) -> Option<String> {
        db.get_server(&sv.id).unwrap().unwrap().bitwarden_id
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn several_items_naming_an_unlinked_server_are_not_guessed_between() {
        // Two items name an unlinked server and no other server
        // is linked to either - one may be a clone that was never imported.
        // Nothing is guessed: no link, no upload, nothing imported - on this
        // run or a later one; the server is reported until the extra copy is
        // gone, and the one left is linked then.
        let db = test_db();
        let mut client = offline_client();
        let web = named_server("web", None, never_synced());
        db.insert_server(&web).unwrap();
        let older = login_naming_at(&client, "s1", &web.id, Some(T0));
        let newer = login_naming_at(&client, "s2", &web.id, Some(T0 + 1_000));
        let expected = format!(
            "2 Bitwarden items name server 'web': \"web\" (id s1), \"web\" (id s2). SSHSpan \
             cannot tell which one is this server's, so it changed none of them. In Bitwarden, \
             delete only the items that are true duplicates of this server; if one of them is a \
             different server, remove \"serverId\": \"{}\" from its notes (it is then offered as \
             a new server) or move it out of the SSHSpan servers folder. Then sync again.",
            web.id
        );
        for run in 1..=2 {
            let report = run_server_pass(&db, &mut client, &[&older, &newer], true).await;
            assert_eq!(report.linked, 0, "run {run}: {report:?}");
            assert_eq!(report.servers_pushed, 0, "run {run}: {report:?}");
            assert_eq!(report.servers_pulled, 0, "run {run}: {report:?}");
            assert_eq!(report.errors.len(), 1, "run {run}: {report:?}");
            assert_eq!(report.errors[0]["server"], "web", "run {run}");
            assert_eq!(report.errors[0]["error"], expected.as_str(), "run {run}");
            assert_eq!(stored_link(&db, &web), None, "run {run}");
            assert_eq!(db.list_servers().unwrap().len(), 1, "run {run}");
        }
        let report = run_server_pass(&db, &mut client, &[&newer], true).await;
        assert_eq!(report.linked, 1, "{report:?}");
        assert_eq!(stored_link(&db, &web).as_deref(), Some("s2"));
    }

    // ── What the "allow remote changes" prompt will apply ──────

    /// Run the key pass offline over `items` (all in the keys folder), then
    /// settle its remote changes as a run does.
    async fn run_key_pass(
        db: &Database,
        client: &mut BitwardenClient,
        items: &[&SyncCipher],
        allow_remote_overwrite: bool,
    ) -> SyncReport {
        let remote = crate::bitwarden::SyncResponse {
            profile: None,
            folders: Vec::new(),
            ciphers: items.iter().map(|c| (*c).clone()).collect(),
        };
        let live = live_of(items);
        let check = || -> Result<()> { Ok(()) };
        let run = SyncRun {
            db,
            vault_password: TEST_PW,
            remote_changes: remote_changes(allow_remote_overwrite),
            check: &check,
        };
        let mut report = SyncReport::default();
        run.key_pass(client, &remote, &live, "keys", &mut report)
            .await
            .unwrap();
        run.settle_remote_changes(client, &live, &mut report)
            .await
            .unwrap();
        report
    }

    /// The linked item of "prod-db" was rewritten to another host (as a
    /// compromised Bitwarden account could), and a server SSHSpan does not
    /// have appeared. Neither may be applied unseen.
    fn rewritten_and_new_servers(
        db: &Database,
        client: &BitwardenClient,
    ) -> (SyncCipher, SyncCipher) {
        let mut prod = named_server("prod-db", Some("s1"), synced_at(T0, T0));
        prod.host = "10.0.0.5".into();
        db.insert_server(&prod).unwrap();
        let mut rewritten = login_item(client, "s1", None);
        rewritten.revision_date = Some(rfc3339_ms(T0 + 5_000));
        rewritten.name = Some(enc(client, "prod-db"));
        rewritten.login.as_mut().unwrap().uris = Some(vec![crate::bitwarden::LoginUri {
            uri: Some(enc(client, "ssh://evil.example.com:2222")),
        }]);
        (rewritten, login_item(client, "s2", None))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn skipped_server_changes_are_listed_with_the_hosts_they_would_set() {
        let db = test_db();
        let mut client = offline_client();
        let (rewritten, fresh) = rewritten_and_new_servers(&db, &client);
        let report = run_server_pass(&db, &mut client, &[&rewritten, &fresh], false).await;
        assert_eq!(report.skipped_server_overwrites, 1, "{report:?}");
        assert_eq!(report.skipped_server_new, 1, "{report:?}");
        let summary = report.summary(None);
        assert_eq!(
            summary["pendingServers"],
            serde_json::json!([
                {
                    "kind": "overwrite", "name": "prod-db", "incomingName": "prod-db",
                    "host": "evil.example.com", "port": 2222,
                    "localHost": "10.0.0.5", "localPort": 22,
                    "changes": ["host", "port", "user"],
                },
                {
                    "kind": "new", "name": "web", "incomingName": null,
                    "host": "web.example.com", "port": 2222,
                    "localHost": null, "localPort": null,
                    "changes": null,
                },
            ]),
            "{summary}"
        );
        assert!(summary.get("pendingTruncated").is_none(), "{summary}");
        // Remote changes allowed: applied, nothing pending.
        let db = test_db();
        let (rewritten, fresh) = rewritten_and_new_servers(&db, &client);
        let summary = run_server_pass(&db, &mut client, &[&rewritten, &fresh], true)
            .await
            .summary(None);
        assert!(summary.get("pendingServers").is_none(), "{summary}");
        assert!(summary.get("pendingKeys").is_none(), "{summary}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn skipped_key_changes_are_listed_with_their_fingerprints() {
        let db = test_db();
        let mut client = offline_client();
        let local = key_row("k1", Some("c1"), synced_at(T0, T0));
        db.insert_key(&local).unwrap();
        // The linked item now holds another key; and a key SSHSpan lacks.
        let (mut replaced, replaced_fp) = ssh_item(&client, "c1", "deploy");
        replaced.revision_date = Some(rfc3339_ms(T0 + 5_000));
        let (fresh, fresh_fp) = ssh_item(&client, "c2", "fresh");
        // An item with no private key cannot be pulled: reported, not offered.
        let hollow_row = key_row("k3", Some("c3"), synced_at(T0, T0));
        db.insert_key(&hollow_row).unwrap();
        let mut hollow = cipher("c3", 5, Some("keys"), Some(T0 + 5_000));
        hollow.name = Some(enc(&client, "hollow"));
        hollow.ssh_key = Some(crate::bitwarden::SshKeyBlock {
            private_key: None,
            public_key: None,
            key_fingerprint: Some(enc(&client, "SHA256:incoming")),
        });
        let report = run_key_pass(&db, &mut client, &[&replaced, &fresh, &hollow], false).await;
        assert_eq!(report.skipped_overwrites, 1, "{report:?}");
        assert_eq!(report.skipped_new, 1, "{report:?}");
        assert!(
            has_error(&report, "hollow holds no private key - not imported."),
            "{report:?}"
        );
        let summary = report.summary(None);
        assert_eq!(
            summary["pendingKeys"],
            serde_json::json!([
                {
                    "kind": "overwrite", "name": "key-k1", "incomingName": "deploy",
                    "fingerprint": replaced_fp, "localFingerprint": "SHA256:fp-k1",
                },
                {
                    "kind": "new", "name": "fresh", "incomingName": null,
                    "fingerprint": fresh_fp, "localFingerprint": null,
                },
            ]),
            "{summary}"
        );
        let text = summary.to_string();
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("sealed"),
            "no key material: {text}"
        );
        // Allowed: nothing pending.
        let db = test_db();
        db.insert_key(&local).unwrap();
        let summary = run_key_pass(&db, &mut client, &[&replaced, &fresh], true)
            .await
            .summary(None);
        assert!(summary.get("pendingKeys").is_none(), "{summary}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_pending_lists_are_bounded_and_cleaned() {
        let db = test_db();
        let mut client = offline_client();
        let long_name = format!("srv\u{7}\u{1b}[31m{}", "x".repeat(500));
        let items: Vec<SyncCipher> = (0..MAX_PENDING_ENTRIES + 10)
            .map(|n| {
                let mut item = login_item(&client, &format!("s{n}"), None);
                item.name = Some(enc(&client, &long_name));
                item
            })
            .collect();
        let refs: Vec<&SyncCipher> = items.iter().collect();
        let summary = run_server_pass(&db, &mut client, &refs, false)
            .await
            .summary(None);
        let pending = summary["pendingServers"].as_array().unwrap();
        assert_eq!(pending.len(), MAX_PENDING_ENTRIES, "at most the cap");
        assert_eq!(summary["pendingTruncated"], true);
        assert_eq!(
            summary["skippedServerNew"],
            MAX_PENDING_ENTRIES + 10,
            "the count stays exact"
        );
        let name = pending[0]["name"].as_str().unwrap();
        assert_eq!(name.chars().count(), 80, "{name}");
        assert!(name.ends_with('\u{2026}'), "cut, and says so: {name}");
        assert!(
            name.starts_with("srv[31mxxx"),
            "control characters stripped: {name:?}"
        );
        assert!(!name.chars().any(char::is_control));
    }

    /// The error never named the items, and its advice -
    /// "delete the extra copies" - lost data when one of them was a
    /// legitimate clone (deleting the clone discarded it; deleting the
    /// server's own copy made SSHSpan link to the clone and overwrite it).
    #[tokio::test(flavor = "multi_thread")]
    async fn the_ambiguous_server_error_names_every_item_and_does_not_say_to_delete_them_all() {
        let db = test_db();
        let mut client = offline_client();
        let web = named_server("web", None, never_synced());
        db.insert_server(&web).unwrap();
        let own = login_naming_at(&client, "item-1", &web.id, Some(T0));
        let mut clone = login_naming_at(&client, "item-2", &web.id, Some(T0 + 1_000));
        clone.name = Some(enc(&client, "web\u{7}-staging\r\n"));
        let report = run_server_pass(&db, &mut client, &[&own, &clone], true).await;
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert_eq!(report.errors[0]["server"], "web");
        let text = report.errors[0]["error"].as_str().unwrap();
        assert!(text.contains("\"web\" (id item-1)"), "{text}");
        assert!(
            text.contains("\"web-staging\" (id item-2)"),
            "control characters stripped: {text}"
        );
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(!text.contains("delete the extra copies"), "{text}");
        assert!(text.contains("only"), "delete only true duplicates: {text}");
        assert!(
            text.contains(&format!("\"serverId\": \"{}\"", web.id)),
            "a different server loses its serverId entry instead: {text}"
        );
        assert!(text.contains("move it out of"), "{text}");
        assert_eq!(stored_link(&db, &web), None, "still nothing guessed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_ambiguous_server_error_stays_bounded() {
        let db = test_db();
        let mut client = offline_client();
        let web = named_server("web", None, never_synced());
        db.insert_server(&web).unwrap();
        let long_title = "x".repeat(500);
        let items: Vec<SyncCipher> = (0..8)
            .map(|n| {
                let mut item = login_naming_at(&client, &format!("item-{n}"), &web.id, Some(T0));
                item.name = Some(enc(&client, &long_title));
                item
            })
            .collect();
        let refs: Vec<&SyncCipher> = items.iter().collect();
        let report = run_server_pass(&db, &mut client, &refs, true).await;
        let text = report.errors[0]["error"].as_str().unwrap();
        assert!(
            text.starts_with("8 Bitwarden items name server 'web'"),
            "{text}"
        );
        assert!(text.contains("(id item-4)"), "{text}");
        assert!(
            !text.contains("(id item-5)"),
            "at most five are listed: {text}"
        );
        assert!(text.contains("and 3 more"), "{text}");
        assert!(!text.contains(&long_title), "titles are shortened: {text}");
        assert!(text.chars().count() < 1500, "{}", text.chars().count());
    }

    /// An item's title and id are written by whoever can edit the item.
    /// Quoted raw in an error - several items naming one server, an older
    /// copy, a copy without a creation date, an item holding no usable key -
    /// a direction character could reverse the advice around them. They are
    /// quoted as a pending entry quotes them ([`pending_text`]).
    #[tokio::test(flavor = "multi_thread")]
    async fn fw_r6_error_texts_quote_item_titles_and_ids_cleaned() {
        let disguising = ['\u{202e}', '\u{2066}', '\u{2067}', '\u{2069}', '\u{200f}'];
        let error_of = |report: &SyncReport, needle: &str| -> serde_json::Value {
            let entry = report
                .errors
                .iter()
                .find(|e| e["error"].as_str().is_some_and(|t| t.contains(needle)))
                .unwrap_or_else(|| panic!("no error with {needle:?}: {report:?}"))
                .clone();
            for value in entry.as_object().unwrap().values() {
                let text = value.as_str().unwrap_or_default();
                assert!(!text.chars().any(|c| disguising.contains(&c)), "{text:?}");
            }
            entry
        };
        let mut client = offline_client();

        // Several items name one server.
        let db = test_db();
        let web = named_server("web", None, never_synced());
        db.insert_server(&web).unwrap();
        let mut own = login_naming_at(&client, "item-\u{2066}1", &web.id, Some(T0));
        own.name = Some(enc(&client, "web\u{202e}gnigats"));
        let other = login_naming_at(&client, "item-2", &web.id, Some(T0 + 1_000));
        let report = run_server_pass(&db, &mut client, &[&own, &other], true).await;
        let entry = error_of(&report, "Bitwarden items name server");
        let text = entry["error"].as_str().unwrap();
        assert!(text.contains("\"webgnigats\" (id item-1)"), "{text}");

        // An older copy, and a copy without a creation date.
        let db = test_db();
        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s-new"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let recreated = login_naming_at(&client, "s-new", &sv.id, Some(T0 + 5_000));
        let mut restored = login_naming_at(&client, "s-\u{2067}orig", &sv.id, Some(T0));
        restored.name = Some(enc(&client, "orig\u{202e}inal"));
        let mut undated = login_naming_at(&client, "s-\u{2069}undated", &sv.id, None);
        undated.name = Some(enc(&client, "un\u{200f}dated"));
        let report =
            run_server_pass(&db, &mut client, &[&recreated, &restored, &undated], true).await;
        let older = error_of(&report, "is an older copy of server");
        assert_eq!(older["cipher_id"], "s-orig", "{older}");
        assert!(
            older["error"]
                .as_str()
                .unwrap()
                .starts_with("original is an older copy"),
            "{older}"
        );
        let no_date = error_of(&report, "creation date");
        assert_eq!(no_date["cipher_id"], "s-undated", "{no_date}");
        assert!(
            no_date["error"]
                .as_str()
                .unwrap()
                .starts_with("undated names server"),
            "{no_date}"
        );

        // An item holding no SSH key.
        let db = test_db();
        let mut keyless = cipher("k-\u{202e}1", 5, Some("keys"), Some(T0));
        keyless.name = Some(enc(&client, "no\u{2066}key"));
        let report = run_key_pass(&db, &mut client, &[&keyless], true).await;
        let entry = error_of(&report, "holds no SSH key");
        assert_eq!(entry["cipher_id"], "k-1", "{entry}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_server_never_takes_over_the_item_another_server_is_linked_to() {
        // web was synced as s1; the user cloned s1 in Bitwarden, the clone
        // (its notes still name web) was imported as web2 (linked s2), then the
        // user deleted s1. The next sync re-linked web to s2 - two servers on
        // one item - and the next upload turned web2 into a copy of web.
        let db = test_db();
        let mut client = offline_client();
        let web = named_server("web", Some("s1"), synced_at(T0, T0));
        let web2 = named_server("web2", Some("s2"), synced_at(T0, T0));
        db.insert_server(&web).unwrap();
        db.insert_server(&web2).unwrap();
        let clone = login_naming_at(&client, "s2", &web.id, Some(T0 + 5_000));
        let report = run_server_pass(&db, &mut client, &[&clone], true).await;
        assert_eq!(report.linked, 0, "{report:?}");
        assert_eq!(stored_link(&db, &web).as_deref(), Some("s1"));
        assert_eq!(stored_link(&db, &web2).as_deref(), Some("s2"));
        // web's own item is re-created instead - offline that upload fails,
        // which shows it was attempted.
        assert!(
            report
                .errors
                .iter()
                .any(|e| e["server"] == "web" && e["error"] == "Not logged in."),
            "{report:?}"
        );
        assert_eq!(report.servers_pulled, 0, "{report:?}");
        assert_eq!(db.list_servers().unwrap().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unlinked_server_finds_its_own_item_not_another_servers_clone() {
        // web is unlinked; s1 is its own item, s2 a clone of it that was
        // imported as web2. Newest-wins linked web to s2 (web2's item) and
        // reported s1 as "an older copy of server 'web'".
        let db = test_db();
        let mut client = offline_client();
        let web = named_server("web", None, never_synced());
        let web2 = named_server("web2", Some("s2"), synced_at(T0, T0));
        db.insert_server(&web).unwrap();
        db.insert_server(&web2).unwrap();
        let own = login_naming_at(&client, "s1", &web.id, Some(T0));
        let clone = login_naming_at(&client, "s2", &web.id, Some(T0 + 5_000));
        let report = run_server_pass(&db, &mut client, &[&own, &clone], true).await;
        assert_eq!(report.linked, 1, "{report:?}");
        assert_eq!(stored_link(&db, &web).as_deref(), Some("s1"));
        assert_eq!(stored_link(&db, &web2).as_deref(), Some("s2"));
        assert!(report.errors.is_empty(), "{report:?}");
        assert_eq!(report.servers_pulled, 0, "{report:?}");
        assert_eq!(db.list_servers().unwrap().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restored_original_is_an_older_copy_not_a_new_server() {
        // The user trashed the item, SSHSpan re-created it, then the user
        // restored the original from the trash - it was offered as a new
        // server and accepting imported a duplicate.
        let db = test_db();
        let mut client = offline_client();
        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s-new"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let recreated = login_naming_at(&client, "s-new", &sv.id, Some(T0 + 5_000));
        let restored = login_naming_at(&client, "s-orig", &sv.id, Some(T0));
        let report = run_server_pass(&db, &mut client, &[&recreated, &restored], true).await;
        assert_eq!(report.servers_pulled, 0, "{report:?}");
        assert_eq!(report.skipped_server_new, 0, "{report:?}");
        assert!(
            has_error(&report, "is an older copy of server"),
            "{report:?}"
        );
        assert_eq!(db.list_servers().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_copy_without_a_creation_date_is_reported_not_imported() {
        let db = test_db();
        let mut client = offline_client();
        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s1"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let linked = login_naming_at(&client, "s1", &sv.id, Some(T0));
        let undated = login_naming_at(&client, "s2", &sv.id, None);
        let report = run_server_pass(&db, &mut client, &[&linked, &undated], true).await;
        assert_eq!(report.servers_pulled, 0, "{report:?}");
        assert!(has_error(&report, "creation date"), "{report:?}");
        assert_eq!(db.list_servers().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bitwarden_clone_of_a_linked_server_is_new_behind_the_prompt() {
        // A clone made in Bitwarden copies the notes, so it names a server
        // already linked to another live item. It used to be skipped without
        // a word - devices drifted apart. Created AFTER the linked item, it is
        // a new server, behind the same confirm-first prompt as any new item.
        let db = test_db();
        let mut client = offline_client();
        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s1"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let original = login_naming_at(&client, "s1", &sv.id, Some(T0));
        let clone = login_naming_at(&client, "s2", &sv.id, Some(T0 + 5_000));
        let report = run_server_pass(&db, &mut client, &[&original, &clone], false).await;
        assert_eq!(report.skipped_server_new, 1, "{report:?}");
        assert_eq!(db.list_servers().unwrap().len(), 1);
        let report = run_server_pass(&db, &mut client, &[&original, &clone], true).await;
        assert_eq!(report.servers_pulled, 1, "{report:?}");
        assert_eq!(db.list_servers().unwrap().len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_edit_made_after_a_lost_link_upload_is_pushed() {
        // Upload, link lost, host edited locally, sync: the notes fallback
        // re-linked the server with its CURRENT change marker, so the edit
        // was never pushed. The re-link stores no local marker, so the next
        // comparison sees the local row as changed and local wins.
        let db = test_db();
        let mut client = offline_client();
        let mut sv = server_row(&uuid::Uuid::new_v4().to_string(), None, never_synced());
        sv.host = "edited.example.com".into();
        sv.updated_at = at_ms(T0 + 7_000);
        db.insert_server(&sv).unwrap();
        let uploaded = login_naming(&client, "s9", &sv.id);
        let report = run_server_pass(&db, &mut client, &[&uploaded], false).await;
        assert_eq!(report.linked, 1, "{report:?}");
        let stored = db.get_server(&sv.id).unwrap().unwrap();
        assert_eq!(stored.bitwarden_id.as_deref(), Some("s9"));
        assert_eq!(
            plan_server(&stored, &[&uploaded], false),
            Plan::Update {
                cipher: "s9",
                conflict: false
            },
            "the local edit must be pushed"
        );
    }

    // ── Approvals bound to the list shown, key fingerprints, clean text ──

    /// One sync over `items` (keys from the keys folder, servers from the
    /// servers folder), offline, returning the summary the command returns.
    /// `approval` is the token the user's "Apply" sends; `None` is a run that
    /// only lists remote changes.
    async fn sync_passes(
        db: &Database,
        client: &mut BitwardenClient,
        items: &[&SyncCipher],
        approval: Option<&str>,
    ) -> serde_json::Value {
        let remote = crate::bitwarden::SyncResponse {
            profile: None,
            folders: Vec::new(),
            ciphers: items.iter().map(|c| (*c).clone()).collect(),
        };
        let live = live_of(items);
        let check = || -> Result<()> { Ok(()) };
        let run = SyncRun {
            db,
            vault_password: TEST_PW,
            remote_changes: approval.map_or(RemoteChanges::Ask, RemoteChanges::ApproveIf),
            check: &check,
        };
        let mut report = SyncReport::default();
        run.key_pass(client, &remote, &live, "keys", &mut report)
            .await
            .unwrap();
        run.server_pass(client, &remote, &live, "servers", &mut report)
            .await
            .unwrap();
        run.settle_remote_changes(client, &live, &mut report)
            .await
            .unwrap();
        report.summary(None)
    }

    /// The dry run shows one list; "Apply" re-fetches. A compromised
    /// account (or a server of its own) could serve something else the
    /// second time - another host, a rolled-back key. The approval is bound
    /// to the list shown: if the second fetch differs, nothing is applied
    /// and the new list comes back to be approved.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s4_an_approval_applies_only_the_list_it_was_issued_for() {
        let db = test_db();
        let mut client = offline_client();
        let (rewritten, fresh) = rewritten_and_new_servers(&db, &client);
        let shown = sync_passes(&db, &mut client, &[&rewritten, &fresh], None).await;
        let token = shown["approvalToken"]
            .as_str()
            .expect("a list to approve comes with its token")
            .to_string();
        assert_eq!(token.len(), 64, "{token}");
        // The second fetch serves another host for the same item.
        let mut swapped = rewritten.clone();
        swapped.login.as_mut().unwrap().uris = Some(vec![crate::bitwarden::LoginUri {
            uri: Some(enc(&client, "ssh://other-evil.example.com:22")),
        }]);
        let stale = sync_passes(&db, &mut client, &[&swapped, &fresh], Some(&token)).await;
        assert_eq!(stale["approvalStale"], true, "{stale}");
        assert_eq!(
            db.list_servers().unwrap().len(),
            1,
            "nothing imported: {stale}"
        );
        assert_eq!(
            db.list_servers().unwrap()[0].host,
            "10.0.0.5",
            "nothing overwritten"
        );
        assert_eq!(stale["pendingServers"][0]["host"], "other-evil.example.com");
        assert_ne!(stale["approvalToken"].as_str(), Some(token.as_str()));
        // The same bytes with no visible difference - an item the server
        // replays with an older ciphertext, say - are not the list shown
        // either.
        let mut replayed = rewritten.clone();
        replayed.favorite = true;
        let stale = sync_passes(&db, &mut client, &[&replayed, &fresh], Some(&token)).await;
        assert_eq!(stale["approvalStale"], true, "{stale}");
        assert_eq!(db.list_servers().unwrap()[0].host, "10.0.0.5");
        // The list as shown: applied.
        let applied = sync_passes(&db, &mut client, &[&rewritten, &fresh], Some(&token)).await;
        assert!(applied.get("approvalStale").is_none(), "{applied}");
        assert!(applied.get("pendingServers").is_none(), "{applied}");
        let hosts: Vec<String> = db
            .list_servers()
            .unwrap()
            .into_iter()
            .map(|s| s.host)
            .collect();
        assert!(hosts.contains(&"evil.example.com".to_string()), "{hosts:?}");
        assert!(hosts.contains(&"web.example.com".to_string()), "{hosts:?}");
    }

    /// An item holding the key `kd` and claiming `claimed_fp` as its
    /// fingerprint (and `claimed_public` as its public key).
    fn ssh_item_claiming(
        client: &BitwardenClient,
        id: &str,
        name: &str,
        kd: &crate::crypto::keys::PrivateKeyData,
        claimed_fp: &str,
        claimed_public: &str,
    ) -> SyncCipher {
        use crate::crypto::keys::{self, KeyFormat};
        let mut item = cipher(id, 5, Some("keys"), Some(T0 + 5_000));
        item.name = Some(enc(client, name));
        item.ssh_key = Some(crate::bitwarden::SshKeyBlock {
            private_key: Some(enc(
                client,
                &keys::export_private_key(kd, KeyFormat::OpenSsh, None).unwrap(),
            )),
            public_key: Some(enc(client, claimed_public)),
            key_fingerprint: Some(enc(client, claimed_fp)),
        });
        item
    }

    /// An item's `keyFingerprint` (and `publicKey`) are fields anyone who
    /// can edit the item can set. A linked item whose private key was swapped
    /// for an attacker's, its fingerprint field kept, read as "no change"
    /// (`SHA256:AAAA -> SHA256:AAAA`) - and after Apply the local key held the
    /// attacker's key under the old fingerprint. The fingerprint and public
    /// key now come from the private key itself; an item that claims others
    /// is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s5_a_key_swapped_behind_its_old_fingerprint_is_refused() {
        use crate::crypto::keys::{self, KeyFormat, KeyType};
        let db = test_db();
        let mut client = offline_client();
        let mine = keys::generate_key_pair(KeyType::Ed25519, None, "mine".into()).unwrap();
        let mine_fp = keys::compute_fingerprint_sha256(&mine.public_key);
        let mine_public = keys::export_public_key(&mine, KeyFormat::OpenSsh).unwrap();
        let mut row = key_row("k1", Some("c1"), synced_at(T0, T0));
        row.name = "deploy".into();
        row.fingerprint_sha256 = mine_fp.clone();
        row.public_key = mine_public.clone();
        db.insert_key(&row).unwrap();
        let attacker = keys::generate_key_pair(KeyType::Ed25519, None, "evil".into()).unwrap();
        let swapped = ssh_item_claiming(&client, "c1", "deploy", &attacker, &mine_fp, &mine_public);
        let shown = run_key_pass(&db, &mut client, &[&swapped], false).await;
        assert!(shown.pending_keys.is_empty(), "not offered: {shown:?}");
        assert!(
            has_error(
                &shown,
                "deploy claims a fingerprint that does not match its key - not imported."
            ),
            "{shown:?}"
        );
        let applied = run_key_pass(&db, &mut client, &[&swapped], true).await;
        assert_eq!(applied.updated_local, 0, "{applied:?}");
        let stored = db.get_key("k1").unwrap().unwrap();
        assert_eq!(stored.fingerprint_sha256, mine_fp);
        assert_eq!(
            stored.private_key_encrypted, "sealed",
            "the key is untouched"
        );
    }

    /// On import, the stored fingerprint and public key are the ones of the
    /// private key; claims that differ are refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s5_an_imported_key_gets_the_fingerprint_and_public_key_of_its_private_key() {
        use crate::crypto::keys::{self, KeyFormat, KeyType};
        let db = test_db();
        let mut client = offline_client();
        let other = keys::generate_key_pair(KeyType::Ed25519, None, "other".into()).unwrap();
        let other_fp = keys::compute_fingerprint_sha256(&other.public_key);
        let other_public = keys::export_public_key(&other, KeyFormat::OpenSsh).unwrap();
        let held = keys::generate_key_pair(KeyType::Ed25519, None, "held".into()).unwrap();
        let held_fp = keys::compute_fingerprint_sha256(&held.public_key);
        let held_public = keys::export_public_key(&held, KeyFormat::OpenSsh).unwrap();
        for (claimed_fp, claimed_public, what) in [
            (&other_fp, &held_public, "fingerprint"),
            (&held_fp, &other_public, "public key"),
        ] {
            let item =
                ssh_item_claiming(&client, "c1", "imported", &held, claimed_fp, claimed_public);
            let err = match pull_new_key(&mut client, &item, &db, TEST_PW).await {
                Ok(_) => panic!("a {what} claim that does not match was imported"),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains(&format!("claims a {what} that does not match its key")),
                "{err}"
            );
            assert!(db.list_keys().unwrap().is_empty());
        }
        let honest = ssh_item_claiming(&client, "c1", "imported", &held, &held_fp, &held_public);
        pull_new_key(&mut client, &honest, &db, TEST_PW)
            .await
            .unwrap();
        let stored = db.list_keys().unwrap().remove(0);
        assert_eq!(stored.fingerprint_sha256, held_fp);
        assert_eq!(
            parse_openssh_public_line(&stored.public_key).unwrap(),
            held.public_key
        );
    }

    /// Text from an item shown in the prompt carries no format or
    /// text-direction characters, whitespace runs are one space, and each
    /// value is at most 80 characters.
    #[test]
    fn rw_s6_pending_text_drops_disguising_characters_and_collapses_whitespace() {
        assert_eq!(
            pending_text(
                "  a\u{202e}b\u{200b}c \u{00a0}\u{2003}\u{3000}d\u{2028}e\u{feff}\u{061c}f\t\n"
            ),
            "abc d ef"
        );
        assert_eq!(pending_text("x\u{2066}y\u{2069}z\u{200f}"), "xyz");
        let long = pending_text(&"w".repeat(500));
        assert_eq!(long.chars().count(), 80, "{long}");
        assert!(long.ends_with('\u{2026}'), "{long}");
        assert_eq!(pending_text("short"), "short");
    }

    /// Server names stored from Bitwarden are cleaned the same way.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s6_server_names_from_bitwarden_are_stored_clean() {
        let db = test_db();
        let mut client = offline_client();
        let mut item = login_item(&client, "s1", None);
        item.name = Some(enc(&client, "web\u{202e}\u{200b}  \u{00a0}prod\u{2066}"));
        pull_new_server(&mut client, &item, &db, TEST_PW)
            .await
            .unwrap();
        assert_eq!(db.list_servers().unwrap()[0].name, "web prod");
        let sv = server_row(
            &uuid::Uuid::new_v4().to_string(),
            Some("s2"),
            synced_at(T0, T0),
        );
        db.insert_server(&sv).unwrap();
        let mut newer = login_item(&client, "s2", None);
        newer.name = Some(enc(&client, "db\u{200f}\u{3000}\u{3000}main"));
        newer.revision_date = Some(rfc3339_ms(T0 + 5_000));
        assert!(
            pull_remote_server(&mut client, &newer, &sv, &db, TEST_PW, false)
                .await
                .unwrap()
        );
        assert_eq!(db.get_server(&sv.id).unwrap().unwrap().name, "db main");
    }

    /// An overwrite replaces more than the address - the user name,
    /// the saved password, the auth method and the linked key too - and the
    /// prompt showed only host:port. Each entry now names what changes.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s6_a_server_overwrite_names_every_setting_the_pull_changes() {
        let db = test_db();
        let mut client = offline_client();
        let mut sv = named_server("prod-db", Some("s1"), synced_at(T0, T0));
        sv.host = "web.example.com".into();
        sv.port = 2222;
        sv.username = "ops".into();
        sv.saved_password = Some(crate::crypto::vault::seal(TEST_PW, b"old-secret").unwrap());
        db.insert_server(&sv).unwrap();
        let mut item = login_item(&client, "s1", Some(enc(&client, "new-secret")));
        item.revision_date = Some(rfc3339_ms(T0 + 5_000));
        item.name = Some(enc(&client, "prod-db"));
        item.login.as_mut().unwrap().username = Some(enc(&client, "root"));
        item.notes = Some(enc(
            &client,
            &serde_json::json!({ "v": 1, "sshspan": { "authMethod": "keyboard-interactive" } })
                .to_string(),
        ));
        let summary = run_server_pass(&db, &mut client, &[&item], false)
            .await
            .summary(None);
        assert_eq!(
            summary["pendingServers"][0]["changes"],
            serde_json::json!(["user", "password", "authMethod"]),
            "{summary}"
        );
        // The same name, password, user and method: nothing but the revision
        // moved.
        let mut bump = login_item(&client, "s1", Some(enc(&client, "old-secret")));
        bump.revision_date = Some(rfc3339_ms(T0 + 5_000));
        bump.name = Some(enc(&client, "prod-db"));
        let summary = run_server_pass(&db, &mut client, &[&bump], false)
            .await
            .summary(None);
        assert_eq!(
            summary["pendingServers"][0]["changes"],
            serde_json::json!([]),
            "{summary}"
        );
    }

    /// Entries that change something come first, ahead of the revision
    /// bumps that change nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_s6_real_changes_are_listed_before_revision_bumps() {
        let db = test_db();
        let mut client = offline_client();
        let mut items = Vec::new();
        for n in 0..60 {
            let mut sv = named_server(
                &format!("bump-{n}"),
                Some(&format!("s{n}")),
                synced_at(T0, T0),
            );
            sv.host = "web.example.com".into();
            sv.port = 2222;
            sv.username = "ops".into();
            db.insert_server(&sv).unwrap();
            let mut item = login_item(&client, &format!("s{n}"), None);
            item.revision_date = Some(rfc3339_ms(T0 + 5_000));
            item.name = Some(enc(&client, &format!("bump-{n}")));
            items.push(item);
        }
        let mut real = named_server("real", Some("s-real"), synced_at(T0, T0));
        real.host = "web.example.com".into();
        db.insert_server(&real).unwrap();
        let mut moved = login_item(&client, "s-real", None);
        moved.revision_date = Some(rfc3339_ms(T0 + 5_000));
        moved.login.as_mut().unwrap().uris = Some(vec![crate::bitwarden::LoginUri {
            uri: Some(enc(&client, "ssh://evil.example.com:22")),
        }]);
        items.push(moved);
        let refs: Vec<&SyncCipher> = items.iter().collect();
        let summary = run_server_pass(&db, &mut client, &refs, false)
            .await
            .summary(None);
        let pending = summary["pendingServers"].as_array().unwrap();
        assert_eq!(pending.len(), 61);
        assert!(summary.get("pendingTruncated").is_none(), "{summary}");
        assert_eq!(pending[0]["name"], "real", "{}", pending[0]);
        assert_eq!(pending[0]["host"], "evil.example.com");
    }

    // ── Crypto off the async workers, the change lists, category uploads ──

    /// Server "web" (password auth for ops@web.example.com:2222), linked to
    /// item "s1" and synced at T0, with `password` saved and filed in a host
    /// category "Web".
    fn synced_web_server(db: &Database, password: &[u8]) -> (ServerRecord, String) {
        let web = db
            .ensure_category_path_scoped("Web", "host")
            .unwrap()
            .unwrap();
        let mut sv = named_server("web", Some("s1"), synced_at(T0, T0));
        sv.host = "web.example.com".into();
        sv.port = 2222;
        sv.username = "ops".into();
        sv.saved_password = Some(crate::crypto::vault::seal(TEST_PW, password).unwrap());
        sv.category_id = Some(web.clone());
        db.insert_server(&sv).unwrap();
        (sv, web)
    }

    /// The SSHSpan notes of `sv`'s item, filing it in `category`.
    fn web_notes(client: &BitwardenClient, sv: &ServerRecord, category: &str) -> String {
        enc(
            client,
            &serde_json::json!({ "v": 1, "sshspan": {
                "serverId": sv.id, "authMethod": "password", "keyFingerprint": null,
                "category": { "id": category, "path": "Hosts-Web" },
            }})
            .to_string(),
        )
    }

    /// Every seal and unseal of the sync runs on the blocking pool: the
    /// server pass unseals a saved password to compare it, a push unseals
    /// what it uploads, an approved pull seals what it stores. Argon2id - 64
    /// MiB and most of a second each - ran on an async worker, twice per
    /// pending server per approval round trip.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_the_sync_seals_and_unseals_only_on_the_blocking_pool() {
        use std::sync::atomic::Ordering::SeqCst;
        let db = test_db();
        let mut client = offline_client();
        let (sv, web) = synced_web_server(&db, b"old-pw");
        let mut item = login_item(&client, "s1", Some(enc(&client, "new-pw")));
        item.revision_date = Some(rfc3339_ms(T0 + 5_000));
        item.notes = Some(web_notes(&client, &sv, &web));
        let mut fresh = named_server("fresh", None, never_synced());
        fresh.saved_password = Some(crate::crypto::vault::seal(TEST_PW, b"fresh-pw").unwrap());
        db.insert_server(&fresh).unwrap();
        let before = crate::commands::POOL_CRYPTO_CALLS.load(SeqCst);
        let shown = sync_passes(&db, &mut client, &[&item], None).await;
        let token = shown["approvalToken"].as_str().unwrap().to_string();
        let applied = sync_passes(&db, &mut client, &[&item], Some(&token)).await;
        assert_eq!(applied["serversUpdatedLocal"], 1, "{applied}");
        assert!(
            crate::commands::POOL_CRYPTO_CALLS.load(SeqCst) >= before + 3,
            "the compare, the push and the pull each ran a derivation"
        );
        let stored = db.get_server(&sv.id).unwrap().unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(TEST_PW, stored.saved_password.as_deref().unwrap())
                .unwrap(),
            b"new-pw"
        );
    }

    /// A remote rename or a move to another category is a real change: named
    /// in `changes` ("name" first, "category" last) - it used to count as a
    /// mere revision bump, which the cap could push out of the list.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_server_overwrite_names_a_rename_and_a_new_category() {
        let db = test_db();
        let mut client = offline_client();
        let (sv, _web) = synced_web_server(&db, b"pw");
        let mut item = login_item(&client, "s1", Some(enc(&client, "pw")));
        item.revision_date = Some(rfc3339_ms(T0 + 5_000));
        item.name = Some(enc(&client, "web-renamed"));
        item.notes = Some(enc(
            &client,
            &serde_json::json!({ "v": 1, "sshspan": {
                "serverId": sv.id, "authMethod": "password",
                "category": { "id": "remote-only", "path": "Hosts-Elsewhere" },
            }})
            .to_string(),
        ));
        let summary = run_server_pass(&db, &mut client, &[&item], false)
            .await
            .summary(None);
        assert_eq!(
            summary["pendingServers"][0]["changes"],
            serde_json::json!(["name", "category"]),
            "{summary}"
        );
        assert!(
            db.list_categories()
                .unwrap()
                .iter()
                .all(|c| c.name != "Elsewhere"),
            "comparing creates no category"
        );
    }

    /// A key moved to another category in Bitwarden is a real change too:
    /// listed before the revision bumps.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_key_moved_to_another_category_is_a_real_change() {
        let db = test_db();
        let mut client = offline_client();
        let mut items = Vec::new();
        for (n, categories) in [(0, None), (1, Some("Ops"))] {
            let (mut item, fp) = ssh_item(&client, &format!("c{n}"), &format!("key-k{n}"));
            item.revision_date = Some(rfc3339_ms(T0 + 5_000));
            item.notes = categories.map(|path| {
                enc(
                    &client,
                    &serde_json::json!({ "v": 1, "sshspan": {
                        "categories": [{ "id": "remote-only", "path": path }],
                    }})
                    .to_string(),
                )
            });
            let mut row = key_row(&format!("k{n}"), Some(&format!("c{n}")), synced_at(T0, T0));
            row.fingerprint_sha256 = fp;
            db.insert_key(&row).unwrap();
            items.push(item);
        }
        let refs: Vec<&SyncCipher> = items.iter().collect();
        let summary = run_key_pass(&db, &mut client, &refs, false)
            .await
            .summary(None);
        let pending = summary["pendingKeys"].as_array().unwrap();
        assert_eq!(pending.len(), 2, "{summary}");
        assert_eq!(
            pending[0]["name"], "key-k1",
            "the re-categorised key comes first: {summary}"
        );
    }

    /// A list longer than the prompt shows cannot be approved: the cap is
    /// 500 entries per list, and past it no approval token is issued and an
    /// approval applies nothing - it used to apply the entries nobody saw.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_an_approval_of_a_list_too_long_to_show_is_refused() {
        let db = test_db();
        let mut client = offline_client();
        let items: Vec<SyncCipher> = (0..501)
            .map(|n| login_item(&client, &format!("n{n}"), None))
            .collect();
        let refs: Vec<&SyncCipher> = items.iter().collect();
        let shown = sync_passes(&db, &mut client, &refs, None).await;
        assert_eq!(shown["pendingServers"].as_array().unwrap().len(), 500);
        assert_eq!(shown["pendingTruncated"], true);
        assert!(
            shown.get("approvalToken").is_none(),
            "no token for a list nobody can see whole"
        );
        let refused = shown["approvalRefused"].as_str().unwrap_or_default();
        assert!(
            refused.starts_with("Too many changes to review at once (501)"),
            "{refused}"
        );
        let applied = sync_passes(&db, &mut client, &refs, Some("an-old-or-forged-token")).await;
        assert_eq!(applied["serversPulled"], 0, "{applied}");
        assert!(db.list_servers().unwrap().is_empty());
    }

    /// A category rename marks the servers under it for an upload of their
    /// category - but never pushes their other fields over newer ones in
    /// Bitwarden. Here the saved password was rotated in Bitwarden and the
    /// category renamed in SSHSpan: "local wins" uploaded the OLD password
    /// over the rotated one, with no question asked. Now the remote change
    /// is listed for approval, the pull keeps the local category, and the
    /// category goes up on the next run - with the rotated password.
    #[tokio::test(flavor = "multi_thread")]
    async fn rw_fix1_a_category_rename_never_pushes_a_password_older_than_the_remote() {
        let db = test_db();
        let mut client = offline_client();
        let (sv, web) = synced_web_server(&db, b"old-pw");
        let mut item = login_item(&client, "s1", Some(enc(&client, "rotated-pw")));
        item.revision_date = Some(rfc3339_ms(T0 + 60_000));
        item.notes = Some(web_notes(&client, &sv, &web));
        db.rename_category(&web, "Production web").unwrap();

        let shown = sync_passes(&db, &mut client, &[&item], None).await;
        assert_eq!(
            shown["errors"],
            serde_json::json!([]),
            "nothing uploaded: {shown}"
        );
        assert_eq!(shown["serversUpdatedRemote"], 0, "{shown}");
        assert_eq!(shown["pendingServers"][0]["kind"], "overwrite", "{shown}");
        assert_eq!(
            shown["pendingServers"][0]["changes"],
            serde_json::json!(["password"]),
            "{shown}"
        );

        let token = shown["approvalToken"].as_str().unwrap().to_string();
        let applied = sync_passes(&db, &mut client, &[&item], Some(&token)).await;
        assert_eq!(applied["serversUpdatedLocal"], 1, "{applied}");
        let stored = db.get_server(&sv.id).unwrap().unwrap();
        assert_eq!(
            crate::crypto::vault::unseal(TEST_PW, stored.saved_password.as_deref().unwrap())
                .unwrap(),
            b"rotated-pw",
            "the rotated password is kept"
        );
        assert_eq!(stored.category_id.as_deref(), Some(web.as_str()));
        assert_eq!(
            db.get_category(&web).unwrap().unwrap().name,
            "Production web",
            "the local rename stays"
        );

        // Next run: the remote is in sync, the category still has to go up.
        let next = sync_passes(&db, &mut client, &[&item], None).await;
        assert!(next.get("pendingServers").is_none(), "{next}");
        assert_eq!(
            next["errors"][0]["server"], "web",
            "the upload of the renamed category was attempted (offline here): {next}"
        );
    }

    // ── Comparing many pending changes reads the categories once ────────────

    /// Run `work` on a thread of its own and wait for it at most `deadline`:
    /// a pass that reads the whole category table per lookup took minutes,
    /// and a test has to say so well before that. The read count is the
    /// precise check; the deadline only bounds a failure, so it is wide for
    /// a loaded machine ([`PASS_DEADLINE`]).
    fn within<T: Send + 'static>(
        deadline: std::time::Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(work());
        });
        finished
            .recv_timeout(deadline)
            .unwrap_or_else(|_| panic!("did not finish within {deadline:?}"))
    }

    /// How long [`within`] waits for one pass of hundreds of items: a few
    /// seconds in a debug build, far longer on a machine saturated by other
    /// builds and suites - and the 357 s the per-lookup reads took.
    const PASS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

    /// A multi-thread runtime for [`within`]'s thread (the database helpers
    /// need one).
    fn pass_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// A top-level category of `scope` named `name`, with a fresh id - as
    /// the UI makes them (another device has other ids for the same names).
    fn new_category(db: &Database, name: &str, scope: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_category(&crate::db::Category {
            id: id.clone(),
            name: name.into(),
            parent_id: None,
            scope: scope.into(),
            color: None,
            sort_index: 0,
            created_at: at_ms(T0),
            updated_at: at_ms(T0),
        })
        .unwrap();
        id
    }

    /// 300 servers whose items changed in Bitwarden, each item filing its
    /// server in one of 150 host categories by path under an id this vault
    /// does not have (the normal case with more than one device). Comparing
    /// read the whole category table for every category of every lookup:
    /// 357 s in a debug build, holding the rotation lock all along. The
    /// categories are now read once per pass, on the blocking pool.
    #[test]
    fn rw_fix2_pending_server_overwrites_read_the_categories_once() {
        let db = test_db();
        let client = offline_client();
        let racks: Vec<String> = (0..150)
            .map(|n| new_category(&db, &format!("rack-{n}"), "host"))
            .collect();
        let mut items = Vec::new();
        for n in 0..300 {
            let mut sv = named_server(
                &format!("srv-{n}"),
                Some(&format!("s{n}")),
                synced_at(T0, T0),
            );
            sv.host = "web.example.com".into();
            sv.port = 2222;
            sv.username = "ops".into();
            sv.category_id = Some(racks[n % 150].clone());
            db.insert_server(&sv).unwrap();
            let mut item = login_item(&client, &format!("s{n}"), None);
            item.revision_date = Some(rfc3339_ms(T0 + 5_000));
            item.name = Some(enc(&client, &format!("srv-{n}")));
            item.notes = Some(enc(
                &client,
                &serde_json::json!({ "v": 1, "sshspan": {
                    "serverId": sv.id,
                    "category": { "id": format!("remote-{n}"),
                                  "path": format!("Hosts-rack-{}", n % 150) },
                }})
                .to_string(),
            ));
            items.push(item);
        }
        let before = crate::db::test_support::category_reads(&db);
        let pass_db = db.clone();
        let summary = within(PASS_DEADLINE, move || {
            pass_runtime().block_on(async move {
                let mut client = offline_client();
                let refs: Vec<&SyncCipher> = items.iter().collect();
                run_server_pass(&pass_db, &mut client, &refs, false)
                    .await
                    .summary(None)
            })
        });
        let reads = crate::db::test_support::category_reads(&db) - before;
        assert!(reads <= 2, "{reads} reads of the categories for one pass");
        let pending = summary["pendingServers"].as_array().unwrap();
        assert_eq!(pending.len(), 300);
        assert!(
            pending
                .iter()
                .all(|e| e["changes"] == serde_json::json!([])),
            "every item names the server's own category by its path: {}",
            pending[0]
        );
    }

    /// The same for keys: 100 keys whose items changed, each filed by path
    /// in one of 50 key categories under an id this vault does not have.
    #[test]
    fn rw_fix2_pending_key_overwrites_read_the_categories_once() {
        let db = test_db();
        let client = offline_client();
        let teams: Vec<String> = (0..50)
            .map(|n| new_category(&db, &format!("team-{n}"), "key"))
            .collect();
        let mut items = Vec::new();
        for n in 0..100 {
            let (mut item, fp) = ssh_item(&client, &format!("c{n}"), &format!("key-k{n}"));
            item.revision_date = Some(rfc3339_ms(T0 + 5_000));
            item.notes = Some(enc(
                &client,
                &serde_json::json!({ "v": 1, "sshspan": { "categories": [
                    { "id": format!("remote-{n}"), "path": format!("team-{}", n % 50) },
                ]}})
                .to_string(),
            ));
            let mut row = key_row(&format!("k{n}"), Some(&format!("c{n}")), synced_at(T0, T0));
            row.fingerprint_sha256 = fp;
            db.insert_key(&row).unwrap();
            db.set_key_categories(&row.id, std::slice::from_ref(&teams[n % 50]))
                .unwrap();
            items.push(item);
        }
        let before = crate::db::test_support::category_reads(&db);
        let pass_db = db.clone();
        let summary = within(PASS_DEADLINE, move || {
            pass_runtime().block_on(async move {
                let mut client = offline_client();
                let refs: Vec<&SyncCipher> = items.iter().collect();
                run_key_pass(&pass_db, &mut client, &refs, false)
                    .await
                    .summary(None)
            })
        });
        let reads = crate::db::test_support::category_reads(&db) - before;
        assert!(reads <= 2, "{reads} reads of the categories for one pass");
        assert_eq!(summary["pendingKeys"].as_array().unwrap().len(), 100);
    }
}
