//! AI assistant: provider proxy, sealed API-key storage, and the per-tab
//! access-level gate for AI-initiated terminal execution.
//!
//! The agent/tool loop lives in the renderer (src/renderer/assistant.js) -
//! the conversation context it needs (terminal scrollback, server info) is
//! renderer-side, so the backend stays a non-streaming proxy plus policy gate:
//! it owns the sealed API key, all provider traffic, the access level, and
//! the only two paths that let AI-issued text reach an SSH channel.
//!
//! Access levels: "read" (advise only), "draft" (may type into the prompt,
//! never submits), "execute" (runs commands, renderer confirms each), "yolo"
//! (runs without asking). The renderer exposes tools to the model according to
//! the level; `assistant_exec` (runs a command: Enter appended, Execute or
//! higher) and `assistant_type_text` (types a single line: never Enter, no
//! control characters, Draft or higher) re-check the level here before
//! writing to the session, so a confused or prompt-injected model cannot
//! escalate itself by emitting tool calls the UI never offered.
//!
//! Known boundary: the renderer can still call `terminal_send` directly (user
//! typing needs it), so this gate constrains the AI's sanctioned path, not a
//! compromised webview - which is outside the threat model (release builds
//! ship without devtools).

pub mod mcp;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::commands::{vault_password, CmdError};

type CmdResult<T> = Result<T, CmdError>;

const OPENAI_DEFAULT_BASE: &str = "https://api.openai.com/v1";
const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Provider calls get one budget end to end. Non-streaming responses from a
/// loaded local server (Ollama on CPU) can legitimately take a minute; two
/// minutes is long enough for that and short enough that a wedged connection
/// does not park a command slot forever.
const CHAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

// ─── Access levels ──────────────────────────────────────────────────────────

/// Per-tab AI access levels, in memory only: they reset on app restart and
/// are cleared on vault lock (see commands::lock_vault_internal). Persisting
/// "yolo" across a restart would arm it without the user re-confirming.
pub struct AssistantLevels(std::sync::Mutex<HashMap<String, String>>);

impl AssistantLevels {
    pub fn new() -> Self {
        Self(std::sync::Mutex::new(HashMap::new()))
    }
    pub fn set(&self, tab_id: &str, level: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(tab_id.to_string(), level.to_string());
    }
    pub fn get(&self, tab_id: &str) -> String {
        self.0
            .lock()
            .unwrap()
            .get(tab_id)
            .cloned()
            .unwrap_or_else(|| "read".to_string())
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

fn valid_level(level: &str) -> bool {
    matches!(level, "read" | "draft" | "execute" | "yolo")
}

/// The gate: may an AI-issued command be executed at this level? Pure so the
/// decision is unit-testable without AppState.
fn level_permits_exec(level: &str) -> bool {
    matches!(level, "execute" | "yolo")
}

/// The typing gate: Draft is the lowest level that may type into the prompt.
fn level_permits_typing(level: &str) -> bool {
    matches!(level, "draft" | "execute" | "yolo")
}

/// Longest text the assistant may type in one go, in characters - a prompt
/// line, not a file.
const MAX_TYPED_CHARS: usize = 4096;

/// Characters that are invisible, change the text direction or change how
/// the text around them is drawn, so a suggestion or Approve card could show
/// the user something other than what gets typed or run: every
/// Unicode general-category Cf (format) code point - bidi embeddings,
/// overrides, isolates and marks, zero-width spaces and joiners, invisible
/// operators, the BOM, prepended number signs, interlinear annotation,
/// format controls of historic scripts and music, tag characters ("ASCII
/// smuggling") - checked against Unicode 15.1; every
/// Default_Ignorable_Code_Point - the combining grapheme joiner, the Hangul
/// fillers, the Khmer inherent vowels, the variation selectors and the code
/// points reserved as default-ignorable, which a renderer draws as nothing;
/// and the line and paragraph separators. A sorted table of inclusive
/// ranges, searched by bisection; shared by typing and running
/// ([`forbidden_terminal_char`]).
const DISGUISING_CHARS: [(char, char); 26] = [
    ('\u{00AD}', '\u{00AD}'),   // soft hyphen
    ('\u{034F}', '\u{034F}'),   // combining grapheme joiner
    ('\u{0600}', '\u{0605}'),   // Arabic number signs
    ('\u{061C}', '\u{061C}'),   // Arabic letter mark
    ('\u{06DD}', '\u{06DD}'),   // Arabic end of ayah
    ('\u{070F}', '\u{070F}'),   // Syriac abbreviation mark
    ('\u{0890}', '\u{0891}'),   // Arabic pound and piastre marks above
    ('\u{08E2}', '\u{08E2}'),   // Arabic disputed end of ayah
    ('\u{115F}', '\u{1160}'),   // Hangul choseong and jungseong fillers
    ('\u{17B4}', '\u{17B5}'),   // Khmer inherent vowels
    ('\u{180B}', '\u{180F}'),   // Mongolian variation selectors, vowel separator
    ('\u{200B}', '\u{200F}'),   // zero-width space and joiners, LRM, RLM
    ('\u{2028}', '\u{2029}'),   // line and paragraph separators
    ('\u{202A}', '\u{202E}'),   // bidi embeddings and overrides
    ('\u{2060}', '\u{206F}'),   // word joiner, invisible operators, isolates
    ('\u{3164}', '\u{3164}'),   // Hangul filler
    ('\u{FE00}', '\u{FE0F}'),   // variation selectors
    ('\u{FEFF}', '\u{FEFF}'),   // zero-width no-break space (BOM)
    ('\u{FFA0}', '\u{FFA0}'),   // halfwidth Hangul filler
    ('\u{FFF0}', '\u{FFFB}'),   // reserved, interlinear annotation
    ('\u{110BD}', '\u{110BD}'), // Kaithi number sign
    ('\u{110CD}', '\u{110CD}'), // Kaithi number sign above
    ('\u{13430}', '\u{1343F}'), // Egyptian hieroglyph format controls
    ('\u{1BCA0}', '\u{1BCA3}'), // shorthand format controls
    ('\u{1D173}', '\u{1D17A}'), // musical symbol format controls
    ('\u{E0000}', '\u{E0FFF}'), // tags, variation selectors supplement
];

/// Whether `c` is invisible or changes how the text around it reads (every
/// format character, the default-ignorables, the line and paragraph
/// separators - [`DISGUISING_CHARS`]). Also used to clean text from a
/// Bitwarden item before SSHSpan shows or stores it.
pub(crate) fn is_disguising(c: char) -> bool {
    DISGUISING_CHARS
        .binary_search_by(|&(first, last)| {
            if last < c {
                std::cmp::Ordering::Less
            } else if first > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether the assistant may type `text` into a terminal at `level`
/// (`assistant_type_text`), and if not, the refusal the model and the user
/// see. Typing must never press Enter or a control key: LF/CR submit the
/// line, Ctrl-C/D/Z interrupt or end the shell, ESC drives full-screen
/// programs - so every control character except TAB (completion) is refused:
/// Unicode's Cc set, i.e. C0, DEL and C1. Text that could look different
/// from what it types ([`DISGUISING_CHARS`]) and text over
/// [`MAX_TYPED_CHARS`] are refused too. Nothing is sent on a refusal. Pure
/// so the rule is unit-testable without a session.
fn check_typed_text(level: &str, text: &str) -> Result<(), String> {
    if !level_permits_typing(level) {
        return Err(format!(
            "AI access level is '{level}' - raise it to Draft or higher in the assistant panel to let the assistant type into the terminal."
        ));
    }
    if text.is_empty() {
        return Err("Nothing to type - the text is empty.".into());
    }
    let length = text.chars().count();
    if length > MAX_TYPED_CHARS {
        return Err(format!(
            "The text is too long to type ({length} characters; the limit is {MAX_TYPED_CHARS}). Nothing was typed."
        ));
    }
    if text.contains(['\n', '\r']) {
        return Err(
            "The assistant may only type a single line: this text contains a line break, which would press Enter. Nothing was typed."
                .into(),
        );
    }
    match forbidden_terminal_char(text) {
        Some(ForbiddenChar::Control(c)) => Err(format!(
            "This text contains a control character (U+{:04X}) - the assistant may not send control keys. Nothing was typed.",
            c as u32
        )),
        Some(ForbiddenChar::Disguising(c)) => Err(format!(
            "This text contains an invisible or text-direction character (U+{:04X}) that could disguise what is typed. Nothing was typed.",
            c as u32
        )),
        None => Ok(()),
    }
}

/// A character the assistant may never send to a terminal.
enum ForbiddenChar {
    /// A control character other than TAB: a key (Enter, Ctrl-C, ESC, ...),
    /// not text.
    Control(char),
    /// A character that could make the text look different from what is
    /// sent ([`DISGUISING_CHARS`]).
    Disguising(char),
}

/// The character of `text` the assistant may not send - any control
/// character other than TAB first, else any disguising one. Shared by typing
/// ([`check_typed_text`]) and running ([`check_exec_command`]), so a card the
/// user reviews always shows exactly what reaches the shell.
fn forbidden_terminal_char(text: &str) -> Option<ForbiddenChar> {
    text.chars()
        .find(|c| c.is_control() && *c != '\t')
        .map(ForbiddenChar::Control)
        .or_else(|| {
            text.chars()
                .find(|&c| is_disguising(c))
                .map(ForbiddenChar::Disguising)
        })
}

/// Whether the assistant may run `command` at `level` (`assistant_exec`), and
/// if not, the refusal the model and the user see: Execute or higher, and -
/// like typing - no control character other than TAB and nothing invisible
/// or text-direction. The Approve card has to show exactly what
/// runs: a right-to-left override or a zero-width character displayed the
/// command reordered or shortened (Trojan Source) while the shell ran it as
/// written, and an embedded line break ran a second line. Nothing is sent on
/// a refusal. Pure so the rule is unit-testable without a session.
fn check_exec_command(level: &str, command: &str) -> Result<(), String> {
    if !level_permits_exec(level) {
        return Err(format!(
            "AI access level is '{level}' - raise it in the assistant panel to let the assistant run commands."
        ));
    }
    // TAB is fine to TYPE (completion is wanted there), but in a command it
    // makes readline complete before Enter, so what runs could differ from
    // what was approved.
    if command.contains('\t') {
        return Err(
            "This command contains a TAB - the shell would complete on it before running, so what runs could differ from what was approved. Nothing was run."
                .into(),
        );
    }
    match forbidden_terminal_char(command) {
        Some(ForbiddenChar::Control(c)) => Err(format!(
            "This command contains a control character (U+{:04X}) - the assistant may only run one line with no control keys, exactly as shown for approval. Nothing was run.",
            c as u32
        )),
        Some(ForbiddenChar::Disguising(c)) => Err(format!(
            "This command contains an invisible or text-direction character (U+{:04X}) that could make it look different from what would run. Nothing was run.",
            c as u32
        )),
        None => Ok(()),
    }
}

// ─── Config commands ────────────────────────────────────────────────────────

#[tauri::command]
pub fn assistant_get_config(app: AppHandle) -> CmdResult<serde_json::Value> {
    let config = app
        .state::<crate::AppState>()
        .db
        .load_assistant_config()
        .map_err(|e| e.to_string())?;
    Ok(config_view(&config))
}

/// The settings as the renderer gets them. The sealed key never crosses the
/// IPC boundary - only whether one is stored - and neither does a user name
/// or password inside a base URL saved before that was refused: the URL comes
/// back without them (so saving the form again stores it clean), while a chat
/// refuses the saved one until then ([`resolve_provider`]).
fn config_view(config: &crate::db::AssistantConfig) -> serde_json::Value {
    serde_json::json!({
        "provider": config.provider,
        "base_url": config.base_url.as_deref().map(without_credentials),
        "model": config.model,
        "has_api_key": config.api_key.is_some(),
    })
}

/// `url` without a user name or password; unchanged when it has none or is
/// not a URL at all.
fn without_credentials(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) if !parsed.username().is_empty() || parsed.password().is_some() => {
            // Both only fail for URLs that cannot have credentials.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            let clean = parsed.to_string();
            // `Url` adds a "/" to a bare origin; the saved form has none.
            if url.ends_with('/') {
                clean
            } else {
                clean.trim_end_matches('/').to_string()
            }
        }
        _ => url.to_string(),
    }
}

/// Save the provider settings. Async, with the work on the blocking pool
/// (A5-12): a new API key is sealed with Argon2id, and as a synchronous
/// command that ran on the main thread and froze the window. A change that
/// would send the stored key to another provider address is asked about in a
/// native dialog first ([`save_config_confirmed`]).
#[tauri::command]
pub async fn assistant_save_config(
    app: AppHandle,
    provider: String,
    base_url: Option<String>,
    model: String,
    api_key: Option<String>,
    // Explicit removal signal: null/empty api_key alone means "keep the
    // stored key" (so a save from a form that blanks the password field for
    // privacy does not silently destroy it), which otherwise made a stored
    // key impossible to remove.
    clear_api_key: Option<bool>,
    // Accepted from renderers that still send it - and IGNORED: the stored
    // key moves to a new address only when the user allows it in the native
    // dialog. A renderer flag is not the user's answer.
    reuse_key_at_new_origin: Option<bool>,
) -> CmdResult<serde_json::Value> {
    crate::commands::run_blocking(move || {
        save_config_from_ipc(
            &app.state::<crate::AppState>().db,
            app.state::<crate::commands::VaultPasswordStore>().inner(),
            app.state::<crate::commands::VaultGeneration>().inner(),
            app.state::<crate::commands::VaultRotationLock>().inner(),
            app.state::<crate::commands::CredentialQuestions>().inner(),
            IpcConfig {
                provider,
                base_url,
                model,
                // Wrapped at once: the plaintext key is wiped when the save
                // is done, not left as freed heap.
                api_key: api_key.map(Zeroizing::new),
                clear_api_key,
                reuse_key_at_new_origin,
            },
            &|prompt| crate::commands::ask_native_confirmation(&app, prompt),
        )
    })
    .await
}

/// The arguments of [`assistant_save_config`] as the renderer sent them.
struct IpcConfig {
    provider: String,
    base_url: Option<String>,
    model: String,
    api_key: Option<Zeroizing<String>>,
    clear_api_key: Option<bool>,
    reuse_key_at_new_origin: Option<bool>,
}

/// [`assistant_save_config`] without the `AppHandle`: the renderer's
/// arguments as they arrive, `reuseKeyAtNewOrigin` included - which is read
/// by nothing. A move of the stored key is asked about in the native dialog
/// ([`save_config_confirmed`]) whatever the flag says.
fn save_config_from_ipc(
    db: &crate::db::Database,
    vault: &crate::commands::VaultPasswordStore,
    generations: &crate::commands::VaultGeneration,
    rotation: &crate::commands::VaultRotationLock,
    questions: &crate::commands::CredentialQuestions,
    ipc: IpcConfig,
    ask: crate::commands::ConfirmCredential<'_>,
) -> CmdResult<serde_json::Value> {
    let IpcConfig {
        provider,
        base_url,
        model,
        api_key,
        clear_api_key,
        reuse_key_at_new_origin,
    } = ipc;
    // Not the user's answer: a compromised renderer can set it.
    let _ = reuse_key_at_new_origin;
    let args = ConfigArgs {
        provider,
        base_url,
        model,
        api_key,
        clear_api_key: clear_api_key.unwrap_or(false),
    };
    save_config_confirmed(db, vault, generations, rotation, questions, args, ask)
}

/// The arguments of [`assistant_save_config`].
struct ConfigArgs {
    provider: String,
    base_url: Option<String>,
    model: String,
    api_key: Option<Zeroizing<String>>,
    clear_api_key: bool,
}

/// What a save refuses when the user did not allow the stored key to go to
/// the new address.
const KEY_MOVE_DECLINED: &str = "Enter the API key for the new address.";

/// What a save refuses when the stored settings changed while the user was
/// deciding: the answer was about another move.
const KEY_MOVE_CHANGED: &str =
    "The assistant settings changed while you were deciding - save them again.";

/// What a save refuses when "Allow" came within a second of the question
/// opening ([`crate::commands::CREDENTIAL_MIN_ANSWER_DELAY`]).
const KEY_MOVE_TOO_QUICK: &str = "The question about sending the stored API key was answered within a second of opening - too fast to be a decision. Save again to be asked again.";

/// What a save refuses when the vault was locked while the user was
/// deciding - even if it was unlocked again before "Allow".
const KEY_MOVE_LOCKED: &str =
    "The vault was locked while you were deciding - unlock it and save the settings again.";

/// What a save refuses while the last move of the stored key asked about, to
/// `host`, was answered "Don't allow" or "Cancel" less than
/// [`crate::commands::CREDENTIAL_DECLINE_BACKOFF`] ago, whatever the new
/// address is now: nothing is asked.
fn key_move_declined_lately(host: &str) -> String {
    format!(
        "Sending the stored API key to {} was declined a moment ago. Wait 30 seconds, then save again, or enter the API key for the new address.",
        crate::commands::dialog_text(host, MAX_DIALOG_NAME_CHARS)
    )
}

/// [`assistant_save_config`] without the `AppHandle`, `ask` answering the
/// native question (blocking: the blocking pool only). A save that would send
/// the stored key to another provider address with no new key typed is asked
/// about first: "Send the stored API key to <host>?" - declined (or allowed
/// within a second of opening), nothing is saved ([`KEY_MOVE_DECLINED`],
/// [`KEY_MOVE_TOO_QUICK`]); allowed, exactly that move is saved. The
/// renderer's `reuseKeyAtNewOrigin` used to decide it (A4-13), and a
/// compromised renderer could set it. One credential question at a time
/// (`questions`): while another is open the save is refused
/// ([`crate::commands::CREDENTIAL_QUESTION_OPEN`]), and the turn lasts until
/// the save is written. The rotation guard is taken for the look at the
/// stored settings and again for the save - not while the user decides.
/// An "Allow" counts only while the vault is still unlocked in the
/// generation the question was asked in (`generations`): given after a lock -
/// even one followed by an unlock - nothing is saved ([`KEY_MOVE_LOCKED`]).
fn save_config_confirmed(
    db: &crate::db::Database,
    vault: &crate::commands::VaultPasswordStore,
    generations: &crate::commands::VaultGeneration,
    rotation: &crate::commands::VaultRotationLock,
    questions: &crate::commands::CredentialQuestions,
    args: ConfigArgs,
    ask: crate::commands::ConfirmCredential<'_>,
) -> CmdResult<serde_json::Value> {
    use crate::commands::CredentialAnswer;
    // The vault as the save finds it, captured before anything is asked.
    let at_ask = crate::commands::VaultAtSave {
        vault,
        generations,
        generation: generations.current(),
    };
    let key_move = {
        let _rotation = rotation.try_shared()?;
        if !at_ask.unchanged() {
            return Err("Vault is locked.".into());
        }
        let stored = db.load_assistant_config().map_err(|e| e.to_string())?;
        pending_key_move(&stored, &args)?
    };
    let Some(key_move) = key_move else {
        // Seals the API key with the master password: not while that is
        // being changed.
        let _rotation = rotation.try_shared()?;
        return save_config(db, vault, args, None);
    };
    let Some(_turn) = questions.begin() else {
        return Err(crate::commands::CREDENTIAL_QUESTION_OPEN.into());
    };
    // After "Don't allow" or "Cancel", no move of the stored key is asked
    // about for 30 seconds ([`crate::commands::CREDENTIAL_DECLINE_BACKOFF`]),
    // whatever the new address; the answer names the host declined.
    let kind = crate::commands::QuestionKind::AssistantKeyMove;
    if let Some(declined) = questions.declined_lately(kind) {
        return Err(key_move_declined_lately(&declined).into());
    }
    let answer = ask(&key_move.prompt());
    if answer == CredentialAnswer::NotAllowed {
        questions.record_decline(kind, &key_move.to_host);
    }
    if answer != CredentialAnswer::Allowed {
        let quick = answer == CredentialAnswer::TooQuick;
        crate::commands::audit_or_log(
            db,
            "assistant.key_move_declined",
            None,
            &format!(
                "to {}{}",
                key_move.to_host,
                if quick { " answered=too-quickly" } else { "" }
            ),
        );
        return Err(if quick {
            KEY_MOVE_TOO_QUICK
        } else {
            KEY_MOVE_DECLINED
        }
        .into());
    }
    let _rotation = rotation.try_shared()?;
    save_config(db, vault, args, Some((&key_move, &at_ask)))
}

/// The provider, base URL and model a save writes, checked.
struct CheckedConfig {
    provider: String,
    /// `None`: the provider's default address.
    base_url: Option<String>,
    model: String,
}

/// Check what a save writes: a known provider, a model, a base URL that
/// today's rules accept ([`normalize_base_url`]).
fn check_config_fields(args: &ConfigArgs) -> CmdResult<CheckedConfig> {
    let provider = args.provider.trim().to_string();
    if provider != "openai" && provider != "anthropic" {
        return Err("Provider must be 'openai' or 'anthropic'.".into());
    }
    let model = args.model.trim().to_string();
    if model.is_empty() {
        return Err("Model is required.".into());
    }
    // Blank base URL = provider default; stored as None so a changed default
    // reaches existing configs. Deliberately no SSRF guard (unlike
    // Bitwarden): user-configured localhost/LAN inference servers (Ollama,
    // LM Studio) are a first-class use case for this feature - but plain
    // http only to local addresses (normalize_base_url), since the key
    // travels with every request.
    let base_url = args
        .base_url
        .as_deref()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .map(|u| normalize_base_url(&u))
        .transpose()?;
    Ok(CheckedConfig {
        provider,
        base_url,
        model,
    })
}

/// Whether the save `args` - checked here first - would send the `stored`
/// API key to another provider address: no new key typed, the key not being
/// removed, and the provider or the key's origin changing ([`key_move`]).
fn pending_key_move(
    stored: &crate::db::AssistantConfig,
    args: &ConfigArgs,
) -> CmdResult<Option<KeyMove>> {
    let checked = check_config_fields(args)?;
    let new_key = args.api_key.as_ref().is_some_and(|k| !k.trim().is_empty());
    if stored.api_key.is_none() || new_key || args.clear_api_key {
        return Ok(None);
    }
    Ok(key_move(
        stored,
        &checked.provider,
        checked.base_url.as_deref(),
    ))
}

/// [`assistant_save_config`] without the `AppHandle`. The caller holds the
/// rotation guard. The stored settings are read, checked
/// ([`check_key_reuse`]: a move of the stored key only as `allowed`, and
/// only while the vault is still as it was when the move was asked about)
/// and written in one transaction
/// ([`crate::db::Database::update_assistant_config`]); a new key is sealed
/// before it, so Argon2id never runs while the write lock is held. A failed
/// audit row after the commit is a `warning`, not an error.
fn save_config(
    db: &crate::db::Database,
    vault: &crate::commands::VaultPasswordStore,
    args: ConfigArgs,
    allowed: Option<(&KeyMove, &crate::commands::VaultAtSave<'_>)>,
) -> CmdResult<serde_json::Value> {
    let pw = vault.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let CheckedConfig {
        provider,
        base_url,
        model,
    } = check_config_fields(&args)?;
    let ConfigArgs {
        api_key,
        clear_api_key,
        ..
    } = args;
    let sealed_key = api_key
        .as_ref()
        .filter(|key| !key.trim().is_empty())
        .map(|key| crate::crypto::vault::seal(&pw, key.trim().as_bytes()))
        .transpose()
        .map_err(|e| e.to_string())?;

    let allowed_move = allowed.map(|(key_move, _)| key_move);
    let key_moved = db
        .update_assistant_config(|config| {
            // The answer counts only while the vault is still as it was
            // when the move was asked about - checked inside the transaction
            // that writes it.
            if allowed.is_some_and(|(_, at_ask)| !at_ask.unchanged()) {
                return Err(CmdError(KEY_MOVE_LOCKED.into()).into());
            }
            let key_moved = check_key_reuse(
                config,
                &provider,
                base_url.as_deref(),
                sealed_key.is_some(),
                clear_api_key,
                allowed_move,
            )
            .map_err(CmdError)?;
            config.provider = Some(provider);
            config.base_url = base_url;
            config.model = Some(model);
            if let Some(sealed) = sealed_key {
                config.api_key = Some(sealed);
            } else if clear_api_key {
                // None deletes the sealed row.
                config.api_key = None;
            }
            Ok(key_moved)
        })
        .map_err(CmdError::from)?;
    let detail = match allowed_move.filter(|_| key_moved) {
        Some(key_move) => format!(
            "saved (stored API key moved to {}, allowed in SSHSpan's confirmation dialog)",
            key_move.to_host
        ),
        None => "saved".to_string(),
    };
    // The settings are stored: a failed audit row is a warning.
    let warning = crate::commands::audit_or_warn(
        db,
        "assistant.config",
        None,
        &detail,
        "The settings were saved, but their audit row could not be written",
    );
    Ok(serde_json::json!({ "ok": true, "warning": warning }))
}

/// The default base URL for a provider when none is stored.
fn default_base_url(provider: &str) -> &'static str {
    if provider == "anthropic" {
        ANTHROPIC_DEFAULT_BASE
    } else {
        OPENAI_DEFAULT_BASE
    }
}

/// Validate a user-entered provider base URL (already trimmed, without a
/// trailing slash) and return it as stored. https reaches any host. Plain
/// http only reaches this machine or the local network - a loopback name or
/// address, an RFC 1918 private or link-local IPv4 address, or an IPv6
/// loopback, link-local or unique-local address - because the API key rides
/// on every request in cleartext (A6-10). Local inference servers (Ollama,
/// LM Studio) on such addresses stay a first-class use case; a LAN host
/// name is not resolved here, so such a server is entered by its address or
/// served over https.
///
/// What comes back - and is stored, asked about and requested - is the
/// address as parsed, not the raw text: the url crate drops tabs and line
/// breaks while it parses, so the raw text could carry sentences into the
/// native question. A control or invisible character is refused outright.
fn normalize_base_url(raw: &str) -> Result<String, String> {
    if raw.chars().any(|c| c.is_control() || is_disguising(c)) {
        return Err(
            "The base URL contains a control or invisible character - type the address again."
                .into(),
        );
    }
    let url = url::Url::parse(raw).map_err(|_| "Base URL is not a valid URL.".to_string())?;
    // Like the MCP server URL: credentials in it would be echoed back in
    // provider errors and the test-connection detail, unsealed.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(
            "Base URL must not contain a user name or password - enter the API key in its own field."
                .into(),
        );
    }
    match url.scheme() {
        "https" => {}
        "http" if url.host().is_some_and(|h| is_local_network_host(&h)) => {}
        "http" => {
            return Err(
                "Plain http:// is only allowed for local or private-network addresses (localhost, 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, or IPv6 loopback/link-local/unique-local) - use https:// for any other host."
                    .into(),
            )
        }
        _ => {
            return Err(
                "Base URL must start with https:// (or http:// for local servers).".into(),
            )
        }
    }
    let parsed = url.to_string();
    // `Url` adds a "/" to a bare origin; the stored form has none.
    Ok(
        if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
            parsed.trim_end_matches('/').to_string()
        } else {
            parsed
        },
    )
}

/// Whether a URL host is this machine or the local network (see
/// [`normalize_base_url`]).
fn is_local_network_host(host: &url::Host<&str>) -> bool {
    let v4_local =
        |ip: std::net::Ipv4Addr| ip.is_loopback() || ip.is_private() || ip.is_link_local();
    match host {
        url::Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        url::Host::Ipv4(ip) => v4_local(*ip),
        url::Host::Ipv6(ip) => {
            ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || ip.to_ipv4_mapped().is_some_and(v4_local)
        }
    }
}

/// The origin (scheme://host:port) a provider config sends its key to: the
/// stored base URL, else the provider's default.
fn key_origin(provider: Option<&str>, base_url: Option<&str>) -> Option<String> {
    let base = match base_url {
        Some(b) => b,
        None => default_base_url(provider?),
    };
    url::Url::parse(base)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}

/// The stored API key going to another provider address: the provider and
/// origin it was saved for, the ones it would go to, and how a dialog names
/// them. Only the user's "Allow" in the native dialog permits one
/// ([`save_config_confirmed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyMove {
    from_provider: Option<String>,
    from_origin: Option<String>,
    to_provider: String,
    to_origin: Option<String>,
    from_host: String,
    to_host: String,
    /// The address the key would be sent to with every request.
    to_address: String,
}

/// Longest address a credential question quotes, in characters.
const MAX_DIALOG_ADDRESS_CHARS: usize = 120;

/// Longest host or provider name a credential question quotes.
const MAX_DIALOG_NAME_CHARS: usize = 60;

impl KeyMove {
    /// The question. Every value in it is quoted cleaned and capped
    /// ([`crate::commands::dialog_text`]): the address and the provider come
    /// from settings a renderer saved (or a backup restored).
    fn prompt(&self) -> crate::commands::CredentialPrompt {
        use crate::commands::dialog_text;
        let name = |text: &str| dialog_text(text, MAX_DIALOG_NAME_CHARS);
        crate::commands::CredentialPrompt {
            title: "SSHSpan - Send the API key?".to_string(),
            message: format!(
                "Send the stored API key to {}?\n\nIt was saved for {} ({}). SSHSpan would send it \
                 with every assistant request to {} ({}). Allow only if you changed the address \
                 yourself.",
                name(&self.to_host),
                name(&self.from_host),
                name(self.from_provider.as_deref().unwrap_or("no provider")),
                dialog_text(&self.to_address, MAX_DIALOG_ADDRESS_CHARS),
                name(&self.to_provider)
            ),
        }
    }
}

/// The move of `old`'s key that saving `provider` and `base_url` (`None`:
/// the provider's default) would make, if the provider or the key's origin
/// changes. A path-only change on the same origin is not a move.
fn key_move(
    old: &crate::db::AssistantConfig,
    provider: &str,
    base_url: Option<&str>,
) -> Option<KeyMove> {
    let from_origin = key_origin(old.provider.as_deref(), old.base_url.as_deref());
    let to_origin = key_origin(Some(provider), base_url);
    if old.provider.as_deref() == Some(provider) && from_origin == to_origin {
        return None;
    }
    let host_of = |address: Option<&str>| {
        address
            .and_then(|a| url::Url::parse(a).ok())
            .map(|u| crate::commands::host_label(&u))
            .unwrap_or_else(|| "an unknown address".to_string())
    };
    let from_address = old.base_url.clone().or_else(|| {
        old.provider
            .as_deref()
            .map(|p| default_base_url(p).to_string())
    });
    let to_address = base_url
        .map(str::to_string)
        .unwrap_or_else(|| default_base_url(provider).to_string());
    Some(KeyMove {
        from_provider: old.provider.clone(),
        from_origin,
        to_provider: provider.to_string(),
        to_origin,
        from_host: host_of(from_address.as_deref()),
        to_host: host_of(Some(&to_address)),
        to_address,
    })
}

/// Whether a save may keep the stored API key (A4-13). The key was stored
/// for one provider at one origin; a save that changes either and supplies
/// no new key would send it to the new endpoint, so that is refused
/// ([`KEY_MOVE_DECLINED`]) unless it is exactly the move the user `allowed`
/// in the native dialog - another one means the settings changed meanwhile
/// ([`KEY_MOVE_CHANGED`]). `Ok(true)` means the key does move, for the audit
/// row; a new key, removing the key, or no stored key means nothing moves.
/// Pure so the rule is unit-testable.
fn check_key_reuse(
    old: &crate::db::AssistantConfig,
    provider: &str,
    base_url: Option<&str>,
    new_key: bool,
    clear_key: bool,
    allowed: Option<&KeyMove>,
) -> Result<bool, String> {
    if old.api_key.is_none() || new_key || clear_key {
        return Ok(false);
    }
    match (key_move(old, provider, base_url), allowed) {
        (None, _) => Ok(false),
        (Some(moving), Some(allowed)) if moving == *allowed => Ok(true),
        (Some(_), Some(_)) => Err(KEY_MOVE_CHANGED.into()),
        (Some(_), None) => Err(KEY_MOVE_DECLINED.into()),
    }
}

// ─── Provider plumbing ──────────────────────────────────────────────────────

struct ResolvedProvider {
    provider: String,
    base_url: String,
    model: String,
    api_key: Zeroizing<String>,
}

/// The saved provider with its key unsealed, on the blocking pool: the
/// unseal is an Argon2id derivation, which ran on an async worker before.
async fn load_provider_on_blocking_pool(app: &AppHandle) -> CmdResult<ResolvedProvider> {
    let app = app.clone();
    crate::commands::run_blocking(move || {
        load_provider_in(
            &app.state::<crate::AppState>().db,
            app.state::<crate::commands::VaultPasswordStore>().inner(),
            app.state::<crate::commands::VaultRotationLock>().inner(),
        )
    })
    .await
}

/// The saved provider with its key unsealed, without the `AppHandle`. It reads
/// the sealed key and unseals it with the master password, so the rotation guard is taken
/// before either is read and held until the key is unsealed: during a
/// master-password change a chat or a test is refused at once. Argon2id: the
/// commands run it on the blocking pool ([`load_provider_on_blocking_pool`]).
fn load_provider_in(
    db: &crate::db::Database,
    vault: &crate::commands::VaultPasswordStore,
    rotation: &crate::commands::VaultRotationLock,
) -> CmdResult<ResolvedProvider> {
    let _rotation = rotation.try_shared()?;
    let pw = vault.get().unwrap_or_default();
    if pw.is_empty() {
        return Err("Vault is locked.".into());
    }
    let config = db.load_assistant_config().map_err(|e| e.to_string())?;
    resolve_provider(config, &pw)
}

/// What a chat or a connection test refuses when the saved base URL breaks
/// today's rules ([`normalize_base_url`]). Nothing from the URL is quoted:
/// it may carry a user name or password.
const SAVED_BASE_URL_REFUSED: &str =
    "The saved assistant URL is no longer accepted - open Assistant settings and save it again.";

/// The provider a chat or a connection test talks to, from the saved
/// settings. The saved base URL is checked again against today's rules: one
/// saved before them - with a user name or password in it, or plain http to
/// a public host - is refused here, before the key is unsealed, instead of
/// being sent the key.
fn resolve_provider(
    config: crate::db::AssistantConfig,
    pw: &Zeroizing<String>,
) -> CmdResult<ResolvedProvider> {
    // Requested as parsed, like a save stores it now.
    let saved_base = config
        .base_url
        .as_deref()
        .map(|saved| normalize_base_url(saved.trim()))
        .transpose()
        .map_err(|_| CmdError(SAVED_BASE_URL_REFUSED.into()))?;
    let provider = config.provider.ok_or_else(|| {
        "AI assistant is not configured - open Settings > AI assistant.".to_string()
    })?;
    let sealed = config
        .api_key
        .ok_or_else(|| "No API key stored - save one in Settings > AI assistant.".to_string())?;
    let key_bytes = crate::crypto::vault::unseal(pw, &sealed).map_err(|e| e.to_string())?;
    let api_key = Zeroizing::new(
        String::from_utf8(key_bytes)
            .map_err(|_| "Stored API key is not valid UTF-8.".to_string())?,
    );
    let base_url = saved_base.unwrap_or_else(|| default_base_url(&provider).to_string());
    let model = config
        .model
        .ok_or_else(|| "No model configured.".to_string())?;
    Ok(ResolvedProvider {
        provider,
        base_url,
        model,
        api_key,
    })
}

/// The provider client. It never follows a redirect (A6-10): on a
/// cross-host hop reqwest strips only Authorization/Cookie-style headers, so
/// Anthropic's `x-api-key` would travel to wherever a proxy or gateway
/// pointed. With `Policy::none()` a 3xx comes back as a plain response, and
/// [`send_provider`] turns it into an error.
fn http_client(timeout: std::time::Duration) -> CmdResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CmdError(e.to_string()))
}

/// Send one provider request. A redirect is an error naming the host it
/// pointed at - the same rule as the MCP client: credentials never leave the
/// configured base URL. `failure` prefixes a transport error.
async fn send_provider(
    request: reqwest::RequestBuilder,
    failure: &str,
) -> CmdResult<reqwest::Response> {
    let resp = request
        .send()
        .await
        .map_err(|e| CmdError(format!("{failure}: {e}")))?;
    if resp.status().is_redirection() {
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok());
        return Err(CmdError(format!(
            "Provider returned a redirect ({}) to {} - redirects are not followed, so the API key never leaves the configured base URL. Set the base URL to the final address.",
            resp.status().as_u16(),
            redirect_target_host(resp.url(), location)
        )));
    }
    Ok(resp)
}

/// The host a redirect points at, for the error message: the Location's
/// host, resolved against the request URL when it is relative.
fn redirect_target_host(request_url: &url::Url, location: Option<&str>) -> String {
    location
        .and_then(|loc| request_url.join(loc).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "an unnamed location".to_string())
}

/// Turn a provider error response into an actionable message. Reads the body
/// once; status classes the user can act on (auth, wrong URL, rate limit)
/// come first.
async fn provider_error(resp: reqwest::Response) -> CmdError {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();
    let msg = match status.as_u16() {
        401 | 403 => "API key rejected (check the key and provider).".to_string(),
        404 => "Provider returned 404 - check the base URL and model name.".to_string(),
        429 => format!("Rate limited by the provider (429). {snippet}"),
        s if s >= 500 => format!("Provider server error ({s}). {snippet}"),
        s => format!("Provider error ({s}). {snippet}"),
    };
    CmdError(msg)
}

// ─── Normalized wire contract (mirrors src/renderer/assistant.js) ──────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    id: String,
    name: String,
    arguments_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum ChatMessage {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: Option<String>,
        tool_calls: Option<Vec<ToolCall>>,
    },
    Tool {
        tool_call_id: String,
        name: String,
        content: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolSpec {
    name: String,
    description: String,
    /// JSON Schema for the tool's parameters, as a JSON string. A string (not
    /// a parsed value) keeps the renderer's schema verbatim - the renderer
    /// authors it and the provider validates it, the backend only forwards.
    parameters_json: String,
}

/// The result a tool call gets when its turn ended before it ran.
const CANCELLED_TOOL_RESULT: &str = "cancelled";

/// The conversation as it may be sent to a provider, whatever state the
/// renderer's history is in (A7-44; defence in depth for A4-03 - the
/// renderer repairs its own history too, this also covers older histories):
/// - an assistant message with neither text nor tool calls is dropped: both
///   providers reject it, so one empty model reply failed every later turn
///   on the tab;
/// - every tool call gets a result directly after its assistant message: a
///   call left unanswered (Stop, the per-turn call cap, an error mid-loop)
///   gets a synthetic "cancelled" result, because both providers reject an
///   unanswered call;
/// - a tool result that answers no call of the assistant message right
///   before it (a duplicate, or one cut off from its call) is dropped, for
///   the same reason.
fn normalize_history(messages: &[ChatMessage]) -> Vec<ChatMessage> {
    let mut out = Vec::with_capacity(messages.len());
    // Calls of the last assistant message still waiting for a result.
    let mut pending: Vec<(String, String)> = Vec::new();
    for m in messages {
        if let ChatMessage::Tool { tool_call_id, .. } = m {
            if let Some(i) = pending.iter().position(|(id, _)| id == tool_call_id) {
                pending.remove(i);
                out.push(m.clone());
            }
            continue;
        }
        answer_pending_calls(&mut out, &mut pending);
        if let ChatMessage::Assistant {
            content,
            tool_calls,
        } = m
        {
            let calls = tool_calls.as_deref().unwrap_or_default();
            let has_text = content.as_deref().is_some_and(|t| !t.trim().is_empty());
            if calls.is_empty() && !has_text {
                continue;
            }
            pending = calls
                .iter()
                .map(|c| (c.id.clone(), c.name.clone()))
                .collect();
        }
        out.push(m.clone());
    }
    answer_pending_calls(&mut out, &mut pending);
    out
}

/// Close the open tool-call group: a "cancelled" result for every call still
/// waiting for one.
fn answer_pending_calls(out: &mut Vec<ChatMessage>, pending: &mut Vec<(String, String)>) {
    for (tool_call_id, name) in pending.drain(..) {
        out.push(ChatMessage::Tool {
            tool_call_id,
            name,
            content: CANCELLED_TOOL_RESULT.into(),
        });
    }
}

// ─── OpenAI-compatible shaping ─────────────────────────────────────────────

/// Which request field carries the output-token cap in an OpenAI-style
/// request (A4-18). OpenAI's own API deprecated `max_tokens` and rejects it
/// for its reasoning models, so requests to api.openai.com send
/// `max_completion_tokens`; every other OpenAI-compatible server (Ollama,
/// LM Studio, OpenRouter, Groq) still expects `max_tokens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenCapField {
    MaxTokens,
    MaxCompletionTokens,
}

impl TokenCapField {
    fn for_base_url(base_url: &str) -> Self {
        let host = url::Url::parse(base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        if host.as_deref() == Some("api.openai.com") {
            Self::MaxCompletionTokens
        } else {
            Self::MaxTokens
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::MaxTokens => "max_tokens",
            Self::MaxCompletionTokens => "max_completion_tokens",
        }
    }
}

fn openai_body(
    model: &str,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
    max_tokens: u32,
    token_cap: TokenCapField,
) -> CmdResult<serde_json::Value> {
    let messages = normalize_history(messages);
    let mut wire_msgs = Vec::with_capacity(messages.len());
    for m in &messages {
        let v = match m {
            ChatMessage::System { content } => serde_json::json!({
                "role": "system", "content": content,
            }),
            ChatMessage::User { content } => serde_json::json!({
                "role": "user", "content": content,
            }),
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                let calls: Vec<serde_json::Value> = tool_calls
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "id": c.id,
                            "type": "function",
                            "function": { "name": c.name, "arguments": c.arguments_json },
                        })
                    })
                    .collect();
                if calls.is_empty() {
                    serde_json::json!({ "role": "assistant", "content": content })
                } else {
                    // OpenAI rejects an assistant message whose tool_calls are
                    // not followed by matching tool results;
                    // normalize_history guarantees the pairing.
                    serde_json::json!({
                        "role": "assistant", "content": content, "tool_calls": calls,
                    })
                }
            }
            ChatMessage::Tool {
                tool_call_id,
                content,
                ..
            } => serde_json::json!({
                "role": "tool", "tool_call_id": tool_call_id, "content": content,
            }),
        };
        wire_msgs.push(v);
    }

    let mut body = serde_json::json!({
        "model": model,
        "messages": wire_msgs,
    });
    body[token_cap.key()] = serde_json::json!(max_tokens);
    if !tools.is_empty() {
        let mut wire_tools = Vec::with_capacity(tools.len());
        for t in tools {
            let params: serde_json::Value =
                serde_json::from_str(&t.parameters_json).map_err(|e| {
                    CmdError(format!(
                        "tool '{}' has invalid parameters_json: {e}",
                        t.name
                    ))
                })?;
            wire_tools.push(serde_json::json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": params,
                },
            }));
        }
        body["tools"] = serde_json::Value::Array(wire_tools);
    }
    Ok(body)
}

fn parse_openai_response(body: &serde_json::Value) -> CmdResult<serde_json::Value> {
    let msg = body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .ok_or_else(|| CmdError("Provider returned no choices[0].message.".into()))?;
    let text = msg
        .get("content")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let mut calls = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(|t| t.as_array()) {
        for c in arr {
            let id = c.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let name = c
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let args = c
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            if !name.is_empty() {
                calls.push(serde_json::json!({
                    "id": if id.is_empty() { uuid::Uuid::new_v4().to_string() } else { id.to_string() },
                    "name": name,
                    "arguments_json": args,
                }));
            }
        }
    }
    Ok(serde_json::json!({ "text": text, "tool_calls": calls }))
}

// ─── Anthropic shaping ──────────────────────────────────────────────────────

fn anthropic_body(
    model: &str,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
    max_tokens: u32,
) -> CmdResult<serde_json::Value> {
    let messages = normalize_history(messages);
    let mut system_parts: Vec<String> = Vec::new();
    let mut wire_msgs: Vec<serde_json::Value> = Vec::new();
    for m in &messages {
        match m {
            // Anthropic takes system as a top-level field, not a message.
            ChatMessage::System { content } => system_parts.push(content.clone()),
            ChatMessage::User { content } => wire_msgs.push(serde_json::json!({
                "role": "user", "content": content,
            })),
            ChatMessage::Assistant {
                content,
                tool_calls,
            } => {
                let mut blocks: Vec<serde_json::Value> = Vec::new();
                // Anthropic rejects a text block that is only whitespace.
                if let Some(t) = content.as_ref().filter(|t| !t.trim().is_empty()) {
                    blocks.push(serde_json::json!({ "type": "text", "text": t }));
                }
                for c in tool_calls.clone().unwrap_or_default() {
                    let input: serde_json::Value =
                        serde_json::from_str(&c.arguments_json).unwrap_or(serde_json::json!({}));
                    blocks.push(serde_json::json!({
                        "type": "tool_use", "id": c.id, "name": c.name, "input": input,
                    }));
                }
                wire_msgs.push(serde_json::json!({ "role": "assistant", "content": blocks }));
            }
            ChatMessage::Tool {
                tool_call_id,
                content,
                ..
            } => {
                // Anthropic carries tool results as tool_result blocks inside
                // a user turn. Consecutive tool results must share one user
                // message - the API rejects adjacent same-role messages - so
                // merge into the previous user message when it is one.
                let block = serde_json::json!({
                    "type": "tool_result", "tool_use_id": tool_call_id, "content": content,
                });
                let merged = match wire_msgs.last_mut() {
                    Some(serde_json::Value::Object(prev))
                        if prev.get("role").and_then(|r| r.as_str()) == Some("user")
                            && prev
                                .get("content")
                                .and_then(|c| c.as_array())
                                .map(|a| {
                                    a.iter().any(|b| {
                                        b.get("type").and_then(|t| t.as_str())
                                            == Some("tool_result")
                                    })
                                })
                                .unwrap_or(false) =>
                    {
                        prev.get_mut("content")
                            .and_then(|c| c.as_array_mut())
                            .map(|a| a.push(block.clone()));
                        true
                    }
                    _ => false,
                };
                if !merged {
                    wire_msgs.push(serde_json::json!({
                        "role": "user", "content": [block],
                    }));
                }
            }
        }
    }
    // Anthropic rejects an empty conversation; a tools-only history is not a
    // valid request either way, so fail loudly instead of sending garbage.
    if wire_msgs.is_empty() {
        return Err("Anthropic request needs at least one non-system message.".into());
    }

    let mut body = serde_json::json!({
        "model": model,
        "messages": wire_msgs,
        "max_tokens": max_tokens,
    });
    if !system_parts.is_empty() {
        body["system"] = serde_json::Value::String(system_parts.join("\n\n"));
    }
    if !tools.is_empty() {
        let mut wire_tools = Vec::with_capacity(tools.len());
        for t in tools {
            let schema: serde_json::Value =
                serde_json::from_str(&t.parameters_json).map_err(|e| {
                    CmdError(format!(
                        "tool '{}' has invalid parameters_json: {e}",
                        t.name
                    ))
                })?;
            wire_tools.push(serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": schema,
            }));
        }
        body["tools"] = serde_json::Value::Array(wire_tools);
    }
    Ok(body)
}

fn parse_anthropic_response(body: &serde_json::Value) -> CmdResult<serde_json::Value> {
    let content = body
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| CmdError("Anthropic response has no content blocks.".into()))?;
    let mut texts: Vec<String> = Vec::new();
    let mut calls = Vec::new();
    for b in content {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => {
                if let Some(t) = b.get("text").and_then(|v| v.as_str()) {
                    texts.push(t.to_string());
                }
            }
            Some("tool_use") => {
                let name = b.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                if !name.is_empty() {
                    calls.push(serde_json::json!({
                        "id": b.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
                        "name": name,
                        "arguments_json": serde_json::to_string(
                            b.get("input").unwrap_or(&serde_json::json!({})),
                        )
                        .unwrap_or_else(|_| "{}".to_string()),
                    }));
                }
            }
            _ => {}
        }
    }
    let text = if texts.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(texts.join(""))
    };
    Ok(serde_json::json!({ "text": text, "tool_calls": calls }))
}

// ─── Chat / test commands ───────────────────────────────────────────────────

#[tauri::command]
pub async fn assistant_chat(
    app: AppHandle,
    messages: Vec<ChatMessage>,
    tools: Vec<ToolSpec>,
    max_tokens: Option<u32>,
) -> CmdResult<serde_json::Value> {
    let p = load_provider_on_blocking_pool(&app).await?;
    let max_tokens = max_tokens.unwrap_or(2048);
    let client = http_client(CHAT_TIMEOUT)?;

    let resp = if p.provider == "anthropic" {
        let body = anthropic_body(&p.model, &messages, &tools, max_tokens)?;
        send_provider(
            client
                .post(format!("{}/v1/messages", p.base_url))
                .header("x-api-key", p.api_key.as_str())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body),
            "Provider request failed",
        )
        .await?
    } else {
        let body = openai_body(
            &p.model,
            &messages,
            &tools,
            max_tokens,
            TokenCapField::for_base_url(&p.base_url),
        )?;
        send_provider(
            client
                .post(format!("{}/chat/completions", p.base_url))
                .bearer_auth(p.api_key.as_str())
                .json(&body),
            "Provider request failed",
        )
        .await?
    };

    if !resp.status().is_success() {
        return Err(provider_error(resp).await);
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| CmdError(format!("Provider returned a non-JSON response: {e}")))?;
    if p.provider == "anthropic" {
        parse_anthropic_response(&body)
    } else {
        parse_openai_response(&body)
    }
}

#[tauri::command]
pub async fn assistant_test_connection(app: AppHandle) -> CmdResult<serde_json::Value> {
    let p = load_provider_on_blocking_pool(&app).await?;
    let client = http_client(TEST_TIMEOUT)?;

    let resp = if p.provider == "anthropic" {
        // Anthropic has no cheap authenticated GET; a 1-token messages call
        // is the smallest real check and validates base URL, key, and model.
        let body = serde_json::json!({
            "model": p.model,
            "max_tokens": 1,
            "messages": [{ "role": "user", "content": "ping" }],
        });
        send_provider(
            client
                .post(format!("{}/v1/messages", p.base_url))
                .header("x-api-key", p.api_key.as_str())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body),
            "Connection failed",
        )
        .await?
    } else {
        send_provider(
            client
                .get(format!("{}/models", p.base_url))
                .bearer_auth(p.api_key.as_str()),
            "Connection failed",
        )
        .await?
    };

    if !resp.status().is_success() {
        return Err(provider_error(resp).await);
    }
    Ok(serde_json::json!({
        "ok": true,
        "detail": format!("Connected to {} (model: {}).", p.base_url, p.model),
    }))
}

// ─── Level + execution gate ─────────────────────────────────────────────────

#[tauri::command]
pub fn assistant_set_level(
    app: AppHandle,
    tab_id: String,
    level: String,
) -> CmdResult<serde_json::Value> {
    if !valid_level(&level) {
        return Err(format!("Unknown access level '{level}'.").into());
    }
    app.state::<AssistantLevels>().set(&tab_id, &level);
    Ok(serde_json::json!({ "ok": true }))
}

#[tauri::command]
pub fn assistant_get_level(app: AppHandle, tab_id: String) -> CmdResult<serde_json::Value> {
    let level = app.state::<AssistantLevels>().get(&tab_id);
    Ok(serde_json::json!({ "level": level }))
}

/// Run a command the user approved on the assistant's card: the command plus
/// Enter on the session's stdin. The tab's level (Execute or higher) and the
/// command's characters are checked first ([`check_exec_command`]); every run
/// is audited (`assistant.exec`, first 200 characters).
#[tauri::command]
pub fn assistant_exec(
    app: AppHandle,
    session_id: String,
    tab_id: String,
    command: String,
) -> CmdResult<serde_json::Value> {
    let level = app.state::<AssistantLevels>().get(&tab_id);
    check_exec_command(&level, &command).map_err(CmdError)?;
    // The same gate as terminal_send (and assistant_type_text): a locked
    // vault drives no session - and leaves no audit row for a command that
    // could not run.
    if vault_password(&app)?.is_empty() {
        return Err("Vault is locked.".into());
    }
    let db = &app.state::<crate::AppState>().db;
    let snippet: String = command.chars().take(200).collect();
    db.add_audit(
        "assistant.exec",
        None,
        &format!("tab={tab_id} level={level} cmd={snippet}"),
    )
    .map_err(|e| e.to_string())?;

    // Same path as terminal_send: the renderer's confirmed AI command is just
    // bytes on the session's stdin, Enter included.
    let registry = app
        .state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
        .inner()
        .clone();
    let mut bytes = command.into_bytes();
    bytes.push(b'\r');
    crate::ssh_client::session_send(&registry, &session_id, bytes).map_err(CmdError::from)?;
    Ok(serde_json::json!({ "ok": true }))
}

/// Type `text` into the session's prompt for the assistant, never pressing
/// Enter: the backend path for the `type_command` tool and a suggestion
/// card's Insert (Ruling R7). The tab's level is re-checked here (Draft or
/// higher) and line breaks and control keys are refused before anything is
/// sent ([`check_typed_text`]), so a confused or prompt-injected model cannot
/// run a command through typing; `assistant_exec` stays the only AI path that
/// appends Enter. Every typing is audited (`assistant.type`, first 200
/// characters, like `assistant.exec`).
#[tauri::command]
pub fn assistant_type_text(
    app: AppHandle,
    session_id: String,
    tab_id: String,
    text: String,
) -> CmdResult<serde_json::Value> {
    let level = app.state::<AssistantLevels>().get(&tab_id);
    check_typed_text(&level, &text).map_err(CmdError)?;
    // The same gate as terminal_send: a locked vault drives no session.
    if vault_password(&app)?.is_empty() {
        return Err("Vault is locked.".into());
    }
    let db = &app.state::<crate::AppState>().db;
    let snippet: String = text.chars().take(200).collect();
    db.add_audit(
        "assistant.type",
        None,
        &format!("tab={tab_id} level={level} text={snippet}"),
    )
    .map_err(|e| e.to_string())?;
    // Exactly what terminal_send does: the bytes go to the session's stdin.
    let registry = app
        .state::<std::sync::Arc<crate::ssh_client::SessionRegistry>>()
        .inner()
        .clone();
    crate::ssh_client::session_send(&registry, &session_id, text.into_bytes())
        .map_err(CmdError::from)?;
    Ok(serde_json::json!({ "ok": true }))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// Helpers shared by the assistant and MCP tests.
#[cfg(test)]
pub(crate) mod test_support {
    /// Make every audit write on `db` fail from now on (a schema trigger, so
    /// on every connection). Runs on its own thread and connection, so async
    /// tests can call it too.
    pub(crate) fn refuse_audit_rows(db: &crate::db::Database) {
        crate::db::test_support::execute(
            db,
            "CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit refused by the test'); END",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "run_command".into(),
            description: "Run a shell command.".into(),
            parameters_json: r#"{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}"#.into(),
        }]
    }

    fn history() -> Vec<ChatMessage> {
        vec![
            ChatMessage::System {
                content: "You help administer servers.".into(),
            },
            ChatMessage::User {
                content: "check disk".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: Some(vec![ToolCall {
                    id: "call_1".into(),
                    name: "get_terminal_output".into(),
                    arguments_json: "{}".into(),
                }]),
            },
            ChatMessage::Tool {
                tool_call_id: "call_1".into(),
                name: "get_terminal_output".into(),
                content: "user@host:~$".into(),
            },
            ChatMessage::Assistant {
                content: Some("Disk is fine.".into()),
                tool_calls: None,
            },
        ]
    }

    #[test]
    fn openai_shapes_all_message_kinds() {
        let body = openai_body(
            "gpt-4o-mini",
            &history(),
            &tools(),
            1024,
            TokenCapField::MaxTokens,
        )
        .unwrap();
        assert_eq!(body["model"], "gpt-4o-mini");
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(
            msgs[2]["tool_calls"][0]["function"]["name"],
            "get_terminal_output"
        );
        // Arguments cross the wire as the string the renderer supplied.
        assert_eq!(msgs[2]["tool_calls"][0]["function"]["arguments"], "{}");
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "call_1");
        // Assistant message without tool calls must not carry an empty array.
        assert!(msgs[4].get("tool_calls").is_none());
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["properties"]["command"]["type"],
            "string"
        );
    }

    #[test]
    fn openai_omits_tools_when_empty() {
        let body = openai_body("m", &history(), &[], 1024, TokenCapField::MaxTokens).unwrap();
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn openai_rejects_bad_schema_json() {
        let bad = vec![ToolSpec {
            name: "x".into(),
            description: "x".into(),
            parameters_json: "{not json".into(),
        }];
        assert!(openai_body("m", &history(), &bad, 1024, TokenCapField::MaxTokens).is_err());
    }

    #[test]
    fn openai_parses_text_toolcalls_and_mixed() {
        let text_only = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "hi" } }]
        });
        let r = parse_openai_response(&text_only).unwrap();
        assert_eq!(r["text"], "hi");
        assert_eq!(r["tool_calls"].as_array().unwrap().len(), 0);

        // OpenAI returns null content when the model only calls tools.
        let calls_only = serde_json::json!({
            "choices": [{ "message": {
                "role": "assistant", "content": null,
                "tool_calls": [{
                    "id": "call_9", "type": "function",
                    "function": { "name": "run_command", "arguments": "{\"command\":\"ls\"}" }
                }]
            }}]
        });
        let r = parse_openai_response(&calls_only).unwrap();
        assert!(r["text"].is_null());
        assert_eq!(r["tool_calls"][0]["name"], "run_command");
        assert_eq!(r["tool_calls"][0]["arguments_json"], "{\"command\":\"ls\"}");

        let no_choices = serde_json::json!({ "choices": [] });
        assert!(parse_openai_response(&no_choices).is_err());
    }

    #[test]
    fn anthropic_hoists_system_and_shapes_tools() {
        let body = anthropic_body("claude-sonnet-4-5", &history(), &tools(), 1024).unwrap();
        assert_eq!(body["system"], "You help administer servers.");
        assert!(body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["role"] != "system"));
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
        let msgs = body["messages"].as_array().unwrap();
        // user, assistant(text absent, tool_use), user(tool_result), assistant(text)
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(msgs[1]["content"][0]["input"], serde_json::json!({}));
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"][0]["type"], "tool_result");
        assert_eq!(msgs[2]["content"][0]["tool_use_id"], "call_1");
    }

    #[test]
    fn anthropic_merges_consecutive_tool_results() {
        let msgs = vec![
            ChatMessage::User {
                content: "go".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: Some(vec![
                    ToolCall {
                        id: "a".into(),
                        name: "t1".into(),
                        arguments_json: "{}".into(),
                    },
                    ToolCall {
                        id: "b".into(),
                        name: "t2".into(),
                        arguments_json: "{}".into(),
                    },
                ]),
            },
            ChatMessage::Tool {
                tool_call_id: "a".into(),
                name: "t1".into(),
                content: "one".into(),
            },
            ChatMessage::Tool {
                tool_call_id: "b".into(),
                name: "t2".into(),
                content: "two".into(),
            },
        ];
        let body = anthropic_body("m", &msgs, &[], 1024).unwrap();
        let wire = body["messages"].as_array().unwrap();
        // Adjacent same-role messages are an API error; both results must sit
        // in ONE following user message.
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[2]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn untrusted_block_in_user_message_shapes_for_both_providers() {
        // The prompt-injection hardening delivers the terminal snapshot inside
        // a single user message (nonce-wrapped, closing tag stripped). Both
        // providers must shape that list into a valid request - critically,
        // Anthropic must NOT split it into adjacent same-role messages.
        let nonce = "1234567890123456";
        let snapshot = format!(
            "<terminal_output_{nonce} trust=\"untrusted\">\n$ df -h\nFilesystem  Size\n</terminal_output_{nonce}>"
        );
        let user_content = format!("summarize the screen\n\n{snapshot}");
        let msgs = vec![
            ChatMessage::System {
                content: "rules".into(),
            },
            ChatMessage::User {
                content: user_content.clone(),
            },
        ];

        // OpenAI: system stays in-band, user content passes through verbatim.
        let oi = openai_body("m", &msgs, &[], 1024, TokenCapField::MaxTokens).unwrap();
        let oi_msgs = oi["messages"].as_array().unwrap();
        assert_eq!(oi_msgs[0]["role"], "system");
        assert_eq!(oi_msgs[1]["role"], "user");
        assert_eq!(
            oi_msgs[1]["content"],
            serde_json::Value::String(user_content.clone())
        );
        assert!(oi_msgs[1]["content"]
            .as_str()
            .unwrap()
            .contains(&format!("terminal_output_{nonce}")));

        // Anthropic: system hoisted, exactly one user message (no adjacent
        // same-role split), and the untrusted block survives inside it.
        let an = anthropic_body("m", &msgs, &[], 1024).unwrap();
        assert_eq!(an["system"], "rules");
        let an_msgs = an["messages"].as_array().unwrap();
        assert_eq!(an_msgs.len(), 1, "must be exactly one non-system message");
        assert_eq!(an_msgs[0]["role"], "user");
        let an_text = an_msgs[0]["content"].as_str().unwrap();
        assert!(an_text.contains(&format!("terminal_output_{nonce}")));
        assert!(an_text.contains("summarize the screen"));
    }

    #[test]
    fn anthropic_rejects_system_only_conversation() {
        let msgs = vec![ChatMessage::System {
            content: "s".into(),
        }];
        assert!(anthropic_body("m", &msgs, &[], 1024).is_err());
    }

    #[test]
    fn anthropic_parses_text_and_tool_use() {
        let body = serde_json::json!({
            "content": [
                { "type": "text", "text": "Let me check. " },
                { "type": "tool_use", "id": "tu_1", "name": "run_command",
                  "input": { "command": "df -h" } },
                { "type": "text", "text": "Running it." }
            ]
        });
        let r = parse_anthropic_response(&body).unwrap();
        assert_eq!(r["text"], "Let me check. Running it.");
        assert_eq!(r["tool_calls"][0]["id"], "tu_1");
        assert_eq!(
            r["tool_calls"][0]["arguments_json"],
            "{\"command\":\"df -h\"}"
        );

        let no_content = serde_json::json!({ "id": "msg_1" });
        assert!(parse_anthropic_response(&no_content).is_err());
    }

    #[test]
    fn level_gate_allows_only_execute_and_yolo() {
        assert!(!level_permits_exec("read"));
        assert!(!level_permits_exec("draft"));
        assert!(level_permits_exec("execute"));
        assert!(level_permits_exec("yolo"));
        assert!(!level_permits_exec(""));
        assert!(!level_permits_exec("admin"));
    }

    #[test]
    fn levels_default_to_read_and_roundtrip() {
        let levels = AssistantLevels::new();
        assert_eq!(levels.get("tab1"), "read");
        levels.set("tab1", "yolo");
        assert_eq!(levels.get("tab1"), "yolo");
        levels.clear();
        assert_eq!(levels.get("tab1"), "read");
    }

    #[test]
    fn unknown_level_strings_are_rejected() {
        for bad in ["YOLO", "write", "", "read-only"] {
            assert!(!valid_level(bad), "{bad} must not validate");
        }
        for good in ["read", "draft", "execute", "yolo"] {
            assert!(valid_level(good));
        }
    }

    #[test]
    fn sealed_key_roundtrip() {
        let pw = Zeroizing::new("vault-master".to_string());
        let sealed = crate::crypto::vault::seal(&pw, b"sk-test-123").unwrap();
        let back = crate::crypto::vault::unseal(&pw, &sealed).unwrap();
        assert_eq!(back, b"sk-test-123");
    }

    // ── AI typing never presses Enter (R7: A4-02, A6-01, A3-30) ─────────

    #[test]
    fn typing_needs_draft_or_higher() {
        assert!(check_typed_text("read", "ls").is_err());
        assert!(check_typed_text("", "ls").is_err());
        for level in ["draft", "execute", "yolo"] {
            assert!(check_typed_text(level, "ls -la").is_ok(), "{level}");
        }
        let err = check_typed_text("read", "ls").unwrap_err();
        assert!(err.contains("Draft"), "{err}");
    }

    #[test]
    fn typed_text_cannot_press_enter_or_send_control_keys() {
        for bad in [
            "ls\n",
            "ls\r",
            "echo harmless\nid",
            "uname -a\r\n",
            "\u{4}",       // Ctrl-D: ends the shell
            "\u{3}",       // Ctrl-C
            "\u{1a}",      // Ctrl-Z
            "\u{1b}[A",    // ESC: drives full-screen programs
            "rm x\u{7f}",  // DEL
            "a\u{0}b",     // NUL
            "a\u{9b}31mb", // C1 CSI
            "",            // nothing to type
        ] {
            assert!(
                check_typed_text("draft", bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        let err = check_typed_text("execute", "curl x | sh\n").unwrap_err();
        assert!(err.contains("Enter"), "{err}");
        // TAB (completion) and ordinary Unicode text are fine.
        for ok in ["cd /var/log\t", "printf 'é ✓'", "ls -la && df -h"] {
            assert!(check_typed_text("draft", ok).is_ok(), "{ok:?}");
        }
    }

    /// Text the user reviews on a card must type exactly what it shows:
    /// bidi overrides/isolates, zero-width and other invisible characters
    /// could disguise it. And a typed "line" has a sane length.
    #[test]
    fn typed_text_cannot_hide_what_it_says_or_run_on() {
        for hidden in [
            "ls \u{202E}txt.exe",   // right-to-left override
            "rm \u{2066}x\u{2069}", // isolates
            "a\u{200B}b",           // zero-width space
            "a\u{200F}b",           // right-to-left mark
            "\u{FEFF}ls",           // zero-width no-break space
            "a\u{2028}b",           // line separator
            "a\u{2060}b",           // word joiner
            "a\u{061C}b",           // Arabic letter mark
            "a\u{E0041}b",          // tag character
        ] {
            let err = check_typed_text("draft", hidden).unwrap_err();
            assert!(
                err.contains("invisible or text-direction"),
                "{hidden:?}: {err}"
            );
        }
        let longest = "x".repeat(4096);
        assert!(check_typed_text("draft", &longest).is_ok());
        let err = check_typed_text("draft", &format!("{longest}x")).unwrap_err();
        assert!(err.contains("4096"), "{err}");
    }

    // ── AI commands run exactly what the Approve card shows ───

    /// Trojan Source: a bidi override or an invisible character makes the
    /// Approve card show a command reordered or shortened, while the shell
    /// runs it as written. `assistant_exec` refuses what typing refuses.
    #[test]
    fn exec_refuses_commands_that_could_hide_what_they_run() {
        for hidden in [
            "ls \u{202E}txt.exe",               // right-to-left override
            "echo safe \u{2066}; rm x\u{2069}", // isolates
            "rm\u{200B} -rf /tmp/x",            // zero-width space
            "cat a\u{200F}b",                   // right-to-left mark
            "\u{FEFF}id",                       // zero-width no-break space
            "id\u{2028}rm x",                   // line separator
            "a\u{2060}b",                       // word joiner
            "a\u{E0041}b",                      // tag character
        ] {
            let err = check_exec_command("execute", hidden)
                .expect_err(&format!("{hidden:?} must be refused"));
            assert!(
                err.contains("invisible or text-direction"),
                "{hidden:?}: {err}"
            );
            assert!(err.contains("Nothing was run"), "{hidden:?}: {err}");
        }
    }

    #[test]
    fn exec_refuses_control_characters_other_than_tab() {
        for bad in [
            "ls\nrm -rf /tmp/x", // a second line the card may not show
            "ls\r",
            "\u{3}",    // Ctrl-C
            "\u{1b}[A", // ESC
            "a\u{0}b",  // NUL
            "a\u{9b}b", // C1 CSI
        ] {
            let err =
                check_exec_command("yolo", bad).expect_err(&format!("{bad:?} must be refused"));
            assert!(err.contains("control character"), "{bad:?}: {err}");
            assert!(err.contains("Nothing was run"), "{bad:?}: {err}");
        }
        let err = check_exec_command("execute", "id\nwhoami").unwrap_err();
        assert!(err.contains("U+000A"), "{err}");
        // Ordinary Unicode commands still run.
        for ok in ["df -h", "echo 'héllo ✓'", "ls -la && df -h"] {
            assert!(check_exec_command("execute", ok).is_ok(), "{ok:?}");
        }
    }

    /// Readline completes on TAB before Enter, so a command with a TAB
    /// can run as something other than what was approved. Typing keeps TAB
    /// (completion is what the user wants there).
    #[test]
    fn exec_refuses_tab_but_typing_keeps_it() {
        for with_tab in ["ls /etc/pass\t", "printf 'a\tb'"] {
            let err = check_exec_command("execute", with_tab)
                .expect_err(&format!("{with_tab:?} must be refused"));
            assert!(err.contains("TAB"), "{with_tab:?}: {err}");
            assert!(err.contains("Nothing was run"), "{with_tab:?}: {err}");
        }
        assert!(check_typed_text("draft", "cd /var/log\t").is_ok());
    }

    /// Every invisible or format character, range by range: each
    /// Unicode general-category Cf code point (Unicode 15.1, checked against
    /// Python's unicodedata) and every Default_Ignorable_Code_Point -
    /// invisible combining marks, Hangul fillers, variation selectors and the
    /// code points reserved as default-ignorable. Both ends of every range
    /// are refused by typing and by running; the code points just outside a
    /// range are not (unless the next range starts there).
    const EXPECTED_DISGUISING_RANGES: [(u32, u32, &str); 26] = [
        (0x00AD, 0x00AD, "soft hyphen"),
        (0x034F, 0x034F, "combining grapheme joiner"),
        (0x0600, 0x0605, "Arabic number signs"),
        (0x061C, 0x061C, "Arabic letter mark"),
        (0x06DD, 0x06DD, "Arabic end of ayah"),
        (0x070F, 0x070F, "Syriac abbreviation mark"),
        (0x0890, 0x0891, "Arabic pound and piastre marks above"),
        (0x08E2, 0x08E2, "Arabic disputed end of ayah"),
        (0x115F, 0x1160, "Hangul choseong and jungseong fillers"),
        (0x17B4, 0x17B5, "Khmer inherent vowels"),
        (
            0x180B,
            0x180F,
            "Mongolian variation selectors and vowel separator",
        ),
        (0x200B, 0x200F, "zero-width space and joiners, LRM, RLM"),
        (0x2028, 0x2029, "line and paragraph separators"),
        (0x202A, 0x202E, "bidi embeddings and overrides"),
        (0x2060, 0x206F, "word joiner, invisible operators, isolates"),
        (0x3164, 0x3164, "Hangul filler"),
        (0xFE00, 0xFE0F, "variation selectors"),
        (0xFEFF, 0xFEFF, "zero-width no-break space"),
        (0xFFA0, 0xFFA0, "halfwidth Hangul filler"),
        (0xFFF0, 0xFFFB, "reserved, interlinear annotation"),
        (0x110BD, 0x110BD, "Kaithi number sign"),
        (0x110CD, 0x110CD, "Kaithi number sign above"),
        (0x13430, 0x1343F, "Egyptian hieroglyph format controls"),
        (0x1BCA0, 0x1BCA3, "shorthand format controls"),
        (0x1D173, 0x1D17A, "musical symbol format controls"),
        (0xE0000, 0xE0FFF, "tags, variation selectors supplement"),
    ];

    fn refused_by_both_gates(c: char) -> bool {
        let text = format!("ls{c}x");
        let typed = check_typed_text("draft", &text)
            .is_err_and(|e| e.contains("invisible or text-direction"));
        let run = check_exec_command("execute", &text)
            .is_err_and(|e| e.contains("invisible or text-direction"));
        typed && run
    }

    #[test]
    fn every_invisible_or_format_range_is_refused_at_both_ends() {
        let in_any = |cp: u32| {
            EXPECTED_DISGUISING_RANGES
                .iter()
                .any(|&(first, last, _)| (first..=last).contains(&cp))
        };
        for &(first, last, what) in &EXPECTED_DISGUISING_RANGES {
            for cp in [first, last] {
                let c = char::from_u32(cp).unwrap();
                assert!(
                    refused_by_both_gates(c),
                    "U+{cp:04X} ({what}) must be refused"
                );
            }
            for cp in [first - 1, last + 1] {
                let Some(c) = char::from_u32(cp) else {
                    continue;
                };
                if !in_any(cp) && !c.is_control() {
                    assert!(
                        !refused_by_both_gates(c),
                        "U+{cp:04X} next to {what} is visible text"
                    );
                }
            }
        }
        // Ordinary text in many scripts still types and runs.
        for ok in [
            "ls -la",
            "echo 'héllo ✓'",
            "cat 日本語.txt",
            "echo مرحبا",
            "echo 😀",
        ] {
            assert!(check_typed_text("draft", ok).is_ok(), "{ok:?}");
            assert!(check_exec_command("execute", ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn the_disguising_table_is_sorted_and_its_ranges_do_not_overlap() {
        assert!(DISGUISING_CHARS.iter().all(|&(first, last)| first <= last));
        assert!(
            DISGUISING_CHARS.windows(2).all(|w| w[0].1 < w[1].0),
            "sorted, without overlaps"
        );
        let table: Vec<(u32, u32)> = DISGUISING_CHARS
            .iter()
            .map(|&(first, last)| (first as u32, last as u32))
            .collect();
        let expected: Vec<(u32, u32)> = EXPECTED_DISGUISING_RANGES
            .iter()
            .map(|&(first, last, _)| (first, last))
            .collect();
        assert_eq!(table, expected);
    }

    #[test]
    fn exec_still_needs_execute_or_yolo() {
        for level in ["read", "draft", "", "admin"] {
            let err = check_exec_command(level, "df -h").unwrap_err();
            assert!(err.contains("access level"), "{level}: {err}");
        }
        assert!(check_exec_command("yolo", "df -h").is_ok());
    }

    // ── Provider client hardening (A6-10) ───────────────────────────────

    /// Credentials in the base URL would be echoed back in provider errors
    /// and the test-connection detail; the key has its own sealed field.
    #[test]
    fn a_base_url_must_not_carry_credentials() {
        for bad in [
            "https://user:pass@api.openai.com/v1",
            "https://sk-key@api.example.com/v1",
            "http://u:p@localhost:11434/v1",
        ] {
            let err = normalize_base_url(bad).unwrap_err();
            assert!(err.contains("user name or password"), "{bad}: {err}");
        }
    }

    /// A provider (proxy, gateway) that answers with a redirect must not get
    /// the request - and with it Anthropic's x-api-key header, which reqwest
    /// does not strip on a cross-host hop - forwarded to the redirect target.
    #[tokio::test]
    async fn provider_client_does_not_follow_a_redirect_with_the_api_key() {
        use std::io::{Read as _, Write as _};
        let bystander = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bystander_addr = bystander.local_addr().unwrap();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = bystander.accept() {
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                let _ = seen_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });
        let provider = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let provider_addr = provider.local_addr().unwrap();
        let location = format!("http://{bystander_addr}/steal");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = provider.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                );
            }
        });
        let client = http_client(TEST_TIMEOUT).unwrap();
        let resp = client
            .post(format!("http://{provider_addr}/v1/messages"))
            .header("x-api-key", "sk-ant-secret")
            .body("{}")
            .send()
            .await;
        assert!(
            seen_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "the redirect target must never receive the request (it would carry x-api-key)"
        );
        assert_eq!(
            resp.expect("the 302 itself comes back").status().as_u16(),
            302
        );
    }

    #[tokio::test]
    async fn a_provider_redirect_is_an_error_naming_its_target_host() {
        use std::io::{Read as _, Write as _};
        let provider = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = provider.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = provider.accept() {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://evil.example.com/harvest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let client = http_client(TEST_TIMEOUT).unwrap();
        let err = send_provider(
            client
                .post(format!("http://{addr}/chat/completions"))
                .bearer_auth("sk-secret")
                .body("{}"),
            "Provider request failed",
        )
        .await
        .unwrap_err();
        assert!(err.0.contains("redirect (307)"), "{err}");
        assert!(err.0.contains("evil.example.com"), "{err}");
        assert!(!err.0.contains("sk-secret"), "{err}");
    }

    #[test]
    fn a_redirect_target_is_named_by_its_host() {
        let base = url::Url::parse("https://gateway.example.com/v1/messages").unwrap();
        assert_eq!(
            redirect_target_host(&base, Some("https://evil.example.com/steal")),
            "evil.example.com"
        );
        // A relative Location stays on the request's host.
        assert_eq!(
            redirect_target_host(&base, Some("/elsewhere")),
            "gateway.example.com"
        );
        assert_eq!(redirect_target_host(&base, None), "an unnamed location");
    }

    #[test]
    fn plain_http_base_urls_only_reach_local_or_private_hosts() {
        for ok in [
            "http://localhost:11434/v1",
            "http://127.0.0.1:1234/v1",
            "http://10.0.0.5:8080/v1",
            "http://172.16.3.4/v1",
            "http://172.31.255.1",
            "http://192.168.1.10:11434/v1",
            "http://169.254.10.20/v1",
            "http://[::1]:8080/v1",
            "http://[fe80::1]/v1",
            "http://[fd12:3456::1]/v1",
            "http://ollama.localhost/v1",
            "https://api.openai.com/v1",
            "https://openrouter.ai/api/v1",
            "https://10.0.0.5/v1",
        ] {
            assert!(normalize_base_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://api.openai.com/v1",
            "http://8.8.8.8/v1",
            "http://172.32.0.1",
            "http://192.169.1.1",
            "http://[2001:db8::1]/v1",
            "http://gpu-box.lan:11434/v1",
            "ftp://example.com",
            "localhost:11434",
            "not a url",
        ] {
            assert!(normalize_base_url(bad).is_err(), "{bad} must be refused");
        }
        let err = normalize_base_url("http://api.openai.com/v1").unwrap_err();
        assert!(err.contains("http://"), "{err}");
    }

    // ── A saved base URL is checked again when it is used ──────

    const SAVED_URL_REFUSED: &str =
        "The saved assistant URL is no longer accepted - open Assistant settings and save it again.";

    fn saved_config(base: Option<&str>, pw: &Zeroizing<String>) -> crate::db::AssistantConfig {
        crate::db::AssistantConfig {
            provider: Some("openai".into()),
            base_url: base.map(String::from),
            model: Some("m".into()),
            api_key: Some(crate::crypto::vault::seal(pw, b"sk-test-123").unwrap()),
        }
    }

    /// A base URL saved before today's rules (no user name or password,
    /// plain http only to local addresses) is refused when a chat or a test
    /// would use it - the saved key would otherwise travel with it - and the
    /// message carries nothing from the URL.
    #[test]
    fn a_saved_base_url_that_todays_rules_refuse_is_not_used() {
        let pw = Zeroizing::new("vault-master".to_string());
        for bad in [
            "https://user:secret-pass@api.openai.com/v1",
            "https://sk-in-the-url@api.example.com/v1",
            "http://api.openai.com/v1",
            "ftp://api.example.com",
            "not a url",
        ] {
            let err = match resolve_provider(saved_config(Some(bad), &pw), &pw) {
                Ok(_) => panic!("{bad} must be refused"),
                Err(e) => e.0,
            };
            assert_eq!(err, SAVED_URL_REFUSED, "{bad}");
        }
        for ok in [
            Some("https://api.openai.com/v1"),
            Some("http://localhost:11434/v1"),
            None,
        ] {
            let resolved = resolve_provider(saved_config(ok, &pw), &pw)
                .unwrap_or_else(|e| panic!("{ok:?}: {e}"));
            assert_eq!(resolved.api_key.as_str(), "sk-test-123");
            assert_eq!(
                resolved.base_url,
                ok.unwrap_or(OPENAI_DEFAULT_BASE),
                "{ok:?}"
            );
        }
    }

    /// The settings view never hands the renderer the user name or password
    /// of a legacy base URL (secrets never cross IPC).
    #[test]
    fn the_settings_view_drops_credentials_from_a_saved_base_url() {
        let pw = Zeroizing::new("vault-master".to_string());
        let view = config_view(&saved_config(
            Some("https://user:secret-pass@api.openai.com/v1"),
            &pw,
        ));
        assert_eq!(view["base_url"], "https://api.openai.com/v1");
        assert!(!view.to_string().contains("secret-pass"), "{view}");
        assert_eq!(view["has_api_key"], true);
        let plain = config_view(&saved_config(Some("http://localhost:11434/v1"), &pw));
        assert_eq!(plain["base_url"], "http://localhost:11434/v1");
        assert_eq!(
            config_view(&saved_config(None, &pw))["base_url"],
            serde_json::Value::Null
        );
    }

    // ── Saving the settings ─────────────────

    fn config_db() -> crate::db::Database {
        crate::db::Database::open_at(
            std::env::temp_dir().join(format!("sshspan-ai-{}.sqlite", uuid::Uuid::new_v4())),
        )
        .unwrap()
    }

    fn unlocked() -> crate::commands::VaultPasswordStore {
        let vault = crate::commands::VaultPasswordStore::new();
        vault.set("vault-master".into());
        vault
    }

    fn config_args(base: Option<&str>, key: Option<&str>) -> ConfigArgs {
        ConfigArgs {
            provider: "openai".into(),
            base_url: base.map(String::from),
            model: "gpt-test".into(),
            api_key: key.map(|k| Zeroizing::new(k.to_string())),
            clear_api_key: false,
        }
    }

    #[test]
    fn saving_the_settings_seals_the_key_and_keeps_the_origin_binding() {
        let db = config_db();
        let vault = unlocked();
        let out = save_config(&db, &vault, config_args(None, Some(" sk-new ")), None).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["warning"], serde_json::Value::Null);
        let stored = db.load_assistant_config().unwrap();
        let pw = Zeroizing::new("vault-master".to_string());
        let key = crate::crypto::vault::unseal(&pw, stored.api_key.as_deref().unwrap()).unwrap();
        assert_eq!(key, b"sk-new");
        // A new origin without a new key is still refused, and changes
        // nothing.
        let err = save_config(
            &db,
            &vault,
            config_args(Some("http://localhost:11434/v1"), None),
            None,
        )
        .unwrap_err();
        assert!(err.0.contains("API key"), "{}", err.0);
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        // Locked: refused before anything is read or sealed.
        let err = save_config(
            &db,
            &crate::commands::VaultPasswordStore::new(),
            config_args(None, Some("k")),
            None,
        )
        .unwrap_err();
        assert_eq!(err.0, "Vault is locked.");
    }

    #[test]
    fn saved_settings_whose_audit_row_fails_are_reported_as_saved_with_a_warning() {
        let db = config_db();
        test_support::refuse_audit_rows(&db);
        let out = save_config(&db, &unlocked(), config_args(None, Some("sk-new")), None)
            .expect("the settings are stored - the call must not report a failure");
        assert!(
            out["warning"]
                .as_str()
                .unwrap_or_default()
                .contains("audit"),
            "{out}"
        );
        assert!(db.load_assistant_config().unwrap().api_key.is_some());
    }

    // ── The stored key moves to a new address only when the user allows it
    //    in a native dialog ──────────────────────────────────────────────

    /// The arguments as a compromised renderer sends them: `args` with the
    /// "reuse the key at the new address" flag set.
    fn ipc_with_reuse_flag(args: ConfigArgs) -> IpcConfig {
        IpcConfig {
            provider: args.provider,
            base_url: args.base_url,
            model: args.model,
            api_key: args.api_key,
            clear_api_key: Some(args.clear_api_key),
            reuse_key_at_new_origin: Some(true),
        }
    }

    #[test]
    fn rw_s2_the_stored_api_key_moves_only_when_the_native_question_allows_it() {
        use crate::commands::{CredentialAnswer, CredentialPrompt};
        let db = config_db();
        let vault = unlocked();
        let generations = crate::commands::VaultGeneration::new();
        let rotation = crate::commands::VaultRotationLock::new();
        // A "no" is not asked about again for 30 seconds: the clock is moved
        // past that before the same move is asked about again.
        let clock = crate::commands::TestClock::new();
        let questions = clock.questions();
        let never = |p: &CredentialPrompt| -> CredentialAnswer {
            panic!("nothing moves, nothing to ask: {}", p.message)
        };
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(None, Some("sk-old")),
            &never,
        )
        .unwrap();
        let sealed = db.load_assistant_config().unwrap().api_key;
        let asked = std::sync::Mutex::new(Vec::<String>::new());
        let decline = |p: &CredentialPrompt| {
            asked.lock().unwrap().push(p.message.clone());
            CredentialAnswer::NotAllowed
        };
        let moved = || config_args(Some("https://llm.example.com/v1"), None);
        // The renderer's flag, through the command's own handling of its
        // arguments: it decides nothing - the question is asked anyway.
        let err = save_config_from_ipc(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            ipc_with_reuse_flag(moved()),
            &decline,
        )
        .expect_err("the renderer's flag alone must not move the key");
        assert_eq!(err.0, "Enter the API key for the new address.");
        let asked = asked.into_inner().unwrap();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert!(
            asked[0].starts_with("Send the stored API key to llm.example.com?"),
            "{}",
            asked[0]
        );
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(stored.base_url, None, "nothing changed");
        assert_eq!(stored.api_key, sealed);
        // Allowed, once the "no" is 30 seconds old: the key goes along,
        // untouched.
        clock.advance(crate::commands::CREDENTIAL_DECLINE_BACKOFF);
        let allow = |_: &CredentialPrompt| CredentialAnswer::Allowed;
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .unwrap();
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(
            stored.base_url.as_deref(),
            Some("https://llm.example.com/v1")
        );
        assert_eq!(stored.api_key, sealed);
        // Nothing moves, nothing is asked: another path on the same address,
        // a new key with the change, removing the key.
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(Some("https://llm.example.com/v2"), None),
            &never,
        )
        .unwrap();
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(Some("https://other.example.com/v1"), Some("sk-other")),
            &never,
        )
        .unwrap();
        let mut remove = config_args(Some("https://third.example.com/v1"), None);
        remove.clear_api_key = true;
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            remove,
            &never,
        )
        .unwrap();
        assert_eq!(db.load_assistant_config().unwrap().api_key, None);
    }

    /// An "Allow" within a second of the question opening is not taken as
    /// the user's decision, and while another credential question is open a
    /// move of the key is refused without a second question: one stray key
    /// could otherwise answer a question the user never read.
    #[test]
    fn rw_fix1_a_quick_allow_or_an_open_question_never_moves_the_api_key() {
        use crate::commands::{CredentialAnswer, CredentialPrompt, CredentialQuestions};
        let db = config_db();
        let vault = unlocked();
        let generations = crate::commands::VaultGeneration::new();
        let rotation = crate::commands::VaultRotationLock::new();
        let questions = CredentialQuestions::new();
        let none = |_: &CredentialPrompt| -> CredentialAnswer { CredentialAnswer::NotAllowed };
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(None, Some("sk-old")),
            &none,
        )
        .unwrap();
        let moved = || config_args(Some("https://llm.example.com/v1"), None);
        let quick = |_: &CredentialPrompt| CredentialAnswer::TooQuick;
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &quick,
        )
        .expect_err("a quick Allow moves nothing");
        assert_eq!(err.0, KEY_MOVE_TOO_QUICK);
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        // Another question is open: refused, and not asked.
        let open = questions.begin().expect("no question is open yet");
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let allow = |_: &CredentialPrompt| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            CredentialAnswer::Allowed
        };
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .expect_err("one question at a time");
        assert_eq!(err.0, crate::commands::CREDENTIAL_QUESTION_OPEN);
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        // Once it is answered, the move is asked about - and allowed.
        drop(open);
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A move of the stored key answered "Don't allow" or "Cancel" is not
    /// asked about again for 30 seconds - a renderer could ask again and
    /// again until a tired user gave in. The save is refused and says why;
    /// after 30 seconds the question is asked again.
    #[test]
    fn fw_s1_a_declined_key_move_is_not_asked_again_for_30_seconds() {
        use crate::commands::{CredentialAnswer, CredentialPrompt};
        let db = config_db();
        let vault = unlocked();
        let generations = crate::commands::VaultGeneration::new();
        let rotation = crate::commands::VaultRotationLock::new();
        let clock = crate::commands::TestClock::new();
        let questions = clock.questions();
        let asked = std::cell::Cell::new(0);
        let counter = &asked;
        let answer = |reply: CredentialAnswer| {
            move |_: &CredentialPrompt| {
                counter.set(counter.get() + 1);
                reply
            }
        };
        let never = answer(CredentialAnswer::NotAllowed);
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(None, Some("sk-old")),
            &never,
        )
        .unwrap();
        assert_eq!(asked.get(), 0, "a new key moves nothing");
        let moved = || config_args(Some("https://llm.example.com/v1"), None);
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &never,
        )
        .unwrap_err();
        assert_eq!((asked.get(), err.0.as_str()), (1, KEY_MOVE_DECLINED));
        let allow = answer(CredentialAnswer::Allowed);
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .unwrap_err();
        assert_eq!(asked.get(), 1, "not asked again within 30 seconds");
        assert_eq!(
            err.0,
            "Sending the stored API key to llm.example.com was declined a moment ago. Wait 30 \
             seconds, then save again, or enter the API key for the new address."
        );
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        clock.advance(crate::commands::CREDENTIAL_DECLINE_BACKOFF);
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.get(), 2, "asked again after 30 seconds");
        assert_eq!(
            db.load_assistant_config().unwrap().base_url.as_deref(),
            Some("https://llm.example.com/v1")
        );
    }

    /// Keyed by the host, the 30 seconds after a "no" let a renderer ask at
    /// once about moving the stored key to the next made-up host. After a
    /// "no", no move of the stored key is asked about for 30 seconds,
    /// whatever the new address, and the answer names the host declined. A
    /// "no" to another kind of question holds nothing back here.
    #[test]
    fn fw_u2_a_declined_key_move_holds_back_every_key_move() {
        use crate::commands::{CredentialAnswer, CredentialPrompt, QuestionKind};
        let db = config_db();
        let vault = unlocked();
        let generations = crate::commands::VaultGeneration::new();
        let rotation = crate::commands::VaultRotationLock::new();
        let clock = crate::commands::TestClock::new();
        let questions = clock.questions();
        let asked = std::cell::Cell::new(0);
        let counter = &asked;
        let answer = |reply: CredentialAnswer| {
            move |_: &CredentialPrompt| {
                counter.set(counter.get() + 1);
                reply
            }
        };
        let declined = answer(CredentialAnswer::NotAllowed);
        let save = |args: ConfigArgs, ask: &dyn Fn(&CredentialPrompt) -> CredentialAnswer| {
            save_config_confirmed(&db, &vault, &generations, &rotation, &questions, args, ask)
        };
        save(config_args(None, Some("sk-old")), &declined).unwrap();
        assert_eq!(asked.get(), 0, "a new key moves nothing");
        questions.record_decline(QuestionKind::McpCredential, "mcp.example.com");
        questions.record_decline(QuestionKind::BitwardenDestination, "vault.example.com");
        let err = save(
            config_args(Some("https://llm.example.com/v1"), None),
            &declined,
        )
        .unwrap_err();
        assert_eq!(
            (asked.get(), err.0.as_str()),
            (1, KEY_MOVE_DECLINED),
            "asked, though the other kinds were declined"
        );
        let allow = answer(CredentialAnswer::Allowed);
        for base in [
            "https://llm.example.com/v2",
            "https://LLM.example.com:443/x/",
            "https://llm.example.org/v1",
            "https://a1.attacker.example/v1",
            "https://a2.attacker.example/v1",
        ] {
            let err = save(config_args(Some(base), None), &allow).unwrap_err();
            assert_eq!(asked.get(), 1, "{base}: held back");
            assert_eq!(
                err.0,
                "Sending the stored API key to llm.example.com was declined a moment ago. \
                 Wait 30 seconds, then save again, or enter the API key for the new address.",
                "{base}"
            );
        }
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        // 30 seconds after the "no": asked again, whatever the address.
        clock.advance(crate::commands::CREDENTIAL_DECLINE_BACKOFF);
        save(
            config_args(Some("https://a3.attacker.example/v1"), None),
            &allow,
        )
        .unwrap();
        assert_eq!(asked.get(), 2, "asked again after 30 seconds");
        assert_eq!(
            db.load_assistant_config().unwrap().base_url.as_deref(),
            Some("https://a3.attacker.example/v1")
        );
    }

    /// An "Allow" counts only while the vault is still unlocked in the
    /// generation the question was asked in. Locked and unlocked again while
    /// the question was open: the key is not moved, the new address is not
    /// stored and no "saved" row is written. Asked again, it moves.
    #[test]
    fn fw_r2_an_allow_after_a_lock_never_moves_the_api_key() {
        use crate::commands::{CredentialAnswer, CredentialPrompt, CredentialQuestions};
        let db = config_db();
        let vault = unlocked();
        let generations = crate::commands::VaultGeneration::new();
        let rotation = crate::commands::VaultRotationLock::new();
        let questions = CredentialQuestions::new();
        let never = |p: &CredentialPrompt| -> CredentialAnswer {
            panic!("nothing moves, nothing to ask: {}", p.message)
        };
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            config_args(None, Some("sk-old")),
            &never,
        )
        .unwrap();
        let sealed = db.load_assistant_config().unwrap().api_key;
        let saved_rows = || {
            db.list_audit(100)
                .unwrap()
                .into_iter()
                .filter(|r| r.action == "assistant.config")
                .count()
        };
        let rows_before = saved_rows();
        let moved = || config_args(Some("https://llm.example.com/v1"), None);
        // Locked, then unlocked again, while the question was open.
        let relocked = |_: &CredentialPrompt| {
            generations.bump();
            vault.clear();
            vault.set("vault-master".into());
            CredentialAnswer::Allowed
        };
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &relocked,
        )
        .expect_err("an Allow after a lock moves nothing");
        assert_eq!(err.0, KEY_MOVE_LOCKED);
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(stored.base_url, None, "the new address is not stored");
        assert_eq!(stored.api_key, sealed, "the key stays where it was");
        assert_eq!(saved_rows(), rows_before, "nothing was saved");
        // Still locked when "Allow" arrives.
        let locked = |_: &CredentialPrompt| {
            generations.bump();
            vault.clear();
            CredentialAnswer::Allowed
        };
        let err = save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &locked,
        )
        .expect_err("a locked vault moves nothing");
        assert_eq!(err.0, "Vault is locked.");
        assert_eq!(db.load_assistant_config().unwrap().base_url, None);
        // Unlocked, and asked again: the key moves.
        vault.set("vault-master".into());
        let allow = |_: &CredentialPrompt| CredentialAnswer::Allowed;
        save_config_confirmed(
            &db,
            &vault,
            &generations,
            &rotation,
            &questions,
            moved(),
            &allow,
        )
        .unwrap();
        let stored = db.load_assistant_config().unwrap();
        assert_eq!(
            stored.base_url.as_deref(),
            Some("https://llm.example.com/v1")
        );
        assert_eq!(stored.api_key, sealed);
    }

    /// The url crate drops tabs and line breaks while it parses, so the raw
    /// address a renderer saved could carry sentences into the question - and
    /// a NUL cut the Windows message and aborted the process under GTK. A
    /// base URL with a control or an invisible character is refused.
    #[test]
    fn rw_fix1_a_base_url_with_control_or_invisible_characters_is_refused() {
        for bad in [
            "https://llm.example.com/v1\n\nSSHSpan checked this address. Allow",
            "https://llm.example.com/v1\r\nX",
            "https://llm.\texample.com/v1",
            "https://llm.example.com/\u{0}v1",
            "https://llm.example.com/v1\u{202e}lla",
            "https://llm.example.com/\u{200b}v1",
        ] {
            let err = normalize_base_url(bad).expect_err(bad);
            assert!(err.contains("control or invisible"), "{bad:?}: {err}");
        }
    }

    /// What is stored, asked about and requested is the address as parsed -
    /// it used to be the raw text the renderer sent.
    #[test]
    fn rw_fix1_the_base_url_is_stored_as_parsed() {
        assert_eq!(
            normalize_base_url("HTTPS://LLM.Example.COM:443/v1").unwrap(),
            "https://llm.example.com/v1"
        );
        assert_eq!(
            normalize_base_url("https://llm.example.com").unwrap(),
            "https://llm.example.com"
        );
        assert_eq!(
            normalize_base_url("https://llm.example.com/a b").unwrap(),
            "https://llm.example.com/a%20b"
        );
        let db = config_db();
        save_config(
            &db,
            &unlocked(),
            config_args(Some("HTTPS://LLM.Example.COM:443/v1/"), Some("sk-new")),
            None,
        )
        .unwrap();
        assert_eq!(
            db.load_assistant_config().unwrap().base_url.as_deref(),
            Some("https://llm.example.com/v1")
        );
    }

    /// The question quotes every value cleaned and the address capped:
    /// nothing a renderer or a restored backup put into the settings can
    /// reorder, hide or add a line to what the user is asked.
    #[test]
    fn rw_fix1_the_api_key_question_quotes_a_clean_capped_address() {
        let old = crate::db::AssistantConfig {
            provider: Some("open\u{202e}ai\u{0}\nAllow".into()),
            base_url: None,
            model: Some("m".into()),
            api_key: Some("sealed".into()),
        };
        let long = format!("https://llm.example.com/{}", "a".repeat(400));
        let moving = key_move(&old, "openai", Some(&long)).unwrap();
        let message = moving.prompt().message;
        assert!(
            !message
                .chars()
                .any(|c| (c.is_control() && c != '\n') || is_disguising(c)),
            "{message:?}"
        );
        assert_eq!(
            message.matches('\n').count(),
            2,
            "only the question's own paragraph break: {message:?}"
        );
        assert!(
            message.chars().count() < 450,
            "the address is capped: {} characters",
            message.chars().count()
        );
        assert!(message.contains('\u{2026}'), "{message}");
    }

    /// A chat or a connection test unseals the stored key with the master
    /// password: not while a master-password change re-encrypts the vault -
    /// it is refused at once, before anything is read. The store holds a
    /// password that cannot open the key meanwhile, so a refusal that came
    /// only after an unseal would be another error (the test used to bound
    /// the refusal at 0.5 s, which a loaded machine could exceed).
    #[test]
    fn rw_b2_the_api_key_is_not_unsealed_during_a_password_change() {
        let db = config_db();
        let vault = unlocked();
        let rotation = crate::commands::VaultRotationLock::new();
        save_config(&db, &vault, config_args(None, Some("sk-test")), None).unwrap();
        let change = rotation.hold_like_a_password_change();
        let cannot_open = crate::commands::VaultPasswordStore::new();
        cannot_open.set("not-the-vault-master".into());
        let started = std::time::Instant::now();
        let err = match load_provider_in(&db, &cannot_open, &rotation) {
            Ok(_) => panic!("unsealed during a password change"),
            Err(e) => e,
        };
        assert_eq!(
            err.0,
            crate::commands::VAULT_REENCRYPTING,
            "refused before any unseal"
        );
        // At once, without waiting for the change (the limit is wide for a
        // loaded machine).
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        drop(change);
        let provider = match load_provider_in(&db, &vault, &rotation) {
            Ok(p) => p,
            Err(e) => panic!("{}", e.0),
        };
        assert_eq!(provider.api_key.as_str(), "sk-test");
    }

    // ── A stored key does not follow a new endpoint (A4-13) ─────────────

    fn stored_config(provider: &str, base: Option<&str>) -> crate::db::AssistantConfig {
        crate::db::AssistantConfig {
            provider: Some(provider.into()),
            base_url: base.map(String::from),
            model: Some("m".into()),
            api_key: Some("sealed-blob".into()),
        }
    }

    #[test]
    fn a_stored_key_does_not_silently_follow_a_new_provider_or_origin() {
        let old = stored_config("openai", None);
        // Same endpoint - the default spelled out, another path, other case.
        let same = [
            Some("https://api.openai.com/v1"),
            Some("https://API.openai.com/v2"),
            None,
        ];
        for base in same {
            assert_eq!(
                check_key_reuse(&old, "openai", base, false, false, None),
                Ok(false),
                "{base:?}"
            );
        }
        // A new origin or provider with no new key is refused...
        let err = check_key_reuse(
            &old,
            "openai",
            Some("http://localhost:11434/v1"),
            false,
            false,
            None,
        )
        .unwrap_err();
        assert!(err.contains("API key"), "{err}");
        assert!(check_key_reuse(&old, "anthropic", None, false, false, None).is_err());
        // ...unless it is the move the user allowed in the native dialog
        // (reported so the audit row says so), or a new key comes with the
        // save, or the key is being removed.
        let to_anthropic = key_move(&old, "anthropic", None).unwrap();
        assert_eq!(to_anthropic.to_host, "api.anthropic.com");
        assert_eq!(to_anthropic.from_host, "api.openai.com");
        assert_eq!(
            check_key_reuse(&old, "anthropic", None, false, false, Some(&to_anthropic)),
            Ok(true)
        );
        // Another move than the one allowed: the settings changed meanwhile.
        assert_eq!(
            check_key_reuse(
                &old,
                "openai",
                Some("https://other.example.com/v1"),
                false,
                false,
                Some(&to_anthropic)
            ),
            Err(KEY_MOVE_CHANGED.to_string())
        );
        assert_eq!(
            check_key_reuse(&old, "anthropic", None, true, false, None),
            Ok(false)
        );
        assert_eq!(
            check_key_reuse(&old, "anthropic", None, false, true, None),
            Ok(false)
        );
        // Nothing stored: nothing can follow.
        let mut empty = stored_config("openai", None);
        empty.api_key = None;
        assert_eq!(
            check_key_reuse(
                &empty,
                "anthropic",
                Some("https://x.example"),
                false,
                false,
                None
            ),
            Ok(false)
        );
    }

    // ── Conversation request shaping (A7-44, A4-03, A4-18) ──────────────

    fn call(id: &str, name: &str) -> ToolCall {
        ToolCall {
            id: id.into(),
            name: name.into(),
            arguments_json: "{}".into(),
        }
    }

    #[test]
    fn empty_assistant_messages_are_not_sent_to_either_provider() {
        let msgs = vec![
            ChatMessage::System {
                content: "s".into(),
            },
            ChatMessage::User {
                content: "first".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: None,
            },
            ChatMessage::User {
                content: "second".into(),
            },
            ChatMessage::Assistant {
                content: Some("  ".into()),
                tool_calls: Some(vec![]),
            },
            ChatMessage::User {
                content: "third".into(),
            },
        ];
        let oi = openai_body("m", &msgs, &[], 64, TokenCapField::MaxTokens).unwrap();
        let roles: Vec<&str> = oi["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["role"].as_str().unwrap())
            .collect();
        assert_eq!(roles, ["system", "user", "user", "user"]);
        let an = anthropic_body("m", &msgs, &[], 64).unwrap();
        let wire = an["messages"].as_array().unwrap();
        assert!(
            wire.iter().all(|m| m["role"] == "user"),
            "no empty assistant turn may be sent: {wire:?}"
        );
    }

    #[test]
    fn every_tool_call_gets_a_result_before_the_next_message() {
        // A turn stopped after the first of two calls: c2 never got a result.
        let msgs = vec![
            ChatMessage::User {
                content: "go".into(),
            },
            ChatMessage::Assistant {
                content: Some("Checking.".into()),
                tool_calls: Some(vec![call("c1", "t1"), call("c2", "t2")]),
            },
            ChatMessage::Tool {
                tool_call_id: "c1".into(),
                name: "t1".into(),
                content: "one".into(),
            },
            ChatMessage::User {
                content: "next".into(),
            },
        ];
        let oi = openai_body("m", &msgs, &[], 64, TokenCapField::MaxTokens).unwrap();
        let wire = oi["messages"].as_array().unwrap();
        // user, assistant(c1, c2), tool c1, tool c2 (synthesized), user
        assert_eq!(wire.len(), 5, "{wire:?}");
        assert_eq!(wire[2]["tool_call_id"], "c1");
        assert_eq!(wire[3]["role"], "tool");
        assert_eq!(wire[3]["tool_call_id"], "c2");
        assert_eq!(wire[3]["content"], "cancelled");
        assert_eq!(wire[4]["role"], "user");

        let an = anthropic_body("m", &msgs, &[], 64).unwrap();
        let wire = an["messages"].as_array().unwrap();
        // user, assistant(text, tool_use c1, tool_use c2), user(two tool_result
        // blocks), user(next) - consecutive user turns are combined by the API.
        let results = wire[2]["content"].as_array().unwrap();
        assert_eq!(results.len(), 2, "{wire:?}");
        assert_eq!(results[1]["tool_use_id"], "c2");
        assert_eq!(results[1]["content"], "cancelled");
    }

    #[test]
    fn a_trailing_unanswered_call_and_a_stray_result_are_repaired() {
        // The history ends on a call with no result, and carries a result
        // whose call is not directly before it.
        let msgs = vec![
            ChatMessage::User {
                content: "go".into(),
            },
            ChatMessage::Tool {
                tool_call_id: "stray".into(),
                name: "t".into(),
                content: "x".into(),
            },
            ChatMessage::Assistant {
                content: None,
                tool_calls: Some(vec![call("c9", "t9")]),
            },
        ];
        let oi = openai_body("m", &msgs, &[], 64, TokenCapField::MaxTokens).unwrap();
        let wire = oi["messages"].as_array().unwrap();
        assert_eq!(wire.len(), 3, "{wire:?}");
        assert!(wire.iter().all(|m| m["tool_call_id"] != "stray"));
        assert_eq!(wire[2]["tool_call_id"], "c9");
        assert_eq!(wire[2]["content"], "cancelled");
    }

    #[test]
    fn openai_com_gets_max_completion_tokens_and_other_servers_max_tokens() {
        assert_eq!(
            TokenCapField::for_base_url("https://api.openai.com/v1"),
            TokenCapField::MaxCompletionTokens
        );
        assert_eq!(
            TokenCapField::for_base_url("https://API.OPENAI.COM/v1"),
            TokenCapField::MaxCompletionTokens
        );
        for other in [
            "http://localhost:11434/v1",
            "https://openrouter.ai/api/v1",
            "https://api.groq.com/openai/v1",
            "https://api.openai.com.evil.example/v1",
            "not a url",
        ] {
            assert_eq!(
                TokenCapField::for_base_url(other),
                TokenCapField::MaxTokens,
                "{other}"
            );
        }
        let body = openai_body(
            "gpt-5",
            &history(),
            &[],
            512,
            TokenCapField::MaxCompletionTokens,
        )
        .unwrap();
        assert_eq!(body["max_completion_tokens"], 512);
        assert!(body.get("max_tokens").is_none());
        let body = openai_body("llama3", &history(), &[], 512, TokenCapField::MaxTokens).unwrap();
        assert_eq!(body["max_tokens"], 512);
        assert!(body.get("max_completion_tokens").is_none());
    }
}
