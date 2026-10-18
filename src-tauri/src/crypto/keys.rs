//! Key generation, fingerprinting, and serialization
//!
//! Generation, OpenSSH parsing/serialization, and fingerprinting are
//! delegated to the audited `ssh-key` crate (RustCrypto) rather than
//! hand-rolled wire-format encoding, so RSA/ECDSA/Ed25519 keys this app
//! produces are byte-correct and parseable by real `ssh-keygen`/OpenSSH.
//! PKCS#8 and PuTTY PPK export still need custom encoding since `ssh-key`
//! doesn't cover those; that logic lives here and in `crypto::putty`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::utils::{generate_random_vec, ssh_fingerprint_md5, ssh_fingerprint_sha256};
use base64ct::{Base64, Encoding};
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair},
    rand_core::OsRng,
    Algorithm, EcdsaCurve, LineEnding, PrivateKey,
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, zeroize::Zeroize,
)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Rsa,
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

impl KeyType {
    /// SSH wire-format algorithm name (as used in `ssh-rsa AAAA...` lines).
    pub fn algorithm_name(self) -> &'static str {
        match self {
            KeyType::Rsa => "ssh-rsa",
            KeyType::Ed25519 => "ssh-ed25519",
            KeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
            KeyType::EcdsaP384 => "ecdsa-sha2-nistp384",
            KeyType::EcdsaP521 => "ecdsa-sha2-nistp521",
        }
    }

    fn from_ssh_key_algorithm(alg: &Algorithm) -> anyhow::Result<Self> {
        match alg {
            Algorithm::Rsa { .. } => Ok(KeyType::Rsa),
            Algorithm::Ed25519 => Ok(KeyType::Ed25519),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => Ok(KeyType::EcdsaP256),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            } => Ok(KeyType::EcdsaP384),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            } => Ok(KeyType::EcdsaP521),
            other => anyhow::bail!("Unsupported key algorithm: {:?}", other),
        }
    }

    /// Stable string tag used for DB storage / IPC (distinct from the
    /// SSH wire algorithm name).
    pub fn db_tag(self) -> &'static str {
        match self {
            KeyType::Rsa => "rsa",
            KeyType::Ed25519 => "ed25519",
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::EcdsaP521 => "ecdsa-p521",
        }
    }

    /// Parse a stored tag or a key type sent over IPC. `ecdsa-nistpNNN` - the
    /// curve's SSH name, which the New Key dialog's curve options use - is
    /// accepted beside the stored `ecdsa-pNNN` (A2-02 / A7-02): without it
    /// every ECDSA key generated from the UI failed with "Unknown key type".
    pub fn from_db_tag(tag: &str) -> anyhow::Result<Self> {
        match tag {
            "rsa" => Ok(KeyType::Rsa),
            "ed25519" => Ok(KeyType::Ed25519),
            "ecdsa" | "ecdsa-p256" | "ecdsa-nistp256" => Ok(KeyType::EcdsaP256),
            "ecdsa-p384" | "ecdsa-nistp384" => Ok(KeyType::EcdsaP384),
            "ecdsa-p521" | "ecdsa-nistp521" => Ok(KeyType::EcdsaP521),
            other => anyhow::bail!("Unknown key type: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyFormat {
    OpenSsh,
    Pkcs8,
    Putty,
    Rfc4716,
}

/// A generated or imported key pair.
///
/// `private_key` holds the raw SSH wire-format private key
/// (`ssh_key::PrivateKey::to_bytes()`, always unencrypted at this layer —
/// encryption at rest is the vault's job) and `public_key` holds the raw
/// SSH wire-format public key blob (`ssh_key::PublicKey::to_bytes()`),
/// i.e. exactly the bytes that appear base64-encoded in an
/// `authorized_keys` line.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyData {
    pub key_type: KeyType,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub comment: String,
}

impl PrivateKeyData {
    pub fn new(
        key_type: KeyType,
        private_key: impl Into<Vec<u8>>,
        public_key: impl Into<Vec<u8>>,
        comment: String,
    ) -> Self {
        Self {
            key_type,
            private_key: private_key.into(),
            public_key: public_key.into(),
            comment,
        }
    }

    /// Reconstruct the `ssh_key::PrivateKey` this data represents.
    fn to_ssh_key(&self) -> anyhow::Result<PrivateKey> {
        PrivateKey::from_bytes(&self.private_key)
            .map_err(|e| anyhow::anyhow!("Invalid stored private key: {e}"))
    }
}

/// Smallest RSA modulus SSHSpan generates (also `ssh-key`'s own minimum).
pub const RSA_MIN_BITS: u32 = 2048;
/// Largest RSA modulus SSHSpan generates - the biggest size the New Key
/// dialog offers. The pure-Rust prime search for larger keys runs for many
/// minutes.
pub const RSA_MAX_BITS: u32 = 8192;
/// RSA modulus size when a request names none.
pub const RSA_DEFAULT_BITS: u32 = 3072;

/// The RSA modulus size for a generate request: absent means the default,
/// and anything outside 2048..=8192 is refused with the range in the message
/// (A7-12). It used to be clamped to 2048-16384 without a word, so 1024 quietly
/// became 2048 and 16384 - effectively a hang - went through.
pub fn rsa_key_bits(bits: Option<u32>) -> anyhow::Result<u32> {
    let bits = bits.unwrap_or(RSA_DEFAULT_BITS);
    if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
        anyhow::bail!(
            "RSA key size must be between {RSA_MIN_BITS} and {RSA_MAX_BITS} bits (got {bits})."
        );
    }
    Ok(bits)
}

/// A key comment that cannot break the one-line formats it is written into
/// (A7-45): every control character (newline, carriage return, tab, NUL, ...)
/// becomes a space, and surrounding whitespace is trimmed.
///
/// The OpenSSH private-key format and PPK carry the comment as a counted or
/// header string that nothing validates, so a crafted key file could hold
/// `x\nssh-ed25519 AAAA... attacker` and turn the `authorized_keys` line a
/// user copies, a deployed `.pub` file or a PPK header into several lines.
/// Applied when a key is generated or imported, and again by every exporter
/// for keys stored before this check existed.
pub fn sanitize_key_comment(comment: &str) -> String {
    comment
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// A stored `authorized_keys` line, made safe to hand out as ONE line - the
/// rule of [`sanitize_key_comment`]. The algorithm and the base64 never hold
/// control characters, so only a comment stored before that check changes.
pub fn sanitize_public_line(line: &str) -> String {
    sanitize_key_comment(line)
}

/// What `key_import` says about text that is neither an OpenSSH private key
/// nor a PuTTY .ppk (A7-03 / A5-39, ruling R9). Those are the only formats it
/// reads, so the message names what the text looks like and how to turn it
/// into one of them, instead of a bare "unsupported format".
pub fn unsupported_import_message(text: &str) -> String {
    const SUPPORTED: &str = "SSHSpan imports OpenSSH private keys (-----BEGIN OPENSSH PRIVATE KEY-----) and PuTTY .ppk files only.";
    // `-o`: before OpenSSH 7.8, `-p` alone rewrote the key in its old PEM
    // format; later versions accept `-o` and ignore it.
    const CONVERT: &str = "Convert a copy with: ssh-keygen -p -o -f <copy-of-the-key-file> (it rewrites that file in OpenSSH format and asks for a passphrase to keep or set), then import the result.";
    const PUTTYGEN: &str = " Or load it in PuTTYgen and use \"Save private key\" to get a .ppk.";
    // (header, what it is, whether PuTTYgen can load it)
    const PRIVATE_PEM: [(&str, &str, bool); 4] = [
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "a PKCS#1 RSA private key",
            true,
        ),
        (
            "-----BEGIN EC PRIVATE KEY-----",
            "a SEC1 EC private key",
            true,
        ),
        (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "an encrypted PKCS#8 private key",
            false,
        ),
        ("-----BEGIN PRIVATE KEY-----", "a PKCS#8 private key", false),
    ];
    for (header, what, puttygen) in PRIVATE_PEM {
        if text.contains(header) {
            return format!(
                "Unsupported key format: this is {what} ({header}). {SUPPORTED} {CONVERT}{}",
                if puttygen { PUTTYGEN } else { "" }
            );
        }
    }
    let public = if text.contains("-----BEGIN PUBLIC KEY-----") {
        Some("an SPKI public key (-----BEGIN PUBLIC KEY-----)")
    } else if text.contains("---- BEGIN SSH2 PUBLIC KEY ----") {
        Some("an RFC 4716 public key (---- BEGIN SSH2 PUBLIC KEY ----)")
    } else if looks_like_openssh_public_line(text) {
        Some("an OpenSSH public key line (authorized_keys / .pub)")
    } else {
        None
    };
    match public {
        Some(what) => format!(
            "Unsupported key format: this is {what}, which holds only the public half. A vault key needs the private key - import the matching OpenSSH private key or PuTTY .ppk file instead."
        ),
        None => "Unsupported key format. Expected an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) or a PuTTY .ppk file.".to_string(),
    }
}

/// An `authorized_keys` / `.pub` line: an SSH algorithm name followed by base64
/// that starts `AAAA` (the length prefix of the algorithm name). Options before
/// the key (`from="..." ssh-ed25519 AAAA...`) are skipped over.
fn looks_like_openssh_public_line(text: &str) -> bool {
    text.lines().any(|line| {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        tokens.windows(2).any(|pair| {
            let algorithm = pair[0];
            (algorithm.starts_with("ssh-")
                || algorithm.starts_with("ecdsa-sha2-")
                || algorithm.starts_with("sk-"))
                && pair[1].starts_with("AAAA")
        })
    })
}

/// Generate a new key pair of the given type.
///
/// `bits` only applies to RSA: 2048 to 8192, 3072 when absent (see
/// [`rsa_key_bits`]). The comment is cleaned with [`sanitize_key_comment`].
pub fn generate_key_pair(
    key_type: KeyType,
    bits: Option<u32>,
    comment: String,
) -> anyhow::Result<PrivateKeyData> {
    let mut rng = OsRng;
    let comment = sanitize_key_comment(&comment);

    let keypair_data: KeypairData = match key_type {
        KeyType::Rsa => {
            let bits = rsa_key_bits(bits)? as usize;
            KeypairData::Rsa(RsaKeypair::random(&mut rng, bits).map_err(|e| anyhow::anyhow!(e))?)
        }
        KeyType::Ed25519 => KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)),
        KeyType::EcdsaP256 => KeypairData::Ecdsa(
            EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256).map_err(|e| anyhow::anyhow!(e))?,
        ),
        KeyType::EcdsaP384 => KeypairData::Ecdsa(
            EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP384).map_err(|e| anyhow::anyhow!(e))?,
        ),
        KeyType::EcdsaP521 => KeypairData::Ecdsa(
            EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP521).map_err(|e| anyhow::anyhow!(e))?,
        ),
    };

    let private_key =
        PrivateKey::new(keypair_data, comment.clone()).map_err(|e| anyhow::anyhow!(e))?;
    let private_bytes = private_key
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();
    let public_bytes = private_key
        .public_key()
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();

    Ok(PrivateKeyData::new(
        key_type,
        private_bytes,
        public_bytes,
        comment,
    ))
}

/// Import a key from an OpenSSH-formatted PEM private key (`-----BEGIN
/// OPENSSH PRIVATE KEY-----`). Handles encrypted and plaintext keys.
pub fn import_openssh_private(
    pem: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<PrivateKeyData> {
    let mut key = PrivateKey::from_openssh(pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse OpenSSH key: {e}"))?;
    if key.is_encrypted() {
        let pass = passphrase
            .ok_or_else(|| anyhow::anyhow!("This key is encrypted; a passphrase is required."))?;
        key = key
            .decrypt(pass)
            .map_err(|_| anyhow::anyhow!("Incorrect passphrase, or the key file is corrupted."))?;
    }

    let key_type = KeyType::from_ssh_key_algorithm(&key.algorithm())?;
    // The comment comes from the file unchecked (A7-45); the cleaned one is
    // also what the stored private key carries.
    let comment = sanitize_key_comment(key.comment());
    key.set_comment(comment.clone());
    let private_bytes = key.to_bytes().map_err(|e| anyhow::anyhow!(e))?.to_vec();
    let public_bytes = key
        .public_key()
        .to_bytes()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();

    Ok(PrivateKeyData::new(
        key_type,
        private_bytes,
        public_bytes,
        comment,
    ))
}

/// Compute SSH fingerprint (SHA-256) - matches `ssh-keygen -lf` exactly.
pub fn compute_fingerprint_sha256(public_key: &[u8]) -> String {
    ssh_fingerprint_sha256(public_key)
}

/// Compute SSH fingerprint (MD5) - for legacy compatibility
pub fn compute_fingerprint_md5(public_key: &[u8]) -> String {
    ssh_fingerprint_md5(public_key)
}

/// Maximum length of a key name. Names are also deployed as `Host` aliases
/// in the user's OpenSSH config; a short cap keeps the config readable and
/// the DB index small.
pub const MAX_KEY_NAME_LEN: usize = 64;

/// Validate a vault key name.
///
/// Constraints (why):
/// - Deployed keys are aliased as a `Host <pattern>` token in the user's
///   OpenSSH config, so the name must be a single whitespace-free token —
///   whitespace would end the pattern and let the next token be re-parsed
///   as a second pattern (or, with a newline, as a fresh directive line).
/// - No control characters (`\n`, `\r`, `\t`, NUL, …): they cannot appear in
///   a config value without enabling line/directive injection.
/// - Printable characters only, non-empty after trimming, no leading or
///   trailing whitespace, and at most [`MAX_KEY_NAME_LEN`] chars.
pub fn validate_key_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Key name cannot be empty or only whitespace.".into());
    }
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err(format!(
            "Key name must be at most {MAX_KEY_NAME_LEN} characters."
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("Key name cannot contain control characters.".into());
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(
            "Key name cannot contain whitespace — it is used as a single Host alias in the SSH config."
                .into(),
        );
    }
    if name.chars().any(|c| !is_printable_char(c)) {
        return Err("Key name must contain only printable characters.".into());
    }
    Ok(())
}

/// A printable char: not a control, format, surrogate, private-use, or
/// unassigned code point. Restricting to Graphic (letters, marks, numbers,
/// punctuation, symbols) + ASCII space (excluded separately by the
/// whitespace rule above) keeps names renderable in every UI surface.
fn is_printable_char(c: char) -> bool {
    if c.is_control() {
        return false;
    }
    let cp = c as u32;
    // Surrogates can't appear in a Rust char; D800–DFFF listed for clarity.
    // Unassigned/private-use planes and the Cn/Co/Co-format ranges are
    // excluded conservatively: anything outside the graphic planes plus a
    // few well-known printable blocks is rejected.
    matches!(c, '\u{20}'..='\u{7E}')            // ASCII graphic
        || matches!(c, '\u{A0}'..='\u{10FFFF}' if !is_non_printable_code_point(cp))
}

/// Code-point ranges that hold no graphic characters (Cf format chars,
/// private-use areas, noncharacters). Conservative: anything in these
/// ranges is treated as non-printable.
fn is_non_printable_code_point(cp: u32) -> bool {
    matches!(cp,
        0xAD                                  // SOFT HYPHEN (Cf)
        | 0x600..=0x605                       // Arabic number signs (Cf)
        | 0x61C                               // ALM (Cf)
        | 0x6DD                               // Arabic end of ayah (Cf)
        | 0x70F                               // Syriac abbreviation mark (Cf)
        | 0x8E2                               // Arabic wakha (Cf)
        | 0x180E                              // Mongolian vowel separator (Cf)
        | 0x200B..=0x200F                     // ZWSP..RLM (Cf) — ZWSP is whitespace-adjacent
        | 0x202A..=0x202E                     // bidi controls (Cf)
        | 0x2060..=0x2064                     // word joiner etc. (Cf)
        | 0x2066..=0x206F                     // bidi isolates (Cf)
        | 0xFEFF                              // BOM (Cf)
        | 0xFFF9..=0xFFFB                     // interlinear annotation (Cf)
        | 0xE000..=0xF8FF                     // private use area
        | 0xF0000..=0xFFFFD                   // supplementary PUA-A
        | 0x100000..=0x10FFFD                 // supplementary PUA-B
        | 0xFDD0..=0xFDEF                     // noncharacters
    ) || (cp & 0xFFFE) == 0xFFFE // noncharacter endings
}

/// Sanitize an arbitrary name into one that passes [`validate_key_name`]:
/// each invalid character (whitespace, control, non-printable) is replaced
/// with `-`. If the result is empty or overlong, falls back to a truncated /
/// placeholder form so the mapping is total (used by import paths that must
/// not reject the whole item, and at deploy time for legacy stored names).
pub fn sanitize_key_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_control() || c.is_whitespace() || !is_printable_char(c) {
                '-'
            } else {
                c
            }
        })
        .collect();
    let chars: Vec<char> = out.chars().collect();
    if chars.len() > MAX_KEY_NAME_LEN {
        out = chars[..MAX_KEY_NAME_LEN].iter().collect();
    }
    if out.trim_matches('-').is_empty() {
        // Everything mapped to '-' (empty or all-invalid input).
        out = "key".to_string();
    }
    out
}

/// Export private key in various formats
pub fn export_private_key(
    key_data: &PrivateKeyData,
    format: KeyFormat,
    passphrase: Option<&str>,
) -> anyhow::Result<String> {
    match format {
        KeyFormat::OpenSsh => export_openssh_private(key_data, passphrase),
        KeyFormat::Pkcs8 => export_pkcs8_private(key_data, passphrase),
        KeyFormat::Putty => export_putty_private(key_data, passphrase),
        KeyFormat::Rfc4716 => export_rfc4716_private(key_data, passphrase),
    }
}

/// Export public key in various formats
pub fn export_public_key(key_data: &PrivateKeyData, format: KeyFormat) -> anyhow::Result<String> {
    match format {
        KeyFormat::OpenSsh => export_openssh_public(key_data),
        KeyFormat::Pkcs8 => export_pkcs8_public(key_data),
        KeyFormat::Rfc4716 => export_rfc4716_public(key_data),
        KeyFormat::Putty => export_putty_public(key_data),
    }
}

/// Export as OpenSSH format, optionally encrypted with a passphrase
/// (aes256-ctr + bcrypt KDF, matching modern `ssh-keygen` defaults). The
/// embedded comment is the key's (cleaned) comment - a key stored before
/// comments were checked still carries the raw one in its private bytes.
fn export_openssh_private(
    key_data: &PrivateKeyData,
    passphrase: Option<&str>,
) -> anyhow::Result<String> {
    let mut key = key_data.to_ssh_key()?;
    key.set_comment(sanitize_key_comment(&key_data.comment));
    let key = match passphrase {
        Some(pass) if !pass.is_empty() => {
            let mut rng = OsRng;
            key.encrypt(&mut rng, pass)
                .map_err(|e| anyhow::anyhow!(e))?
        }
        _ => key,
    };
    Ok(key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!(e))?
        .to_string())
}

/// The `authorized_keys` line. The comment is re-checked here (A7-45): keys
/// stored before comments were cleaned on import may still hold a newline.
fn export_openssh_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let b64 = Base64::encode_string(&key_data.public_key);
    Ok(format!(
        "{} {} {}",
        key_data.key_type.algorithm_name(),
        b64,
        sanitize_key_comment(&key_data.comment)
    )
    .trim_end()
    .to_string())
}

/// Export as PKCS#8 format (SPKI public / PrivateKeyInfo private PEM)
fn export_pkcs8_private(
    key_data: &PrivateKeyData,
    passphrase: Option<&str>,
) -> anyhow::Result<String> {
    let der = crate::crypto::pkcs8::private_key_to_pkcs8_der(key_data)?;
    if let Some(pass) = passphrase.filter(|p| !p.is_empty()) {
        encrypt_pkcs8_with_passphrase(&der, pass)
    } else {
        pem_wrap("PRIVATE KEY", &der)
    }
}

fn export_pkcs8_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let der = crate::crypto::pkcs8::public_key_to_spki_der(key_data)?;
    pem_wrap("PUBLIC KEY", &der)
}

fn pem_wrap(label: &str, der: &[u8]) -> anyhow::Result<String> {
    let b64 = Base64::encode_string(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    Ok(out)
}

/// Export as PuTTY PPK format
fn export_putty_private(
    key_data: &PrivateKeyData,
    passphrase: Option<&str>,
) -> anyhow::Result<String> {
    crate::crypto::putty::export_ppk(key_data, passphrase)
}

fn export_putty_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    export_rfc4716_public(key_data)
}

/// Export as RFC 4716 format
fn export_rfc4716_private(
    _key_data: &PrivateKeyData,
    _passphrase: Option<&str>,
) -> anyhow::Result<String> {
    anyhow::bail!("RFC 4716 private key export not supported (not part of the RFC 4716 spec; OpenSSH doesn't support it either).");
}

fn export_rfc4716_public(key_data: &PrivateKeyData) -> anyhow::Result<String> {
    let openssh_pub = export_openssh_public(key_data)?;
    let parts: Vec<&str> = openssh_pub.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid OpenSSH public key");
    }
    let base64_key = parts[1];
    // The whole (cleaned) comment: taking the third whitespace-separated
    // word of the OpenSSH line kept only the comment's first word.
    let comment = sanitize_key_comment(&key_data.comment);

    let mut output = String::new();
    output.push_str("---- BEGIN SSH2 PUBLIC KEY ----\n");
    output.push_str(&format!("Comment: \"{}\"\n", comment));
    // RFC 4716 3.3: no line longer than 72 bytes. 70 per line, as
    // `ssh-keygen -e` writes it.
    for chunk in base64_key.as_bytes().chunks(70) {
        output.push_str(&String::from_utf8_lossy(chunk));
        output.push('\n');
    }
    output.push_str("---- END SSH2 PUBLIC KEY ----\n");
    Ok(output)
}

/// Encrypt PKCS#8 DER private key with a passphrase as a real RFC 8018
/// PBES2 `EncryptedPrivateKeyInfo` (RFC 5958 §3), DER-encoded and PEM-wrapped.
///
/// Scheme: PBES2 { PBKDF2-HMAC-SHA256 (16-byte random salt, 100_000
/// iterations) → 32-byte key, AES-256-CBC with a fresh random IV }. Both the
/// salt and the IV are serialized inside the DER so the output is decryptable
/// by external tools (`openssl pkcs8`, PuTTYgen) and never uses the legacy
/// OpenSSL `Proc-Type`/`DEK-Info` PEM encryption headers.
fn encrypt_pkcs8_with_passphrase(pkcs8_der: &[u8], passphrase: &str) -> anyhow::Result<String> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use pbkdf2::pbkdf2_hmac_array;
    use sha2::Sha256;

    const PBKDF2_ITERATIONS: u32 = 100_000;
    let salt = generate_random_vec(16);
    let iv = generate_random_vec(16);

    // Derive only the AES key from the passphrase (never the IV).
    let key: [u8; 32] =
        pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS);

    // AES-256-CBC encrypt with PKCS#7 padding.
    let mut buf = pkcs8_der.to_vec();
    let pt_len = buf.len();
    buf.resize(pt_len + 16, 0);
    let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)
        .expect("AES-256 key is 32 bytes and IV is 16 bytes")
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!(e))?
        .to_vec();

    let der = crate::crypto::pkcs8::encrypt_private_key_info_pbes2_der(
        &salt,
        PBKDF2_ITERATIONS,
        &iv,
        &ct,
    )?;
    pem_wrap("ENCRYPTED PRIVATE KEY", &der)
}

/// One key of every supported type, generated once per test run and shared by
/// the format round-trip tests here and in `putty`/`pkcs8`: RSA generation is
/// slow in a debug build. The comments carry a space on purpose.
#[cfg(test)]
pub(crate) fn sample_keys() -> &'static [PrivateKeyData] {
    static KEYS: std::sync::OnceLock<Vec<PrivateKeyData>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        [
            KeyType::Rsa,
            KeyType::Ed25519,
            KeyType::EcdsaP256,
            KeyType::EcdsaP384,
            KeyType::EcdsaP521,
        ]
        .into_iter()
        .map(|kt| {
            generate_key_pair(kt, Some(2048), format!("sample {}", kt.db_tag()))
                .expect("generate a sample key")
        })
        .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── A2-02 / A7-02 / A5-37: the New Key dialog's key types parse ──

    #[test]
    fn ecdsa_curve_tags_accept_the_ssh_spellings() {
        for (tag, want) in [
            ("ecdsa-nistp256", KeyType::EcdsaP256),
            ("ecdsa-nistp384", KeyType::EcdsaP384),
            ("ecdsa-nistp521", KeyType::EcdsaP521),
            ("ecdsa-p256", KeyType::EcdsaP256),
            ("ecdsa-p384", KeyType::EcdsaP384),
            ("ecdsa-p521", KeyType::EcdsaP521),
        ] {
            assert_eq!(KeyType::from_db_tag(tag).ok(), Some(want), "{tag}");
        }
        assert!(KeyType::from_db_tag("ecdsa-nistp999").is_err());
    }

    /// The `<option value>`s of one `<select id="...">` in index.html.
    fn select_options(html: &str, id: &str) -> Vec<String> {
        let start = html
            .find(&format!("<select id=\"{id}\""))
            .unwrap_or_else(|| panic!("index.html has no <select id=\"{id}\">"));
        let body = &html[start..];
        let body = &body[..body.find("</select>").expect("unterminated <select>")];
        body.split("<option value=\"")
            .skip(1)
            .map(|rest| rest[..rest.find('"').expect("unterminated value")].to_string())
            .collect()
    }

    /// Contract test against the LIVE dialog: every key type, curve and RSA
    /// size the New Key dialog offers must be accepted by the backend, built
    /// the way `submitKeyModal` builds it (`ecdsa-` + the curve option).
    #[test]
    fn every_key_type_the_new_key_dialog_offers_is_accepted() {
        let html = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/renderer/index.html"),
        )
        .expect("read src/renderer/index.html");
        let types = select_options(&html, "genType");
        let curves = select_options(&html, "genCurve");
        let sizes = select_options(&html, "genBits");
        assert!(!types.is_empty() && !curves.is_empty() && !sizes.is_empty());
        let mut refused = Vec::new();
        for t in &types {
            let tags: Vec<String> = if t == "ecdsa" {
                curves.iter().map(|c| format!("ecdsa-{c}")).collect()
            } else {
                vec![t.clone()]
            };
            for tag in tags {
                if let Err(e) = KeyType::from_db_tag(&tag) {
                    refused.push(format!("{tag}: {e}"));
                }
            }
        }
        for size in &sizes {
            let bits: u32 = size.parse().expect("numeric RSA size");
            if !(2048..=8192).contains(&bits) {
                refused.push(format!("RSA {bits} bits is outside 2048..=8192"));
            }
        }
        assert!(refused.is_empty(), "refused: {refused:?}");
    }

    // ── A7-12: RSA sizes outside 2048..=8192 are refused, not clamped ──

    #[test]
    fn rsa_generation_refuses_sizes_below_2048_bits() {
        let err = generate_key_pair(KeyType::Rsa, Some(1024), String::new())
            .err()
            .expect("1024-bit RSA must be refused");
        assert!(err.to_string().contains("2048"), "{err}");
    }

    #[test]
    fn rsa_key_bits_accepts_2048_to_8192_and_names_the_range_otherwise() {
        assert_eq!(rsa_key_bits(None).unwrap(), 3072);
        for ok in [2048, 3072, 4096, 8192] {
            assert_eq!(rsa_key_bits(Some(ok)).unwrap(), ok);
        }
        for bad in [0, 1024, 2047, 8193, 16384] {
            assert_eq!(
                rsa_key_bits(Some(bad)).unwrap_err().to_string(),
                format!("RSA key size must be between 2048 and 8192 bits (got {bad}).")
            );
        }
    }

    // ── A7-03 / A5-39 / R9: the import error names what was pasted ──

    #[test]
    fn unsupported_import_message_names_each_detected_format() {
        let private_pem = |label: &str| {
            format!("-----BEGIN {label}-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END {label}-----\n")
        };
        let cases = [
            (private_pem("RSA PRIVATE KEY"), "a PKCS#1 RSA private key"),
            (private_pem("EC PRIVATE KEY"), "a SEC1 EC private key"),
            (private_pem("PRIVATE KEY"), "a PKCS#8 private key"),
            (
                private_pem("ENCRYPTED PRIVATE KEY"),
                "an encrypted PKCS#8 private key",
            ),
        ];
        for (text, what) in &cases {
            let msg = unsupported_import_message(text);
            assert!(msg.contains(what), "{what}: {msg}");
            // `-o`: before OpenSSH 7.8, `-p` alone kept the PEM format.
            assert!(msg.contains("ssh-keygen -p -o -f"), "{what}: {msg}");
            assert!(msg.contains("OpenSSH") && msg.contains(".ppk"), "{msg}");
        }
        // PuTTYgen reads PKCS#1 and SEC1 PEM files.
        assert!(unsupported_import_message(&cases[0].0).contains("PuTTYgen"));
        assert!(unsupported_import_message(&cases[1].0).contains("PuTTYgen"));

        for (text, what) in [
            (
                "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----".to_string(),
                "an SPKI public key",
            ),
            (
                "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"x\"\nAAAAC3Nza\n---- END SSH2 PUBLIC KEY ----".to_string(),
                "an RFC 4716 public key",
            ),
            (
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample me@host".to_string(),
                "an OpenSSH public key line",
            ),
            (
                "from=\"10.0.0.1\" ecdsa-sha2-nistp256 AAAAE2VjZHNh me".to_string(),
                "an OpenSSH public key line",
            ),
        ] {
            let msg = unsupported_import_message(&text);
            assert!(msg.contains(what), "{what}: {msg}");
            assert!(msg.contains("private"), "{msg}");
            assert!(!msg.contains("ssh-keygen -p"), "no conversion for a public key: {msg}");
        }

        assert_eq!(
            unsupported_import_message("hello"),
            "Unsupported key format. Expected an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) or a PuTTY .ppk file."
        );
    }

    // ── A7-45: a comment can never put a second line into a key file ──

    const INJECTED_COMMENT: &str =
        "me@host\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKER attacker\r\n";

    #[test]
    fn generated_key_comments_lose_their_control_characters() {
        let key = generate_key_pair(KeyType::Ed25519, None, INJECTED_COMMENT.into()).unwrap();
        assert!(
            !key.comment.chars().any(char::is_control),
            "{:?}",
            key.comment
        );
        let line = export_public_key(&key, KeyFormat::OpenSsh).unwrap();
        assert_eq!(line.lines().count(), 1, "{line:?}");
    }

    #[test]
    fn imported_openssh_comments_lose_their_control_characters() {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        key.set_comment(INJECTED_COMMENT);
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let imported = import_openssh_private(&pem, None).unwrap();
        assert!(
            !imported.comment.chars().any(char::is_control),
            "{:?}",
            imported.comment
        );
        // The comment inside the stored private key is the cleaned one too.
        let stored = PrivateKey::from_bytes(&imported.private_key).unwrap();
        assert_eq!(stored.comment(), imported.comment);
        let line = export_public_key(&imported, KeyFormat::OpenSsh).unwrap();
        assert_eq!(line.lines().count(), 1, "{line:?}");
    }

    /// Keys stored before the import-time check keep their raw comment; every
    /// exporter re-checks, so the line a user copies is still one line.
    #[test]
    fn exporters_recheck_comments_stored_before_the_fix() {
        // Exactly what an import stored before the check: the raw comment in
        // the comment column AND inside the private key bytes.
        let mut raw = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        raw.set_comment(INJECTED_COMMENT);
        let key = PrivateKeyData::new(
            KeyType::Ed25519,
            raw.to_bytes().unwrap().to_vec(),
            raw.public_key().to_bytes().unwrap(),
            INJECTED_COMMENT.to_string(),
        );
        let public = export_public_key(&key, KeyFormat::OpenSsh).unwrap();
        assert_eq!(public.lines().count(), 1, "{public:?}");
        let ppk = export_private_key(&key, KeyFormat::Putty, None).unwrap();
        let comment_lines: Vec<&str> = ppk
            .lines()
            .filter(|l| l.contains("attacker") || l.starts_with("Comment:"))
            .collect();
        assert_eq!(comment_lines.len(), 1, "{ppk}");
        assert!(comment_lines[0].starts_with("Comment: "));
        let openssh = export_private_key(&key, KeyFormat::OpenSsh, None).unwrap();
        let reread = PrivateKey::from_openssh(&openssh).unwrap();
        assert!(!reread.comment().chars().any(char::is_control));
    }

    /// A7-53 (comment handling): the RFC 4716 header carries the whole
    /// comment, not its first word.
    /// RFC 4716 3.3: no line longer than 72 bytes - the base64 body wraps.
    #[test]
    fn rfc4716_public_export_wraps_the_body() {
        let rsa = &sample_keys()[0];
        let text = export_public_key(rsa, KeyFormat::Rfc4716).unwrap();
        let body: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with("----") && !l.starts_with("Comment:"))
            .collect();
        assert!(body.len() > 1, "{text}");
        assert!(body.iter().all(|l| l.len() <= 72), "{text}");
        let joined: String = body.concat();
        assert_eq!(Base64::decode_vec(&joined).unwrap(), rsa.public_key);
    }

    #[test]
    fn rfc4716_public_export_keeps_the_whole_comment() {
        let key = generate_key_pair(KeyType::Ed25519, None, "deploy key\tfor web".into()).unwrap();
        let text = export_public_key(&key, KeyFormat::Rfc4716).unwrap();
        assert!(text.contains("Comment: \"deploy key for web\"\n"), "{text}");
    }

    #[test]
    fn validate_key_name_accepts_single_token_names() {
        assert!(validate_key_name("deploy-key-1").is_ok());
        assert!(validate_key_name("github.com").is_ok());
        assert!(validate_key_name("web*prod").is_ok());
        assert!(validate_key_name(&"a".repeat(MAX_KEY_NAME_LEN)).is_ok());
    }

    #[test]
    fn validate_key_name_rejects_config_injection_payloads() {
        // Each payload would break out of a single `Host <token>` line if it
        // reached ~/.ssh/config unvalidated.
        for payload in [
            "x\nHost *\n ProxyCommand evil",
            "x\rHost *",
            "x\n",
            "x\r",
            "x\tHost *",
            "x Host *", // space ends the pattern
            " Host",    // leading whitespace
            "Host ",    // trailing whitespace
            "",         // empty
            "   ",      // whitespace-only
            "x\u{0}y",  // NUL
            "x\u{7}y",  // bell
        ] {
            assert!(
                validate_key_name(payload).is_err(),
                "payload {payload:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_key_name_rejects_overlong_names() {
        let too_long = "a".repeat(MAX_KEY_NAME_LEN + 1);
        assert!(validate_key_name(&too_long).is_err());
    }

    #[test]
    fn sanitize_key_name_maps_invalid_runs_to_dashes() {
        assert_eq!(sanitize_key_name("my deploy key"), "my-deploy-key");
        assert_eq!(
            sanitize_key_name("x\nHost *\n ProxyCommand evil"),
            "x-Host-*--ProxyCommand-evil"
        );
        assert_eq!(sanitize_key_name("x\r\ny"), "x--y");
    }

    #[test]
    fn sanitize_key_name_output_always_validates() {
        for input in [
            "",
            " ",
            "\n",
            "\n\n\n",
            "\t\r",
            "x\nHost *",
            "  leading",
            "trailing  ",
        ] {
            let out = sanitize_key_name(input);
            assert!(
                validate_key_name(&out).is_ok(),
                "sanitize({input:?}) = {out:?} must pass validation"
            );
        }
    }

    #[test]
    fn sanitize_key_name_truncates_to_cap_and_passes_through_valid() {
        let long = "a b\nc".repeat(40);
        let out = sanitize_key_name(&long);
        assert!(out.chars().count() <= MAX_KEY_NAME_LEN);
        assert!(validate_key_name(&out).is_ok());

        assert_eq!(sanitize_key_name("already-fine"), "already-fine");
    }

    /// Minimal DER TLV reader for the round-trip test: reads the TLV starting
    /// at `pos` and returns (tag, content range, position of the next TLV).
    /// Supports short- and long-form lengths (the ciphertext OCTET STRING is
    /// large enough to need long-form).
    fn read_tlv(buf: &[u8], pos: usize) -> (u8, std::ops::Range<usize>, usize) {
        assert!(pos + 2 <= buf.len(), "truncated TLV header");
        let tag = buf[pos];
        let first = buf[pos + 1];
        let (header_len, len) = if first & 0x80 == 0 {
            (2usize, first as usize)
        } else {
            let num_bytes = (first & 0x7f) as usize;
            assert!(num_bytes > 0 && num_bytes <= 8, "unsupported length form");
            assert!(
                pos + 2 + num_bytes <= buf.len(),
                "truncated long-form length"
            );
            let len = buf[pos + 2..pos + 2 + num_bytes]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize);
            (2 + num_bytes, len)
        };
        let next = pos + header_len + len;
        assert!(next <= buf.len(), "TLV content overruns buffer");
        (tag, pos + header_len..next, next)
    }

    /// Test-only counterpart of `encrypt_pkcs8_with_passphrase`: parse a PBES2
    /// EncryptedPrivateKeyInfo, re-derive the key, and AES-256-CBC decrypt.
    fn decrypt_pbes2_pem(pem: &str, passphrase: &str) -> anyhow::Result<Vec<u8>> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        let body = pem
            .strip_prefix("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
            .and_then(|b| b.strip_suffix("-----END ENCRYPTED PRIVATE KEY-----\n"))
            .ok_or_else(|| anyhow::anyhow!("missing PEM header/footer"))?;
        let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let der = Base64::decode_vec(&body).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))?;

        // EncryptedPrivateKeyInfo ::= SEQUENCE { algId, encryptedData }
        let (tag, epki, _) = read_tlv(&der, 0);
        assert_eq!(tag, 0x30, "outer SEQUENCE");
        let der = &der[epki];
        let mut pos = 0;

        // encryptionAlgorithm AlgorithmIdentifier (PBES2)
        let (tag, alg_content, next) = read_tlv(der, pos);
        assert_eq!(tag, 0x30, "encryptionAlgorithm SEQUENCE");
        pos = next;
        let alg = &der[alg_content];

        // AlgorithmIdentifier ::= SEQUENCE { OID, PBES2-params }
        let (tag, oid_range, next) = read_tlv(alg, 0);
        assert_eq!(tag, 0x06, "id-PBES2 OID");
        assert_eq!(
            &alg[oid_range],
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D]
        );
        // PBES2-params ::= SEQUENCE { kdf AlgId, encScheme AlgId }
        let (tag, pbes2_range, _) = read_tlv(alg, next);
        assert_eq!(tag, 0x30, "PBES2-params SEQUENCE");
        let pbes2 = &alg[pbes2_range];

        // keyDerivationFunc
        let (tag, kdf_range, next) = read_tlv(pbes2, 0);
        assert_eq!(tag, 0x30, "keyDerivationFunc SEQUENCE");
        let kdf = &pbes2[kdf_range];
        // encryptionScheme
        let (tag, enc_range, _) = read_tlv(pbes2, next);
        assert_eq!(tag, 0x30, "encryptionScheme SEQUENCE");
        let enc = &pbes2[enc_range];

        // kdf: OID id-PBKDF2 + PBKDF2-params SEQUENCE
        let (tag, _, next) = read_tlv(kdf, 0);
        assert_eq!(tag, 0x06, "id-PBKDF2 OID");
        let (tag, params_range, _) = read_tlv(kdf, next);
        assert_eq!(tag, 0x30, "PBKDF2-params SEQUENCE");
        let params = &kdf[params_range];
        // PBKDF2-params: salt OCTET STRING, iterationCount INTEGER, prf AlgId
        let (tag, salt_range, next) = read_tlv(params, 0);
        assert_eq!(tag, 0x04, "salt OCTET STRING");
        let salt = params[salt_range].to_vec();
        let (tag, iter_range, next) = read_tlv(params, next);
        assert_eq!(tag, 0x02, "iterationCount INTEGER");
        let iterations = params[iter_range]
            .iter()
            .fold(0u32, |acc, b| (acc << 8) | *b as u32);
        let (tag, _, _) = read_tlv(params, next);
        assert_eq!(tag, 0x30, "prf AlgorithmIdentifier");

        // enc scheme: OID id-aes256-CBC + IV OCTET STRING
        let (tag, _, next) = read_tlv(enc, 0);
        assert_eq!(tag, 0x06, "id-aes256-CBC OID");
        let (tag, iv_range, _) = read_tlv(enc, next);
        assert_eq!(tag, 0x04, "IV OCTET STRING");
        let iv = enc[iv_range].to_vec();

        // encryptedData OCTET STRING (last child of the outer sequence)
        let (tag, ct_range, end) = read_tlv(der, pos);
        assert_eq!(tag, 0x04, "encryptedData OCTET STRING");
        assert_eq!(end, der.len(), "trailing garbage after encryptedData");
        let ciphertext = der[ct_range].to_vec();

        let key: [u8; 32] =
            pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), &salt, iterations);
        let mut buf = ciphertext;
        let pt = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv)
            .map_err(|e| anyhow::anyhow!(e))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(pt.to_vec())
    }

    #[test]
    fn pbes2_export_round_trip() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0xAB, 0xCD]; // arbitrary DER-ish blob
        let pem =
            encrypt_pkcs8_with_passphrase(&der, "correct horse battery staple").expect("encrypt");
        let recovered =
            decrypt_pbes2_pem(&pem, "correct horse battery staple").expect("decrypt round trip");
        assert_eq!(recovered, der);
    }

    #[test]
    fn pbes2_export_wrong_passphrase_fails() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x00, 0xAB, 0xCD];
        let pem = encrypt_pkcs8_with_passphrase(&der, "right").expect("encrypt");
        // The decrypt itself may succeed: AES-CBC with PKCS#7 padding has no
        // integrity check, and a wrong key decrypts to random bytes whose
        // padding is valid about 0.4% of the time (1/256 + 1/256^2 + ...).
        // What must hold is that the key bytes never come back.
        assert!(
            decrypt_pbes2_pem(&pem, "wrong").map_or(true, |pt| pt != der),
            "a wrong passphrase must not recover the key"
        );
    }

    #[test]
    fn pbes2_export_pem_shape() {
        let pem = encrypt_pkcs8_with_passphrase(&[0x01, 0x02, 0x03], "pass").expect("encrypt");
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END ENCRYPTED PRIVATE KEY-----\n"));
        assert!(!pem.contains("Proc-Type"));
        assert!(!pem.contains("DEK-Info"));
    }

    #[test]
    fn pbes2_export_randomized() {
        let der = vec![0x42u8; 64];
        let a = encrypt_pkcs8_with_passphrase(&der, "same pass").expect("encrypt");
        let b = encrypt_pkcs8_with_passphrase(&der, "same pass").expect("encrypt");
        assert_ne!(a, b, "random salt+IV must yield different ciphertexts");
    }

    #[test]
    fn pbes2_der_reparseable_by_der_crate() {
        use der::asn1::{ObjectIdentifier, OctetStringRef};
        use der::{Reader, SliceReader};

        let salt = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let ct = [0xAAu8; 32];
        let der_bytes =
            crate::crypto::pkcs8::encrypt_private_key_info_pbes2_der(&salt, 100_000, &iv, &ct)
                .expect("build der");

        // EncryptedPrivateKeyInfo ::= SEQUENCE { algId, encryptedData }
        let mut outer = SliceReader::new(&der_bytes).expect("slice reader");
        let (alg_bytes, data) = outer
            .sequence(|r| {
                let alg = r.tlv_bytes().expect("algId TLV").to_vec();
                let data: OctetStringRef = r.decode().expect("encryptedData");
                Ok((alg, data))
            })
            .expect("parse EncryptedPrivateKeyInfo");
        assert_eq!(data.as_bytes(), &ct);

        // AlgorithmIdentifier ::= SEQUENCE { OID id-PBES2, PBES2-params }
        let mut alg = SliceReader::new(&alg_bytes).expect("slice reader");
        let (pbes2_oid, pbes2_bytes) = alg
            .sequence(|r| {
                let oid: ObjectIdentifier = r.decode().expect("OID");
                let params = r.tlv_bytes().expect("PBES2-params TLV").to_vec();
                Ok((oid, params))
            })
            .expect("parse encryptionAlgorithm");
        assert_eq!(pbes2_oid.to_string(), "1.2.840.113549.1.5.13");

        // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
        let mut pbes2 = SliceReader::new(&pbes2_bytes).expect("slice reader");
        let (kdf_bytes, enc_bytes) = pbes2
            .sequence(|r| {
                let kdf = r.tlv_bytes().expect("kdf TLV").to_vec();
                let enc = r.tlv_bytes().expect("enc TLV").to_vec();
                Ok((kdf, enc))
            })
            .expect("parse PBES2-params");

        // keyDerivationFunc ::= SEQUENCE { OID id-PBKDF2, PBKDF2-params }
        let mut kdf = SliceReader::new(&kdf_bytes).expect("slice reader");
        let (kdf_oid, salt_os, iter_count, prf_oid) = kdf
            .sequence(|r| {
                let oid: ObjectIdentifier = r.decode().expect("OID");
                let (salt, iterations, prf) = r.sequence(|r| {
                    let salt: OctetStringRef = r.decode().expect("salt");
                    let iterations: u32 = r.decode().expect("iterationCount");
                    let prf: ObjectIdentifier = r
                        .sequence(|r| {
                            let oid: ObjectIdentifier = r.decode().expect("prf OID");
                            Ok(oid)
                        })
                        .expect("parse prf AlgorithmIdentifier");
                    Ok((salt, iterations, prf))
                })?;
                Ok((oid, salt, iterations, prf))
            })
            .expect("parse keyDerivationFunc");
        assert_eq!(kdf_oid.to_string(), "1.2.840.113549.1.5.12");
        assert_eq!(salt_os.as_bytes(), &salt);
        assert_eq!(iter_count, 100_000);
        assert_eq!(prf_oid.to_string(), "1.2.840.113549.2.9");

        // encryptionScheme ::= SEQUENCE { OID id-aes256-CBC, IV OCTET STRING }
        let mut enc = SliceReader::new(&enc_bytes).expect("slice reader");
        let (enc_oid, enc_iv) = enc
            .sequence(|r| {
                let oid: ObjectIdentifier = r.decode().expect("OID");
                let iv: OctetStringRef = r.decode().expect("IV");
                Ok((oid, iv))
            })
            .expect("parse encryptionScheme");
        assert_eq!(enc_oid.to_string(), "2.16.840.1.101.3.4.1.42");
        assert_eq!(enc_iv.as_bytes(), &iv);

        // Sanity: the whole outer structure consumed exactly the input.
        assert!(outer.is_finished(), "trailing bytes after outer SEQUENCE");
    }
}
