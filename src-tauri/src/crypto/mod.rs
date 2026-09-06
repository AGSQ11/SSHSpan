//! Cryptographic operations for SSHSpan
//! Replaces Node.js crypto module usage with Rust equivalents

pub mod bitwarden;
pub mod keys;
pub mod pkcs8;
pub mod putty;
pub mod utils;
pub mod vault;

#[derive(Clone)]
pub struct CryptoService;

impl CryptoService {
    pub fn new() -> Self {
        Self
    }
}
