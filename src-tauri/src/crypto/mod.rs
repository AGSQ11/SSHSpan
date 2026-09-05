//! Cryptographic operations for SSHSpan
//! Replaces Node.js crypto module usage with Rust equivalents

pub mod vault;
pub mod keys;
pub mod putty;
pub mod bitwarden;
pub mod utils;
pub mod pkcs8;


#[derive(Clone)]
pub struct CryptoService;

impl CryptoService {
    pub fn new() -> Self {
        Self
    }
}