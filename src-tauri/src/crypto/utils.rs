//! Common cryptographic utilities

use base64ct::{Base64, Base64Unpadded, Encoding};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

/// Generate random bytes returning a new Vec
pub fn generate_random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    generate_random_bytes(&mut buf);
    buf
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Compute SSH fingerprint (SHA-256) - matches OpenSSH's `ssh-keygen -lf` output
/// exactly: "SHA256:" + unpadded standard base64 of the raw digest (no `=`).
pub fn ssh_fingerprint_sha256(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    format!("SHA256:{}", Base64Unpadded::encode_string(&hash))
}

/// Compute SSH fingerprint (MD5) - legacy format
pub fn ssh_fingerprint_md5(public_key: &[u8]) -> String {
    use md5::{Md5, Digest};
    let hash = Md5::digest(public_key);
    let mut result = String::new();
    for (i, byte) in hash.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        result.push_str(&format!("{:02x}", byte));
    }
    format!("MD5:{}", result)
}

/// Base64 encode
pub fn base64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

/// Base64 decode
pub fn base64_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    Ok(Base64::decode_vec(data)?)
}

/// Hex encode
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Hex decode
pub fn hex_decode(data: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(data)?)
}

/// PKCS#7 padding
pub fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    let padding_len = block_size - (data.len() % block_size);
    for _ in 0..padding_len {
        data.push(padding_len as u8);
    }
}

/// PKCS#7 unpadding
pub fn pkcs7_unpad(data: &mut [u8]) -> anyhow::Result<usize> {
    if data.is_empty() {
        anyhow::bail!("Empty data");
    }
    let padding_len = data[data.len() - 1] as usize;
    if padding_len == 0 || padding_len > 16 {
        anyhow::bail!("Invalid padding length");
    }
    if data.len() < padding_len {
        anyhow::bail!("Data too short for padding");
    }
    for byte in &data[data.len() - padding_len..] {
        if *byte != padding_len as u8 {
            anyhow::bail!("Invalid padding bytes");
        }
    }
    Ok(data.len() - padding_len)
}

/// Read length-prefixed string from buffer
pub fn read_length_prefixed(data: &[u8], offset: &mut usize) -> anyhow::Result<Vec<u8>> {
    if *offset + 4 > data.len() {
        anyhow::bail!("Buffer too short for length");
    }
    let len = u32::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
    ]) as usize;
    *offset += 4;

    if *offset + len > data.len() {
        anyhow::bail!("Buffer too short for string data");
    }
    let result = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(result)
}

/// Write length-prefixed string to buffer
pub fn write_length_prefixed(output: &mut Vec<u8>, data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(data);
}

/// Read u32 from buffer
pub fn read_u32(data: &[u8], offset: &mut usize) -> anyhow::Result<u32> {
    if *offset + 4 > data.len() {
        anyhow::bail!("Buffer too short for u32");
    }
    let val = u32::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]
    ]);
    *offset += 4;
    Ok(val)
}

/// Write u32 to buffer
pub fn write_u32(output: &mut Vec<u8>, val: u32) {
    output.extend_from_slice(&val.to_be_bytes());
}

/// Read u64 from buffer
pub fn read_u64(data: &[u8], offset: &mut usize) -> anyhow::Result<u64> {
    if *offset + 8 > data.len() {
        anyhow::bail!("Buffer too short for u64");
    }
    let val = u64::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
        data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7]
    ]);
    *offset += 8;
    Ok(val)
}

/// Write u64 to buffer
pub fn write_u64(output: &mut Vec<u8>, val: u64) {
    output.extend_from_slice(&val.to_be_bytes());
}