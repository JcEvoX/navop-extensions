//! Navicat 旧版（≤ 11，`connections.ncx` 导出）口令解密。
//!
//! 算法是 `AES-128-CBC`，固定密钥 `libcckeylibcckey`、固定 IV `libcciv libcciv `，
//! 密钥列是**十六进制**（大小写都出现过），明文带 PKCS#7 填充。移植自
//! `dbx/apps/desktop/src/lib/imports/navicatImport.ts`。
//!
//! Navicat 12+ 换成了逐安装派生的密钥，这套常量解不开；此时必须返回 `None`，
//! 让调用方如实标注「没导进来」，绝不能把解出来的垃圾当成口令。

use aes::Aes128;
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

const LEGACY_KEY: &[u8; 16] = b"libcckeylibcckey";
const LEGACY_IV: &[u8; 16] = b"libcciv libcciv ";

/// 解一条 Navicat 旧版口令密文（十六进制）；解不出来返回 `None`。
pub(crate) fn decrypt_legacy_password(value: &str) -> Option<String> {
    let mut buffer = hex::decode(value.trim()).ok()?;
    if buffer.is_empty() || !buffer.len().is_multiple_of(16) {
        return None;
    }
    let plaintext = Decryptor::<Aes128>::new(LEGACY_KEY.into(), LEGACY_IV.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .ok()?;
    let text = std::str::from_utf8(plaintext).ok()?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 向量用 Node `aes-128-cbc` 以同一组 key/iv 算出，明文分别为
    /// `database-secret`、`P@ssw0rd!`。
    #[test]
    fn decrypts_legacy_ciphertext() {
        assert_eq!(
            decrypt_legacy_password("9E3951B0152DA9E9391648E8B0B58029").as_deref(),
            Some("database-secret")
        );
        assert_eq!(
            decrypt_legacy_password("FB7D4A56E9AADE86D052B0F125570306").as_deref(),
            Some("P@ssw0rd!")
        );
    }

    #[test]
    fn accepts_lowercase_hex() {
        assert_eq!(
            decrypt_legacy_password("9e3951b0152da9e9391648e8b0b58029").as_deref(),
            Some("database-secret")
        );
    }

    #[test]
    fn rejects_non_hex_and_misaligned_input() {
        assert_eq!(decrypt_legacy_password(""), None);
        assert_eq!(decrypt_legacy_password("not-a-hex-value"), None);
        assert_eq!(decrypt_legacy_password("9E3951B0152DA9"), None);
        // Navicat 12+ 的 base64 密文：不是十六进制，直接判失败。
        assert_eq!(decrypt_legacy_password("dGhpcyBpcyBub3QgaGV4"), None);
    }
}
