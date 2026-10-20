//! SecureCRT 配置密码解密。
//!
//! SecureCRT 存在两代、三种密文格式（与 `securecrt_cipher` 参考实现一致）：
//!
//! - **V1**：无前缀的裸 hex，双层 Blowfish-CBC（两个固死密钥 + 零 IV），
//!   明文是 UTF-16LE，两端各有 4 字节随机/填充；
//! - **V2-`02:`**：`key = SHA256(passphrase)`，AES-256-CBC + 零 IV；
//! - **V2-`03:`**：密文前 16 字节是 salt，`key ‖ iv = bcrypt_pbkdf(passphrase, salt, 16, 48)`。
//!
//! V2 的明文布局是 LVC：`<u32le 明文长度> 明文 SHA256(明文) 填充`，因此校验和同时
//! 承担「口令是否正确」的判定——口令错时 CBC 解出的填充几乎必然不合规。
//!
//! 本模块逐行移植自已用测试向量验证过的 Go 实现
//! `scrt-go-migrate/internal/scrt/{cipher,v2,bcrypt_pbkdf}.go`，测试向量直接取自
//! 该实现的 `*_test.go`，两边结果必须逐字节一致。

use aes::Aes256;
use blowfish::Blowfish;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use sha2::{Digest, Sha256};

/// V1 外层 Blowfish 密钥（SecureCRT 内置常量，与用户口令无关）。
const V1_OUTER_KEY: [u8; 16] = [
    0x24, 0xA6, 0x3D, 0xDE, 0x5B, 0xD3, 0xB3, 0x82, 0x9C, 0x7E, 0x06, 0xF4, 0x08, 0x16, 0xAA, 0x07,
];

/// V1 内层 Blowfish 密钥。
const V1_INNER_KEY: [u8; 16] = [
    0x5F, 0xB0, 0x45, 0xA2, 0x94, 0x17, 0xD9, 0x16, 0xC6, 0xC6, 0xA2, 0xFF, 0x06, 0x41, 0x82, 0xB7,
];

const V1_IV: [u8; 8] = [0u8; 8];

/// V2-`03:` 的 bcrypt-pbkdf 轮数。
const V2_BCRYPT_ROUNDS: u32 = 16;

/// 未显式设置 SecureCRT 配置口令时的口令（SecureCRT 默认值，等价于空字符串）。
pub(crate) const DEFAULT_PASSPHRASE: &str = "";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecryptError {
    /// 空值或明显不是密文。
    NotCiphertext,
    InvalidHex,
    /// 长度不合法（非块对齐、短于最小长度）。
    BadLength,
    /// `xx:` 前缀不认识。
    UnknownPrefix,
    /// 填充校验失败——绝大多数情况意味着口令不对。
    BadPadding,
    /// 末尾 SHA256 校验和不匹配——同样意味着口令不对或密文损坏。
    BadChecksum,
    /// 解出来的字节不是合法文本。
    NotText,
}

impl DecryptError {
    /// 给人看的原因，用于导入警告文案。
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::NotCiphertext => "value is not a SecureCRT ciphertext",
            Self::InvalidHex => "ciphertext is not valid hex",
            Self::BadLength => "ciphertext length is invalid",
            Self::UnknownPrefix => "unknown SecureCRT cipher version prefix",
            Self::BadPadding => {
                "padding check failed (a SecureCRT config passphrase is probably set)"
            }
            Self::BadChecksum => {
                "checksum mismatch (a SecureCRT config passphrase is probably set)"
            }
            Self::NotText => "decrypted bytes are not valid UTF-8",
        }
    }
}

/// 解密单个 SecureCRT 配置密码（会话自带的 `Password V2` / `Password` 字段，
/// 或 Credentials 目录里的同名凭据）。
///
/// `raw` 是 ini/xml 里的原始字符串：`02:…`、`03:…` 或 V1 的裸 hex。
pub(crate) fn decrypt_config_password(raw: &str, passphrase: &str) -> Result<String, DecryptError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DecryptError::NotCiphertext);
    }
    match version_prefix(raw) {
        Some("02") | Some("03") => decrypt_v2(raw, passphrase),
        Some(_) => Err(DecryptError::UnknownPrefix),
        None => decrypt_v1(raw),
    }
}

/// 取 `xx:` 形式的前缀。只看字节，避免在非 ASCII 上切出无效的字符边界。
fn version_prefix(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    if bytes.len() >= 3 && bytes[2] == b':' && bytes[..2].iter().all(u8::is_ascii_hexdigit) {
        raw.get(..2)
    } else {
        None
    }
}

fn decrypt_v1(cipher_hex: &str) -> Result<String, DecryptError> {
    let ciphertext = decode_hex(cipher_hex).ok_or(DecryptError::InvalidHex)?;
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(8) {
        return Err(DecryptError::BadLength);
    }

    let outer = blowfish_cbc_decrypt(&V1_OUTER_KEY, &ciphertext)?;
    // 外层明文首尾各 4 字节是随机前缀/后缀。
    let inner_cipher = outer
        .get(4..outer.len() - 4)
        .ok_or(DecryptError::BadLength)?;
    let inner = blowfish_cbc_decrypt(&V1_INNER_KEY, inner_cipher)?;

    // 内层是 UTF-16LE 的 C 字符串：找双字节 0 结尾。
    let terminator = inner
        .chunks_exact(2)
        .position(|pair| pair[0] == 0 && pair[1] == 0)
        .map(|index| index * 2)
        .ok_or(DecryptError::NotText)?;
    let padding_len = inner.len() - (terminator + 2);
    if padding_len != 8 - (terminator + 2) % 8 {
        return Err(DecryptError::BadPadding);
    }

    let units = inner[..terminator]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| DecryptError::NotText)
}

fn decrypt_v2(raw: &str, passphrase: &str) -> Result<String, DecryptError> {
    let (prefix, body) = raw.split_once(':').ok_or(DecryptError::UnknownPrefix)?;
    let ciphertext = decode_hex(body).ok_or(DecryptError::InvalidHex)?;

    let (key, iv, payload) = match prefix {
        // 02：密钥是口令的 SHA256，IV 全零。
        "02" => {
            let digest = Sha256::digest(passphrase.as_bytes());
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&[0u8; 16]);
            (digest.to_vec(), iv, ciphertext)
        }
        // 03：前 16 字节是 salt，key 与 iv 都由 bcrypt-pbkdf 派生。
        "03" => {
            if ciphertext.len() < 16 {
                return Err(DecryptError::BadLength);
            }
            let (salt, payload) = ciphertext.split_at(16);
            let mut derived = [0u8; 48];
            bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, V2_BCRYPT_ROUNDS, &mut derived)
                .map_err(|_| DecryptError::BadChecksum)?;
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&derived[32..48]);
            (derived[..32].to_vec(), iv, payload.to_vec())
        }
        _ => return Err(DecryptError::UnknownPrefix),
    };

    let plaintext_with_frame = aes_cbc_decrypt(&key, &iv, &payload)?;
    unwrap_lvc_frame(&plaintext_with_frame)
}

/// V2 明文布局：`<u32le len> 明文 <sha256(明文)> 填充`。
fn unwrap_lvc_frame(frame: &[u8]) -> Result<String, DecryptError> {
    let length_bytes = frame.get(..4).ok_or(DecryptError::BadLength)?;
    let plaintext_len = u32::from_le_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]) as usize;

    let plaintext = frame
        .get(4..4 + plaintext_len)
        .ok_or(DecryptError::BadLength)?;
    let checksum = frame
        .get(4 + plaintext_len..4 + plaintext_len + 32)
        .ok_or(DecryptError::BadChecksum)?;
    let padding = &frame[4 + plaintext_len + 32..];

    // 与 Go 实现一致：PKCS#7 变体，但填充量不足半个块时再多补一个整块。
    let mut expected_padding = 16 - (4 + plaintext_len + 32) % 16;
    if expected_padding < 8 {
        expected_padding += 16;
    }
    if padding.len() != expected_padding {
        return Err(DecryptError::BadPadding);
    }

    if Sha256::digest(plaintext).as_slice() != checksum {
        return Err(DecryptError::BadChecksum);
    }
    String::from_utf8(plaintext.to_vec()).map_err(|_| DecryptError::NotText)
}

fn blowfish_cbc_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut buffer = data.to_vec();
    let decryptor = cbc::Decryptor::<Blowfish>::new_from_slices(key, &V1_IV)
        .map_err(|_| DecryptError::BadLength)?;
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| DecryptError::BadPadding)?;
    Ok(buffer)
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if !data.len().is_multiple_of(16) {
        return Err(DecryptError::BadLength);
    }
    let mut buffer = data.to_vec();
    let decryptor =
        cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| DecryptError::BadLength)?;
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| DecryptError::BadPadding)?;
    Ok(buffer)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 以下三条向量直接取自 `scrt-go-migrate/internal/scrt/cipher_test.go`，
    // 保证 Rust 侧与已验证的 Go 实现逐字节一致。

    #[test]
    fn decrypts_v1_blowfish_vector() {
        let plaintext = decrypt_config_password(
            "c9d42f89c85d3c089d115db0e899c2070d653048467f869d196d689f754269d5d04ec18a59b46a5c94c39574a0593ed896cd25e84707089f",
            DEFAULT_PASSPHRASE,
        )
        .expect("V1 vector must decrypt");
        assert_eq!(plaintext, "mySecretPassword123");
    }

    #[test]
    fn decrypts_v2_sha256_vector() {
        let plaintext = decrypt_config_password(
            "02:ce03b492b17bdd0e66ddce4732ddbbe6afb25537207e4e1b61b35472cd5320f0b7b597cb8a27f1986301290565f50233e0eeefd794ae86ff85ccaf44276133eb",
            "configpass",
        )
        .expect("V2-02 vector must decrypt");
        assert_eq!(plaintext, "pass-02-vector");
    }

    #[test]
    fn decrypts_v2_bcrypt_vector() {
        let plaintext = decrypt_config_password(
            "03:000102030405060708090a0b0c0d0e0fdc2bbba761e1186c63ec87155e157c0882bd8806c52e6b100ec0d3136513a24e4df7fe48eaf506e7f00e21def5abe00fd4769bffe21d210e3a66f9115c7e03a8",
            "configpass",
        )
        .expect("V2-03 vector must decrypt");
        assert_eq!(plaintext, "pass-03-vector");
    }

    #[test]
    fn rejects_wrong_passphrase_for_v2_03() {
        // 同一份密文用错口令必须失败（填充/校验和任一拦住），绝不能返回垃圾明文。
        let error = decrypt_config_password(
            "03:000102030405060708090a0b0c0d0e0fdc2bbba761e1186c63ec87155e157c0882bd8806c52e6b100ec0d3136513a24e4df7fe48eaf506e7f00e21def5abe00fd4769bffe21d210e3a66f9115c7e03a8",
            "wrong-passphrase",
        )
        .expect_err("wrong passphrase must not decrypt");
        // 口令错时 CBC 解出的「明文长度」通常已是天文数字，因此可能先撞长度检查；
        // 无论哪一处拦住，结论都必须是「解不出来」，绝不能返回垃圾明文。
        assert!(matches!(
            error,
            DecryptError::BadLength
                | DecryptError::BadPadding
                | DecryptError::BadChecksum
                | DecryptError::NotText
        ));
    }

    #[test]
    fn rejects_invalid_and_unknown_values() {
        assert_eq!(
            decrypt_config_password("", DEFAULT_PASSPHRASE),
            Err(DecryptError::NotCiphertext)
        );
        assert_eq!(
            decrypt_config_password("02:deadbeef", DEFAULT_PASSPHRASE),
            Err(DecryptError::BadLength)
        );
        assert_eq!(
            decrypt_config_password("02:zz", DEFAULT_PASSPHRASE),
            Err(DecryptError::InvalidHex)
        );
        assert_eq!(
            decrypt_config_password("09:aabb", DEFAULT_PASSPHRASE),
            Err(DecryptError::UnknownPrefix)
        );
        // 不是 hex 的自由文本（历史导出的明文片段）走 V1 分支后报无效 hex。
        assert_eq!(
            decrypt_config_password("securecrt-secret-sentinel", DEFAULT_PASSPHRASE),
            Err(DecryptError::InvalidHex)
        );
    }
}
