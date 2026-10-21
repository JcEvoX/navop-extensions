//! HexHub 口令解密。
//!
//! HexHub 把 SSH 的 `password` / `privateKey`、代理口令等字段在入库前用**固定密钥**
//! AES-128-CBC 加密，再 base64 编码（见 issue #7 给出的参考实现与其客户端
//! `serializeData → encryptFields → Yu()` 调用链）：
//!
//! ```text
//! key = "CsN#&Uc!aOUQbh&B"   (16 字节)
//! iv  = "w6KQ^MPlEx*mfHcb"   (16 字节)
//! 密文 = base64(AES-128-CBC-PKCS7(UTF-8 明文))
//! ```
//!
//! 固定密钥意味着任何拿到导出文件的人都能解出口令——这里不需要用户输入任何密码。
//! CBC 没有认证，错误输入也能"解出"字节，所以解完必须过一遍 [`decode_plaintext`]。

use aes::Aes128;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

const KEY: &[u8; 16] = b"CsN#&Uc!aOUQbh&B";
const IV: &[u8; 16] = b"w6KQ^MPlEx*mfHcb";

type Decryptor = cbc::Decryptor<Aes128>;

/// 解密一个 HexHub 密文字段。明文为空、密文不是 HexHub 格式、或解出来不是可打印文本
/// 时返回 `None`——绝不把乱码当口令导进去。
pub(crate) fn decrypt_secret(ciphertext: &str) -> Option<String> {
    let ciphertext = ciphertext.trim();
    if ciphertext.is_empty() {
        return None;
    }
    let raw = decode_base64(ciphertext)?;
    if raw.is_empty() || !raw.len().is_multiple_of(16) {
        return None;
    }
    let plain = Decryptor::new(KEY.into(), IV.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&raw)
        .ok()?;
    decode_plaintext(&plain)
}

/// 「看起来像口令」：合法 UTF-8，且不含 NUL 与其它控制字符（换行/制表符除外）。
fn decode_plaintext(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.trim_end_matches(['\u{0}', '\n', '\r']).trim();
    if text.is_empty() {
        return None;
    }
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(text.to_string())
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let compact = value.replace(['\r', '\n'], "");
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(compact.trim_end_matches('=')))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

    type Encryptor = cbc::Encryptor<Aes128>;

    fn encrypt(plain: &str) -> String {
        let ciphertext =
            Encryptor::new(KEY.into(), IV.into()).encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes());
        STANDARD.encode(ciphertext)
    }

    #[test]
    fn decrypts_password_encrypted_with_the_fixed_key() {
        // issue #7 里那条等价 Python 实现加密出来的形状：base64 + AES-128-CBC + PKCS7。
        let ciphertext = encrypt("p@ssw0rd!中文");
        assert_eq!(
            decrypt_secret(&ciphertext).as_deref(),
            Some("p@ssw0rd!中文")
        );
    }

    #[test]
    fn tolerates_padding_and_whitespace_variants() {
        let ciphertext = encrypt("deploy");
        let unwrapped = ciphertext.trim_end_matches('=');
        assert_eq!(decrypt_secret(unwrapped).as_deref(), Some("deploy"));
        assert_eq!(
            decrypt_secret(&format!("  {ciphertext}\n")).as_deref(),
            Some("deploy")
        );
    }

    #[test]
    fn rejects_values_that_are_not_hexhub_ciphertext() {
        assert_eq!(decrypt_secret(""), None);
        assert_eq!(decrypt_secret("not-base64!"), None);
        // 合法 base64 但长度不是块整数倍。
        assert_eq!(decrypt_secret("QUJD"), None);
    }

    #[test]
    fn rejects_garbage_that_decrypts_to_control_characters() {
        // 16 字节任意二进制：CBC 能"解开"，但解出来是控制字符，必须拒绝。
        let ciphertext = STANDARD.encode([0u8; 16]);
        assert_eq!(decrypt_secret(&ciphertext), None);
    }
}
