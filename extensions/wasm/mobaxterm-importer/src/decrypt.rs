//! MobaXterm 存储口令解密。
//!
//! 移植自 `Netcatty/domain/vaultImport/mobaXtermCrypto.ts`，两条实现路径：
//!
//! * **主密码**：`AES-256-CFB8`，密钥是 `SHA512(master_password)[..32]`；IV 有两种
//!   （老格式是 `AES-256(key, 0^16)` 加密出来的块，v25 起把随机 IV 前缀写在密文里）。
//! * **弱口令**：MobaXterm 自家那套"字母表置换"编码，密钥由 `SessionP` 或
//!   `MPSetAccount + MPSetComputer + 连接自身的用户名/主机名` 拼出来。
//!
//! 两种情况都只做"看起来像口令才算成功"的判定：AES-CFB8 没有认证，错误密钥也能
//! 输出字节，所以必须靠 `decode_plaintext` 的 NUL/控制字符/UTF-8 校验挡掉垃圾。

use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha512};

/// 弱密钥允许出现的字符集（MobaXterm 置换表的字母表）。
const WEAK_KEY_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
/// 弱密钥的起始种子，逐位被真实密钥材料替换。
const WEAK_KEY_SEED: &[u8; 16] = b"0d5e9n1348/U2+67";

/// 一条 MobaXterm 密文的解密输入。缺哪个字段就走不了对应的那条路径。
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StoredSecretInput<'a> {
    pub(crate) ciphertext: &'a str,
    pub(crate) master_password: Option<&'a str>,
    pub(crate) session_p: Option<&'a str>,
    pub(crate) sys_username: Option<&'a str>,
    pub(crate) sys_hostname: Option<&'a str>,
    pub(crate) conn_username: Option<&'a str>,
    pub(crate) conn_hostname: Option<&'a str>,
}

/// 解密一条 MobaXterm 存储口令；解不出来（含"解出来不像口令"）时返回 `None`。
pub(crate) fn decrypt_stored_secret(input: &StoredSecretInput<'_>) -> Option<String> {
    let ciphertext = input.ciphertext.trim();
    if ciphertext.is_empty() {
        return None;
    }

    // 主密码优先：用户在 MobaXterm 里设了主密码，弱口令路径一定失败。
    if let Some(master_password) = input.master_password.filter(|value| !value.is_empty()) {
        return decode_plaintext(&decrypt_master_password(ciphertext, master_password)?);
    }

    // 其次是以 用户名+主机名 为材料的弱密钥（[Misc] 里记着本机账号/计算机名）。
    if let (Some(conn_username), Some(conn_hostname), Some(sys_username), Some(sys_hostname)) = (
        input.conn_username,
        input.conn_hostname,
        input.sys_username,
        input.sys_hostname,
    ) {
        let key = craft_connection_key(sys_username, sys_hostname, conn_username, conn_hostname);
        if let Some(weak) = decrypt_weak_cipher(ciphertext, &key) {
            if let Some(plaintext) = decode_plaintext(&weak) {
                return Some(plaintext);
            }
        }
    }

    // 最后试 SessionP（[Misc] 里那一串数字）。
    if let Some(session_p) = input.session_p.filter(|value| !value.is_empty()) {
        let key = craft_session_p_key(session_p);
        return decode_plaintext(&decrypt_weak_cipher(ciphertext, &key)?);
    }

    None
}

/// 密文是否"看起来需要主密码"——`_@` 前缀是 v25 随机 IV 格式的标志。
pub(crate) fn looks_like_random_iv_ciphertext(ciphertext: &str) -> bool {
    let ciphertext = ciphertext.trim();
    ciphertext.starts_with("_@") && ciphertext.len() >= 20
}

fn decrypt_master_password(ciphertext: &str, master_password: &str) -> Option<Vec<u8>> {
    let digest = Sha512::digest(master_password.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);

    let (iv, body) = if looks_like_random_iv_ciphertext(ciphertext) {
        let iv = latin1_bytes(ciphertext).get(2..18)?.try_into().ok()?;
        let decoded = decode_base64(ciphertext, true)?;
        if decoded.len() <= 15 {
            return None;
        }
        (iv, decoded[15..].to_vec())
    } else {
        let decoded = decode_base64(ciphertext, false)?;
        if decoded.is_empty() {
            return None;
        }
        (aes256_encrypt_block(&key, &[0u8; 16]), decoded)
    };
    if body.is_empty() {
        return None;
    }
    Some(aes_cfb8_decrypt(&key, &iv, &body))
}

/// AES-256-CFB8 解密：逐字节把 `E(shift)[0]` 与密文异或，再把密文推进移位寄存器。
fn aes_cfb8_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("AES-256 accepts a 32-byte key");
    let mut shift = *iv;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        let mut block = aes::Block::from(shift);
        cipher.encrypt_block(&mut block);
        out.push(byte ^ block[0]);
        shift.copy_within(1.., 0);
        shift[15] = byte;
    }
    out
}

fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new_from_slice(key).expect("AES-256 accepts a 32-byte key");
    let mut buffer = aes::Block::from(*block);
    cipher.encrypt_block(&mut buffer);
    buffer.into()
}

/// `[Misc] SessionP` → 弱密钥。
pub(crate) fn craft_session_p_key(session_p: &str) -> [u8; 16] {
    let repeated = repeat_to_length(session_p, 20);
    craft_weak_key(&[
        repeated.to_uppercase(),
        repeated.to_uppercase(),
        repeated.to_lowercase(),
        repeated.to_lowercase(),
    ])
}

/// `[Misc] MPSetAccount + MPSetComputer` 与连接自身 用户名+主机名 → 弱密钥。
pub(crate) fn craft_connection_key(
    sys_username: &str,
    sys_hostname: &str,
    conn_username: &str,
    conn_hostname: &str,
) -> [u8; 16] {
    let sys_material = repeat_to_length(&format!("{sys_username}{sys_hostname}"), 20);
    let conn_material = repeat_to_length(&format!("{conn_username}{conn_hostname}"), 20);
    craft_weak_key(&[
        sys_material.to_uppercase(),
        conn_material.to_uppercase(),
        sys_material.to_lowercase(),
        conn_material.to_lowercase(),
    ])
}

/// 用四段密钥材料逐位替换种子，得到 16 字节弱密钥。
fn craft_weak_key(keyspace: &[String]) -> [u8; 16] {
    let mut key = *WEAK_KEY_SEED;
    for index in 0..key.len() {
        let source = &keyspace[(index + 1) % keyspace.len()];
        // 与原实现一致：按 UTF-16 码元取第 index 位，取不到就保留种子。
        let Some(unit) = source.encode_utf16().nth(index) else {
            continue;
        };
        if unit > 0x7f {
            continue;
        }
        let byte = unit as u8;
        if !key.contains(&byte) && WEAK_KEY_ALPHABET.as_bytes().contains(&byte) {
            key[index] = byte;
        }
    }
    key
}

/// 弱密钥加密的逆运算：密文只保留属于密钥的字符，两两还原成一个字节。
fn decrypt_weak_cipher(ciphertext: &str, key: &[u8; 16]) -> Option<Vec<u8>> {
    let filtered: Vec<u8> = ciphertext
        .chars()
        .filter_map(|ch| {
            let unit = ch as u32;
            if unit <= 0xff && key.contains(&(unit as u8)) {
                Some(unit as u8)
            } else {
                None
            }
        })
        .collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return None;
    }

    let mut working = *key;
    let mut plaintext = Vec::with_capacity(filtered.len() / 2);
    for pair in filtered.chunks_exact(2) {
        let low = working.iter().position(|&byte| byte == pair[0])?;
        working.rotate_right(1);
        let high = working.iter().position(|&byte| byte == pair[1])?;
        working.rotate_right(1);
        plaintext.push((((high << 4) + low) & 0xff) as u8);
    }
    Some(plaintext)
}

/// 只接受"像口令"的字节：允许尾部 NUL 补位，拒绝内部 NUL、控制字符和非 UTF-8。
fn decode_plaintext(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let slice = match bytes.iter().position(|&byte| byte == 0) {
        Some(0) => return None,
        Some(position) => {
            if bytes[position..].iter().any(|&byte| byte != 0) {
                return None;
            }
            &bytes[..position]
        }
        None => bytes,
    };
    if slice.is_empty() {
        return None;
    }
    if slice.iter().any(|&byte| byte < 0x20 && byte != 0x09) {
        return None;
    }
    std::str::from_utf8(slice).ok().map(str::to_string)
}

fn repeat_to_length(value: &str, min_length: usize) -> String {
    if value.is_empty() {
        return String::new();
    }
    let mut out = value.to_string();
    while out.encode_utf16().count() < min_length {
        out.push_str(value);
    }
    out
}

/// 按 `charCode & 0xff` 取字节，和 JS 侧 `latin1Encode` 对齐。
fn latin1_bytes(value: &str) -> Vec<u8> {
    value.chars().map(|ch| (ch as u32 & 0xff) as u8).collect()
}

fn decode_base64(input: &str, alt_alphabet: bool) -> Option<Vec<u8>> {
    let normalized: String = input
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .map(|ch| match (alt_alphabet, ch) {
            (true, '@') => '+',
            (true, '_') => '/',
            _ => ch,
        })
        .collect();
    if normalized.is_empty() {
        return None;
    }
    let padding = (4 - normalized.len() % 4) % 4;
    let mut padded = normalized;
    padded.extend(std::iter::repeat_n('=', padding));
    STANDARD.decode(padded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三条向量全部来自 `Netcatty/domain/vaultImport/mobaXtermCrypto.test.ts`，
    /// 其中两条是公开的 HyperSine 样本，一条是 v25 随机 IV 格式。
    #[test]
    fn decrypts_master_password_vectors() {
        assert_eq!(
            decrypt_stored_secret(&StoredSecretInput {
                ciphertext: "1du11XKQBOxud/FWh4ouWA==",
                master_password: Some("12345678"),
                ..Default::default()
            })
            .as_deref(),
            Some("Lw3+cZ2s.w@U@f]U")
        );
        assert_eq!(
            decrypt_stored_secret(&StoredSecretInput {
                ciphertext: "0XROpGmLAYVx",
                master_password: Some("12345678"),
                ..Default::default()
            })
            .as_deref(),
            Some("HyperSine")
        );
    }

    #[test]
    fn decrypts_published_session_p_vector() {
        let key = craft_session_p_key("165821882556840");
        let plaintext = decrypt_weak_cipher(
            "bSj4VWbHezNH3tTY9Nil2RzJX57p7/S6KqMw8VsiT/WH+I8p03pqnInAu",
            &key,
        )
        .and_then(|bytes| decode_plaintext(&bytes));
        assert_eq!(plaintext.as_deref(), Some("HyperSine"));
    }

    #[test]
    fn decrypts_published_connection_key_vector() {
        let plaintext = decrypt_stored_secret(&StoredSecretInput {
            ciphertext: "F0+wuBvbe9qPW6ypiOeYHTHhKdShRc/nXaM1Ky1jeTfw46TzQoSesX9buGm0WW36yP4lhH70ZCHZpEo4wLJhIl1",
            sys_username: Some("DoubleSine"),
            sys_hostname: Some("ShadowSurface"),
            conn_username: Some("root"),
            conn_hostname: Some("45.32.110.171"),
            ..Default::default()
        });
        assert_eq!(plaintext.as_deref(), Some("Lw3+cZ2s.w@U@f]U"));
    }

    #[test]
    fn wrong_master_password_is_rejected_instead_of_returning_garbage() {
        for master_password in ["wrong-password", "wrong0", "wrong25", "x", "0"] {
            for ciphertext in ["1du11XKQBOxud/FWh4ouWA==", "0XROpGmLAYVx"] {
                assert_eq!(
                    decrypt_stored_secret(&StoredSecretInput {
                        ciphertext,
                        master_password: Some(master_password),
                        ..Default::default()
                    }),
                    None,
                    "{ciphertext} accepted garbage for {master_password}"
                );
            }
        }
    }

    #[test]
    fn plaintext_decoder_rejects_interior_nul_but_trims_trailing_padding() {
        assert_eq!(
            decode_plaintext(&[0x4d, 0x29, 0x38, 0x25, 0x00, 0x72, 0x33, 0x8a, 0xa8]),
            None
        );
        assert_eq!(
            decode_plaintext(&[0x48, 0x69, 0x00, 0x00]).as_deref(),
            Some("Hi")
        );
        assert_eq!(decode_plaintext(&[0x00, 0x48]), None);
    }

    #[test]
    fn empty_input_never_decrypts() {
        assert_eq!(
            decrypt_stored_secret(&StoredSecretInput {
                ciphertext: "   ",
                master_password: Some("12345678"),
                ..Default::default()
            }),
            None
        );
    }
}
