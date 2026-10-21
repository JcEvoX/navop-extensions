use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[path = "decrypt.rs"]
mod decrypt;

use decrypt::StoredSecretInput;

const MAX_MOBATXTERM_SESSIONS: usize = 8192;
const DEFAULT_SSH_PORT: u16 = 22;

/// 会话串第一组参数的索引 0 是会话类型（见 `session_type_label`）。
const SSH_SESSION_TYPE: &str = "0";
/// SFTP 会话：和 SSH 共用主机/端口/用户名/口令，宿主侧统一建模成 SSH，导进来才有用。
const SFTP_SESSION_TYPE: &str = "7";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportRecord {
    pub id: String,
    pub importer_id: String,
    pub source_label: String,
    pub source_id: Option<String>,
    pub kind: String,
    pub display_name: String,
    pub database: Option<serde_json::Value>,
    pub ssh: Option<SshImportRecord>,
    pub port_forwarding: Option<serde_json::Value>,
    pub password_status: String,
    pub warnings: Vec<ImportWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SshImportRecord {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub group_path: Option<String>,
    pub auth_method: SshImportAuthMethod,
    pub init_script: Option<String>,
    pub jump_server: Option<serde_json::Value>,
    pub proxy: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshImportAuthMethod {
    Password {
        password: Option<String>,
    },
    PrivateKey {
        key_path: String,
        passphrase: Option<String>,
    },
    Agent,
    AutoPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreviewReport {
    pub records: Vec<ImportRecord>,
    /// 没能导入的非 SSH 会话：会话类型名 → 条数。宿主的导入协议只认 SSH / 数据库 /
    /// 端口转发，RDP、VNC、telnet 之类没有对应的记录类型，只能如实报数。
    pub skipped: Vec<(String, usize)>,
}

pub fn preview_records_from_sources<'a, I>(sources: I, include_passwords: bool) -> Vec<ImportRecord>
where
    I: IntoIterator<Item = (String, &'a [u8])>,
{
    preview_report_from_sources(sources, include_passwords, None).records
}

/// 与 [`preview_records_from_sources`] 相同，但允许传入 MobaXterm 主密码。
///
/// 只有配了「主密码」的 MobaXterm（配置里有 `[SessPass]` 段）才需要它；不设主密码时
/// 口令走弱密钥路径，靠 `[Misc]` 里的 `SessionP` / `MPSetAccount` / `MPSetComputer`。
pub fn preview_records_from_sources_with_master_password<'a, I>(
    sources: I,
    include_passwords: bool,
    master_password: Option<&str>,
) -> Vec<ImportRecord>
where
    I: IntoIterator<Item = (String, &'a [u8])>,
{
    preview_report_from_sources(sources, include_passwords, master_password).records
}

/// 带「被跳过的会话」统计的预览，供 `scan()` 与警告文案使用。
pub fn preview_report_from_sources<'a, I>(
    sources: I,
    include_passwords: bool,
    master_password: Option<&str>,
) -> PreviewReport
where
    I: IntoIterator<Item = (String, &'a [u8])>,
{
    let mut report = PreviewReport::default();
    let mut seen = BTreeSet::new();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    for (path, bytes) in sources {
        let Some(text) = decode_text(bytes) else {
            continue;
        };
        let file = parse_file_report(&path, &text, include_passwords, master_password);
        for record in file.records {
            if seen.insert(record.id.clone()) {
                report.records.push(record);
            }
        }
        for (label, count) in file.skipped {
            *skipped.entry(label).or_default() += count;
        }
        if report.records.len() >= MAX_MOBATXTERM_SESSIONS {
            break;
        }
    }
    report.skipped = skipped.into_iter().collect();
    report
}

pub fn is_supported_source_path(path: &str) -> bool {
    let file_name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    file_name.eq_ignore_ascii_case("mobaxterm.ini")
        || has_extension(file_name, "mxtsessions")
        // 「右键会话 → Save session to file」导出的单条会话文件。
        || has_extension(file_name, "moba")
}

#[cfg(test)]
fn parse_ini_sessions(path: &str, text: &str) -> Vec<ImportRecord> {
    parse_file_report(path, text, false, None).records
}

#[derive(Default)]
struct FileReport {
    records: Vec<ImportRecord>,
    skipped: BTreeMap<String, usize>,
}

fn parse_file_report(
    path: &str,
    text: &str,
    include_passwords: bool,
    master_password: Option<&str>,
) -> FileReport {
    let file = ParsedFile::parse(text);
    let store = PasswordStore::build(&file, include_passwords, master_password);
    let mut report = FileReport::default();
    for entry in &file.sessions {
        let group = file.section_group(&entry.section);
        match session_record(path, entry, group, &store) {
            SessionOutcome::Record(record) => report.records.push(record),
            SessionOutcome::Skipped(label) => *report.skipped.entry(label).or_default() += 1,
            SessionOutcome::Unusable => {}
        }
    }
    // 文件级警告（跳过非 SSH 会话、口令存在注册表、主密码缺失……）挂到首条记录上，
    // 导入界面按记录展示。
    let mut warnings = skipped_warnings(&report.skipped);
    warnings.extend(store.file_warnings.iter().cloned());
    if let Some(first) = report.records.first_mut() {
        warnings.append(&mut first.warnings);
        first.warnings = warnings;
    }
    report
}

fn skipped_warnings(skipped: &BTreeMap<String, usize>) -> Vec<ImportWarning> {
    if skipped.is_empty() {
        return Vec::new();
    }
    let total: usize = skipped.values().sum();
    let detail = skipped
        .iter()
        .map(|(label, count)| format!("{label} ×{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    vec![ImportWarning {
        code: "mobaxterm_non_ssh_sessions_skipped".to_string(),
        message: format!(
            "{total} non-SSH session(s) were skipped ({detail}). Only SSH, database and \
             port-forwarding connections can be imported, so MobaXterm RDP/VNC/telnet/FTP \
             sessions are not carried over."
        ),
    }]
}

struct SessionEntry {
    section: String,
    key: String,
    value: String,
}

#[derive(Default)]
struct ParsedFile {
    sessions: Vec<SessionEntry>,
    section_groups: BTreeMap<String, String>,
    /// `[Passwords]`：`user@host` / `ssh22:user@host` → 密文。
    passwords: Vec<(String, String)>,
    /// `[Credentials]`：用户名 → 密文。
    credentials: Vec<(String, String)>,
    /// `[Misc]`：`SessionP` / `MPSetAccount` / `MPSetComputer` / `PasswordsInRegistry`。
    misc: BTreeMap<String, String>,
    /// 存在 `[SessPass]` 段 ⇒ 配置用了主密码。
    has_sesspass: bool,
}

impl ParsedFile {
    fn parse(text: &str) -> Self {
        let mut file = Self::default();
        let mut section = String::new();
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                section = name.trim().to_string();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            if key.is_empty() {
                continue;
            }
            let lower_section = section.to_ascii_lowercase();
            match lower_section.as_str() {
                "passwords" => {
                    if !value.is_empty() {
                        file.passwords.push((key.to_string(), value.to_string()));
                    }
                    continue;
                }
                "credentials" => {
                    if let Some((username, ciphertext)) = value.split_once(':') {
                        let (username, ciphertext) = (username.trim(), ciphertext.trim());
                        if !username.is_empty() && !ciphertext.is_empty() {
                            file.credentials
                                .push((username.to_string(), ciphertext.to_string()));
                        }
                    }
                    continue;
                }
                "misc" => {
                    file.misc
                        .insert(key.to_ascii_lowercase(), value.to_string());
                    continue;
                }
                "sesspass" => {
                    file.has_sesspass = true;
                    continue;
                }
                _ => {}
            }
            if !is_bookmark_section(&section) && !is_headerless_session(&section, value) {
                continue;
            }
            if key.eq_ignore_ascii_case("subrep") {
                if let Some(group) = normalize_group(Some(value)) {
                    file.section_groups.insert(section.clone(), group);
                }
                continue;
            }
            if key.eq_ignore_ascii_case("imgnum") {
                continue;
            }
            file.sessions.push(SessionEntry {
                section: section.clone(),
                key: key.to_string(),
                value: value.to_string(),
            });
        }
        file
    }

    fn section_group(&self, section: &str) -> Option<&str> {
        self.section_groups.get(section).map(String::as_str)
    }
}

/// 一个 MobaXterm 配置里解出来的口令，按记录查询。
#[derive(Default)]
struct PasswordStore {
    /// 原始键（`[Passwords]` 的 key）→ 明文。
    decrypted: BTreeMap<String, String>,
    /// 有密文但解不出来的键；不导口令时也会填满，用来判定 `unsupported`。
    undecrypted: Vec<String>,
    /// `[Credentials]` 解出来的明文，按用户名分组。
    credentials_by_user: BTreeMap<String, Vec<String>>,
    /// `[Credentials]` 解不出来的用户名。
    failed_credential_users: BTreeSet<String>,
    session_p: Option<String>,
    sys_username: Option<String>,
    sys_hostname: Option<String>,
    master_password: Option<String>,
    /// 是否真的尝试过解密；没尝试（用户没勾"导入密码"）时不报解密失败。
    attempted: bool,
    /// 主密码缺失，跳过了全部解密。
    master_password_missing: bool,
    file_warnings: Vec<ImportWarning>,
}

impl PasswordStore {
    fn build(file: &ParsedFile, include_passwords: bool, master_password: Option<&str>) -> Self {
        let mut store = Self {
            session_p: file.misc.get("sessionp").cloned(),
            sys_username: file.misc.get("mpsetaccount").cloned(),
            sys_hostname: file.misc.get("mpsetcomputer").cloned(),
            master_password: master_password
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            ..Self::default()
        };

        let has_ciphertext = !file.passwords.is_empty() || !file.credentials.is_empty();
        let passwords_in_registry = file
            .misc
            .get("passwordsinregistry")
            .is_some_and(|value| value.trim() == "1");

        if passwords_in_registry && !has_ciphertext {
            store.file_warnings.push(ImportWarning {
                code: "mobaxterm_passwords_in_windows_registry".to_string(),
                message: "MobaXterm saved its passwords in the Windows registry, so this \
                          configuration file has no credentials to import."
                    .to_string(),
            });
            return store;
        }
        if !has_ciphertext {
            return store;
        }
        if !include_passwords {
            // 用户没要求导密码：一条都不解，但要把"有密文"这件事记下来。
            store
                .undecrypted
                .extend(file.passwords.iter().map(|(key, _)| key.clone()));
            store
                .failed_credential_users
                .extend(file.credentials.iter().map(|(user, _)| user.clone()));
            return store;
        }
        if file.has_sesspass && master_password.is_none() {
            store.master_password_missing = true;
            store
                .undecrypted
                .extend(file.passwords.iter().map(|(key, _)| key.clone()));
            store
                .failed_credential_users
                .extend(file.credentials.iter().map(|(user, _)| user.clone()));
            return store;
        }
        store.attempted = true;

        for (key, ciphertext) in &file.passwords {
            let (conn_username, conn_hostname) = parse_password_key(key);
            let plaintext = decrypt::decrypt_stored_secret(&StoredSecretInput {
                ciphertext,
                master_password,
                session_p: store.session_p.as_deref(),
                sys_username: store.sys_username.as_deref(),
                sys_hostname: store.sys_hostname.as_deref(),
                conn_username: conn_username.as_deref(),
                conn_hostname: conn_hostname.as_deref(),
            });
            match plaintext {
                Some(plaintext) => {
                    store.decrypted.insert(key.clone(), plaintext);
                }
                None => store.undecrypted.push(key.clone()),
            }
        }

        // 凭据只按 SessionP 解：它们不绑定具体主机，拿不到 用户名+主机名 材料。
        for (username, ciphertext) in &file.credentials {
            let plaintext = decrypt::decrypt_stored_secret(&StoredSecretInput {
                ciphertext,
                master_password,
                session_p: store.session_p.as_deref(),
                sys_username: store.sys_username.as_deref(),
                sys_hostname: store.sys_hostname.as_deref(),
                conn_username: None,
                conn_hostname: None,
            });
            match plaintext {
                Some(plaintext) => store
                    .credentials_by_user
                    .entry(username.clone())
                    .or_default()
                    .push(plaintext),
                None => {
                    store.failed_credential_users.insert(username.clone());
                }
            }
        }
        store
    }

    /// 按 (用户名, 主机, 端口) 找明文；找不到返回 `None`。
    fn lookup(&self, username: &str, hostname: &str, port: Option<u16>) -> Option<&str> {
        if !username.is_empty() {
            for candidate in password_key_candidates(username, hostname, port) {
                if let Some(value) = self.decrypted.get(&candidate) {
                    return Some(value.as_str());
                }
            }
        }
        if let Some(key) = scan_matching(self.decrypted.keys(), username, hostname) {
            return self.decrypted.get(key).map(String::as_str);
        }
        // `[Credentials]` 只按用户名绑定，不区分主机；同名唯一时才采用。
        if !username.is_empty() {
            if let Some(values) = self.credentials_by_user.get(username) {
                if values.len() == 1 {
                    return values.first().map(String::as_str);
                }
            }
        }
        None
    }

    /// 有密文但这台主机没解出来（含主密码缺失、完全没尝试的情况）。
    fn has_unresolved_password(&self, username: &str, hostname: &str, port: Option<u16>) -> bool {
        if !username.is_empty() {
            for candidate in password_key_candidates(username, hostname, port) {
                if self.undecrypted.iter().any(|key| *key == candidate) {
                    return true;
                }
            }
        }
        scan_matching(self.undecrypted.iter(), username, hostname).is_some()
            || (!username.is_empty() && self.failed_credential_users.contains(username))
    }

    /// 会话自带的口令字段（标准会话串第 5 段），有些版本会把它当密文存。
    fn decrypt_inline(&self, ciphertext: &str, username: &str, hostname: &str) -> Option<String> {
        decrypt::decrypt_stored_secret(&StoredSecretInput {
            ciphertext,
            master_password: self.master_password.as_deref(),
            session_p: self.session_p.as_deref(),
            sys_username: self.sys_username.as_deref(),
            sys_hostname: self.sys_hostname.as_deref(),
            conn_username: Some(username),
            conn_hostname: Some(hostname),
        })
    }
}

/// `[Passwords]` 里一条口令可能用的三种键写法。
fn password_key_candidates(username: &str, hostname: &str, port: Option<u16>) -> [String; 3] {
    let port = port.unwrap_or(DEFAULT_SSH_PORT);
    [
        format!("{username}@{hostname}"),
        format!("ssh{port}:{username}@{hostname}"),
        format!("ssh:{username}@{hostname}"),
    ]
}

/// 在键集合里按解析出的 (用户名, 主机) 匹配，返回命中的键。
fn scan_matching<'a, I>(keys: I, username: &str, hostname: &str) -> Option<&'a String>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut host_only_match = None;
    let mut host_only_matches = 0usize;
    for key in keys {
        let (parsed_username, parsed_hostname) = parse_password_key(key);
        if !same_host(parsed_hostname.as_deref(), hostname) {
            continue;
        }
        if !username.is_empty() {
            match parsed_username.as_deref() {
                Some(parsed) if parsed != username => continue,
                Some(_) => return Some(key),
                // 键里没写用户名时不参与"用户名已指定"的匹配。
                None => continue,
            }
        }
        host_only_matches += 1;
        host_only_match = Some(key);
    }
    if username.is_empty() && host_only_matches == 1 {
        return host_only_match;
    }
    None
}

/// `[Passwords]` 的键形如 `user@host` 或 `ssh22:user@host`。
fn parse_password_key(raw: &str) -> (Option<String>, Option<String>) {
    let stripped = strip_scheme_prefix(raw.trim());
    match stripped.rsplit_once('@') {
        Some((username, hostname)) if !username.is_empty() && !hostname.is_empty() => {
            (Some(username.to_string()), Some(hostname.to_string()))
        }
        _ => (None, None),
    }
}

fn strip_scheme_prefix(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
        index += 1;
    }
    if index == 0 {
        return value;
    }
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if bytes.get(index) == Some(&b':') {
        &value[index + 1..]
    } else {
        value
    }
}

fn same_host(left: Option<&str>, right: &str) -> bool {
    left.is_some_and(|left| left.eq_ignore_ascii_case(right))
}

fn normalize_group(subrep: Option<&str>) -> Option<String> {
    let normalized = subrep
        .unwrap_or_default()
        .replace('\\', "/")
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn is_bookmark_section(section: &str) -> bool {
    let lower = section.trim().to_ascii_lowercase();
    if lower == "bookmark" {
        return true;
    }
    let Some(rest) = lower.strip_prefix("bookmarks") else {
        return false;
    };
    // `[Bookmarks]` / `[Bookmarks_1]`，以及少数导出工具写成 `[Bookmarks1]`。
    let rest = rest.strip_prefix('_').unwrap_or(rest);
    rest.is_empty() || rest.chars().all(|ch| ch.is_ascii_digit())
}

/// `.moba`（单条会话另存）整份文件没有段落头，只有一行 `名称=#109#0%...`。
fn is_headerless_session(section: &str, value: &str) -> bool {
    section.is_empty() && is_standard_prefix(value)
}

enum SessionOutcome {
    Record(ImportRecord),
    /// 是会话，但类型不是 SSH 家族：带上是哪种类型，用于汇总成「被跳过」的警告。
    Skipped(String),
    /// 不是会话行，或者连主机都没有，无法导入。
    Unusable,
}

fn session_record(
    path: &str,
    entry: &SessionEntry,
    group: Option<&str>,
    store: &PasswordStore,
) -> SessionOutcome {
    let (label, key_group) = session_label_and_group(&entry.key);
    let group = key_group.as_deref().or(group);

    let name = label.clone();
    // `source_id` 必须把段落也算进去：同一个名字可以分别出现在 `[Bookmarks]` 与
    // `[Bookmarks_1]` 里（不同文件夹各有一条同名会话），只拼 key 会当成同一条丢掉。
    let source_id = if entry.section.is_empty() {
        format!("{path}#{}", entry.key)
    } else {
        format!("{path}#{}#{}", entry.section, entry.key)
    };
    let id = record_id(&source_id);

    let (host, port, username, inline_password) = if is_standard_prefix(&entry.value) {
        match parse_standard_session(&entry.value) {
            Some(fields) => fields,
            None => {
                return SessionOutcome::Skipped(describe_session_type(&standard_session_type(
                    &entry.value,
                )));
            }
        }
    } else if let Some(fields) = parse_legacy_session(&entry.value) {
        fields
    } else {
        return SessionOutcome::Unusable;
    };
    if host.is_empty() {
        return SessionOutcome::Unusable;
    }

    let resolved = store
        .lookup(&username, &host, port)
        .map(str::to_string)
        .or_else(|| {
            inline_password
                .as_deref()
                .and_then(|ciphertext| store.decrypt_inline(ciphertext, &username, &host))
        });

    let mut warnings = Vec::new();
    let has_unresolved =
        inline_password.is_some() || store.has_unresolved_password(&username, &host, port);

    let (auth_method, password_status) = match resolved {
        Some(password) => (
            SshImportAuthMethod::Password {
                password: Some(password),
            },
            "included",
        ),
        None if has_unresolved => {
            if store.master_password_missing {
                warnings.push(ImportWarning {
                    code: "mobaxterm_master_password_required".to_string(),
                    message: "These MobaXterm passwords are protected by a master password. \
                              Enter it to import credentials."
                        .to_string(),
                });
            } else if store.attempted {
                warnings.push(ImportWarning {
                    code: "mobaxterm_password_decrypt_failed".to_string(),
                    message: "A stored MobaXterm password could not be decrypted and was \
                              skipped."
                        .to_string(),
                });
            }
            (
                SshImportAuthMethod::Password { password: None },
                "unsupported",
            )
        }
        None => (SshImportAuthMethod::AutoPublicKey, "missing"),
    };

    SessionOutcome::Record(ImportRecord {
        id,
        importer_id: "mobaxterm".to_string(),
        source_label: "MobaXterm".to_string(),
        source_id: Some(source_id),
        kind: "ssh".to_string(),
        display_name: name.clone(),
        database: None,
        ssh: Some(SshImportRecord {
            name,
            host,
            port,
            username,
            group_path: group.map(str::to_string),
            auth_method,
            init_script: None,
            jump_server: None,
            proxy: None,
        }),
        port_forwarding: None,
        password_status: password_status.to_string(),
        warnings,
    })
}

// Standard MobaXterm session: `#109#0%HOST%PORT%USER%...`
// The icon number (`109` for SSH by default) is user-changeable, so the type is read
// from the first `%` field: 0 = SSH, 4 = RDP, 5 = VNC, 7 = SFTP, 11 = browser.
fn parse_standard_session(value: &str) -> Option<(String, Option<u16>, String, Option<String>)> {
    let outer = value.split('#').collect::<Vec<_>>();
    if outer.len() < 3 || !is_standard_prefix(value) {
        return None;
    }
    let fields = outer[2].split('%').collect::<Vec<_>>();
    let session_type = fields.first().copied().unwrap_or_default().trim();
    // 只收 SSH 与 SFTP：SFTP 的主机/端口/用户名/口令与 SSH 完全通用。
    // RDP / VNC / telnet / FTP 之类没有对应的导入记录类型，交给调用方汇总成警告。
    if session_type != SSH_SESSION_TYPE && session_type != SFTP_SESSION_TYPE {
        return None;
    }
    let host = fields
        .get(1)
        .copied()
        .unwrap_or_default()
        .trim()
        .to_string();
    let port = fields
        .get(2)
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .or(Some(DEFAULT_SSH_PORT));
    let username = fields
        .get(3)
        .copied()
        .unwrap_or_default()
        .trim()
        .to_string();
    let username = if username.is_empty() || username == "<default>" {
        String::new()
    } else {
        username
    };
    let inline_password = fields
        .get(4)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    Some((host, port, username, inline_password))
}

fn is_standard_prefix(value: &str) -> bool {
    let trimmed = value.trim();
    let rest = trimmed
        .strip_prefix(";")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    let rest = rest
        .strip_prefix("logout")
        .map(str::trim_start)
        .unwrap_or(rest);
    rest.starts_with('#')
        && rest[1..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .count()
            > 0
}

/// 会话串里第一组参数（`%` 分隔）的索引 0。
fn standard_session_type(value: &str) -> String {
    value
        .split('#')
        .nth(2)
        .unwrap_or_default()
        .split('%')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// 把会话类型编号变成能读的名字；编号与含义见 `parse_standard_session` 的注释。
fn describe_session_type(session_type: &str) -> String {
    match session_type {
        "0" | "7" => "SSH".to_string(),
        "4" => "RDP".to_string(),
        "5" => "VNC".to_string(),
        "11" => "browser".to_string(),
        "" => "unknown".to_string(),
        other => format!("type {other}"),
    }
}

// Older/legacy layouts accepted by MobaXterm, e.g.
// `deploy@legacy.example.com:2222#ssh` or `user@host#ssh#22`.
fn parse_legacy_session(value: &str) -> Option<(String, Option<u16>, String, Option<String>)> {
    let tokens = value
        .split('#')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let ssh_token_index = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("ssh"))?;

    let mut host = String::new();
    let mut username = String::new();
    let mut port = None;

    for token in tokens.iter().take(ssh_token_index) {
        if let Some(target) = parse_target(token) {
            host = target.host;
            username = target.username.unwrap_or_default();
            port = target.port;
            break;
        }
    }
    if host.is_empty() {
        return None;
    }
    if let Some(numeric) = tokens
        .iter()
        .skip(ssh_token_index + 1)
        .find_map(|token| token.parse::<u16>().ok())
    {
        port = Some(numeric);
    }
    Some((host, port, username, None))
}

struct ParsedTarget {
    host: String,
    username: Option<String>,
    port: Option<u16>,
}

fn parse_target(value: &str) -> Option<ParsedTarget> {
    let value = value
        .trim()
        .strip_prefix("ssh://")
        .unwrap_or_else(|| value.trim());
    let value = value.split('/').next().unwrap_or(value);
    let (user_info, host_port) = value
        .rsplit_once('@')
        .map_or((None, value), |(user, host)| (Some(user), host));
    let username = user_info
        .map(|user| user.split_once(':').map_or(user, |(user, _)| user))
        .map(str::to_string)
        .filter(|user| !user.is_empty());
    let (host, port) = parse_host_port(host_port)?;
    Some(ParsedTarget {
        host,
        username,
        port,
    })
}

fn parse_host_port(value: &str) -> Option<(String, Option<u16>)> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = suffix
            .strip_prefix(':')
            .and_then(|value| value.parse().ok());
        return Some((host.to_string(), port));
    }
    if value.matches(':').count() == 1 {
        let (host, port) = value.rsplit_once(':')?;
        if let Ok(port) = port.parse::<u16>() {
            return Some((host.to_string(), Some(port)));
        }
    }
    Some((value.to_string(), None))
}

fn session_label_and_group(key: &str) -> (String, Option<String>) {
    let parts = key.replace('\\', "/");
    let parts = parts.split('/').filter(|part| !part.is_empty());
    let mut label = String::new();
    let mut group_parts = Vec::new();
    for part in parts {
        if !label.is_empty() {
            group_parts.push(label.clone());
        }
        label = part.to_string();
    }
    let group = if group_parts.is_empty() {
        None
    } else {
        Some(group_parts.join("/"))
    };
    (label, group)
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(&bytes[2..], u16::from_le_bytes);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16(&bytes[2..], u16::from_be_bytes);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Some(text.trim_start_matches('\u{feff}').to_string());
    }
    // MobaXterm 的 `.mxtsessions` 官方格式是 CP1252，中文 Windows 上实际写的是 GBK，
    // 两者都不是合法 UTF-8。以前这里直接返回 `None`，调用方随即 `continue`，
    // 于是「会话名里带一个中文」就会让**整个文件**悄无声息地导不进任何东西。
    // 现在按 GB18030（GBK 超集）严格解一次，失败再退回 CP1252（恒成功）。
    if let Some(text) =
        encoding_rs::GB18030.decode_without_bom_handling_and_without_replacement(bytes)
    {
        return Some(text.into_owned());
    }
    let (text, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
    Some(text.into_owned())
}

fn decode_utf16(bytes: &[u8], from_bytes: fn([u8; 2]) -> u16) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| from_bytes(*chunk));
    std::char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

fn has_extension(path: &str, extension: &str) -> bool {
    path.rsplit_once('.')
        .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case(extension))
}

/// 记录 ID：可读 slug + 原始 `source_id` 的稳定短哈希。
///
/// 只用 slug 会把所有非 ASCII 字符塌成一个 `-`，于是「生产服务器」与「测试服务器」
/// 会算出同一个 ID —— 预览阶段按 ID 去重，后一条就被当成重复静默丢掉。哈希保证唯一，
/// slug 保证排查时还能看出是哪条会话。
fn record_id(source_id: &str) -> String {
    format!(
        "mobaxterm:{}-{:016x}",
        slug(source_id),
        stable_hash(source_id)
    )
}

/// FNV-1a 64 位：不引依赖，跨版本稳定（`DefaultHasher` 不保证）。
fn stable_hash(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "session".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 公开向量：MobaXterm 弱密钥的 credential 与 session 两条密文。
    const WEAK_CREDENTIAL_CIPHERTEXT: &str =
        "bSj4VWbHezNH3tTY9Nil2RzJX57p7/S6KqMw8VsiT/WH+I8p03pqnInAu";
    const WEAK_SESSION_CIPHERTEXT: &str =
        "F0+wuBvbe9qPW6ypiOeYHTHhKdShRc/nXaM1Ky1jeTfw46TzQoSesX9buGm0WW36yP4lhH70ZCHZpEo4wLJhIl1";

    #[test]
    fn parses_standard_ssh_session_with_group() {
        let ini = "[Bookmarks]\nSubRep=\nImgNum=42\n\
                   root-server=#109#0%root.example.com%22%<default>%%-1%\n\n\
                   [Bookmarks_1]\nSubRep=Production\\\\Linux\nImgNum=41\n\
                   web-server=#109#0%10.0.0.20%2222%deploy%%-1%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 2);
        let first = &records[0];
        assert_eq!(first.display_name, "root-server");
        assert_eq!(first.ssh.as_ref().unwrap().host, "root.example.com");
        assert_eq!(first.ssh.as_ref().unwrap().port, Some(22));
        assert_eq!(first.ssh.as_ref().unwrap().username, "");
        assert_eq!(first.ssh.as_ref().unwrap().group_path, None);
        let second = &records[1];
        assert_eq!(
            second.ssh.as_ref().unwrap().group_path.as_deref(),
            Some("Production/Linux")
        );
        assert_eq!(second.ssh.as_ref().unwrap().port, Some(2222));
    }

    #[test]
    fn imports_weak_key_password_from_passwords_section() {
        let ini = format!(
            "[Misc]\nMPSetAccount=DoubleSine\nMPSetComputer=ShadowSurface\n\n\
             [Passwords]\nssh:root@45.32.110.171={WEAK_SESSION_CIPHERTEXT}\n\n\
             [Bookmarks]\nSubRep=\nprod=#109#0%45.32.110.171%22%root%%-1%\n"
        );
        let record = &preview_records_from_sources_with_master_password(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            true,
            None,
        )[0];

        assert_eq!(record.password_status, "included");
        assert_eq!(
            record.ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password {
                password: Some("Lw3+cZ2s.w@U@f]U".to_string())
            }
        );
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn credentials_section_password_is_reused_by_username() {
        let ini = format!(
            "[Misc]\nSessionP=165821882556840\n\n\
             [Credentials]\nDeployAccount=Deploy:{WEAK_CREDENTIAL_CIPHERTEXT}\n\n\
             [Bookmarks]\nSubRep=\nprod=#109#0%prod.example.test%22%Deploy%%-1%\n"
        );
        let record = &preview_records_from_sources_with_master_password(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            true,
            None,
        )[0];

        assert_eq!(record.password_status, "included");
        assert_eq!(
            record.ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password {
                password: Some("HyperSine".to_string())
            }
        );
    }

    #[test]
    fn password_is_not_decrypted_unless_requested() {
        let ini = format!(
            "[Misc]\nSessionP=165821882556840\n\n\
             [Passwords]\nssh:root@45.32.110.171={WEAK_SESSION_CIPHERTEXT}\n\n\
             [Bookmarks]\nSubRep=\nprod=#109#0%45.32.110.171%22%root%%-1%\n"
        );
        let record = &preview_records_from_sources(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            false,
        )[0];

        assert_eq!(record.password_status, "unsupported");
        assert!(matches!(
            record.ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password { password: None }
        ));
        assert!(!serde_json::to_string(record).unwrap().contains("Lw3+cZ2s"));
    }

    #[test]
    fn master_password_protected_config_reports_that_it_needs_one() {
        let ini = format!(
            "[SessPass]\nSalt=abc\n\n\
             [Passwords]\nssh:root@45.32.110.171={WEAK_SESSION_CIPHERTEXT}\n\n\
             [Bookmarks]\nSubRep=\nprod=#109#0%45.32.110.171%22%root%%-1%\n"
        );
        let record = &preview_records_from_sources_with_master_password(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            true,
            None,
        )[0];

        assert_eq!(record.password_status, "unsupported");
        assert!(
            record
                .warnings
                .iter()
                .any(|warning| warning.code == "mobaxterm_master_password_required")
        );
    }

    #[test]
    fn master_password_config_decrypts_when_password_is_supplied() {
        // 密文来自公开的 HyperSine 向量，主密码为 12345678。
        let ini = "[SessPass]\nSalt=abc\n\n\
                   [Credentials]\nRootAccount=root:1du11XKQBOxud/FWh4ouWA==\n\n\
                   [Bookmarks]\nSubRep=\nprod=#109#0%prod.example.test%22%root%%-1%\n";
        let records = preview_records_from_sources_with_master_password(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            true,
            Some("12345678"),
        );

        assert_eq!(records[0].password_status, "included");
        assert_eq!(
            records[0].ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password {
                password: Some("Lw3+cZ2s.w@U@f]U".to_string())
            }
        );
    }

    #[test]
    fn wrong_master_password_leaves_the_password_unresolved() {
        let ini = "[SessPass]\nSalt=abc\n\n\
                   [Credentials]\nRootAccount=root:1du11XKQBOxud/FWh4ouWA==\n\n\
                   [Bookmarks]\nSubRep=\nprod=#109#0%prod.example.test%22%root%%-1%\n";
        let records = preview_records_from_sources_with_master_password(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            true,
            Some("wrong-password"),
        );

        assert_eq!(records[0].password_status, "unsupported");
        assert!(matches!(
            records[0].ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password { password: None }
        ));
    }

    #[test]
    fn skips_non_ssh_session_types() {
        let ini =
            "[Bookmarks]\nSubRep=\ntelnet=#91#4%10.0.0.5%23%\nssh=#109#0%10.0.0.6%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ssh.as_ref().unwrap().host, "10.0.0.6");
    }

    #[test]
    fn parses_legacy_user_host_layout() {
        let ini = "[Bookmarks]\nLegacy\\\\server=deploy@legacy.example.com:2222#ssh\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 1);
        let ssh = records[0].ssh.as_ref().unwrap();
        assert_eq!(ssh.host, "legacy.example.com");
        assert_eq!(ssh.port, Some(2222));
        assert_eq!(ssh.username, "deploy");
        assert_eq!(ssh.group_path.as_deref(), Some("Legacy"));
    }

    #[test]
    fn deduplicates_records_with_identical_ids() {
        let ini = "[Bookmarks]\nSubRep=\nserver=#109#0%prod.example.com%22%root%%\n";
        let records = preview_records_from_sources(
            vec![
                ("MobaXterm.ini".to_string(), ini.as_bytes()),
                ("MobaXterm.ini".to_string(), ini.as_bytes()),
            ],
            false,
        );

        assert_eq!(records.len(), 1);
    }

    #[test]
    fn recognizes_supported_paths() {
        assert!(is_supported_source_path(
            "C:/Users/x/Documents/MobaXterm/MobaXterm.ini"
        ));
        assert!(is_supported_source_path("sessions.MXTSESSIONS"));
        assert!(is_supported_source_path("Saved/Deck.moba"));
        assert!(!is_supported_source_path("random.ini"));
        // 声明的候选是**目录**，目录本身永远不该被当成源码文件读。
        assert!(!is_supported_source_path("%APPDATA%/MobaXterm"));
        assert!(!is_supported_source_path(
            "C:\\Users\\x\\Documents\\MobaXterm"
        ));
    }

    #[test]
    fn gbk_encoded_export_still_imports_and_keeps_chinese_names() {
        // `.mxtsessions` 官方是 CP1252，中文 Windows 上实际写 GBK：整份文件都不是
        // 合法 UTF-8。以前会被整份丢弃，现在必须照常导入。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"[Bookmarks]\r\nSubRep=\r\nImgNum=42\r\n");
        bytes.extend_from_slice(b"\xc9\xfa\xb2\xfa\xb7\xfe\xce\xf1\xc6\xf7");
        bytes.extend_from_slice(b"=#109#0%10.0.0.8%22%root%%-1%\r\n");

        let records = preview_records_from_sources(
            vec![("sessions.mxtsessions".to_string(), bytes.as_slice())],
            false,
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].display_name, "生产服务器");
        assert_eq!(records[0].ssh.as_ref().unwrap().host, "10.0.0.8");
    }

    #[test]
    fn cp1252_encoded_export_is_decoded_instead_of_dropped() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            b"[Bookmarks]\nSubRep=\nCaf\xe9=#109#0%cafe.example.test%22%root%%\n",
        );

        let records = preview_records_from_sources(
            vec![("sessions.mxtsessions".to_string(), bytes.as_slice())],
            false,
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].display_name, "Café");
    }

    #[test]
    fn imports_single_session_moba_file_without_section_header() {
        let records = preview_records_from_sources(
            vec![(
                "Deck.moba".to_string(),
                b"Deck=#109#0%192.168.137.40%22%deck%%0%0#MobaFont%10#0# #-1".as_slice(),
            )],
            false,
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].display_name, "Deck");
        assert_eq!(records[0].ssh.as_ref().unwrap().username, "deck");
    }

    #[test]
    fn imports_sftp_session_type_seven() {
        // 索引 0 = 7 是 SFTP：主机/端口/用户名/口令与 SSH 通用，按 SSH 导入。
        let ini = "[Bookmarks]\nSubRep=\ngw=#109#7%10.0.0.9%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ssh.as_ref().unwrap().host, "10.0.0.9");
    }

    #[test]
    fn chinese_session_names_are_kept_as_distinct_records() {
        // 曾经的 ID 只来自 slug，非 ASCII 字符全被吞掉：两条中文名算出同一个 ID，
        // 预览按 ID 去重 ⇒ 只剩一条。中文 MobaXterm 里这是最常见的丢记录方式。
        let ini = "[Bookmarks]\nSubRep=\n\
                   生产服务器=#109#0%10.0.0.1%22%root%%\n\
                   测试服务器=#109#0%10.0.0.2%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 2);
        assert_ne!(records[0].id, records[1].id);
        assert_eq!(records[0].display_name, "生产服务器");
        assert_eq!(records[1].display_name, "测试服务器");
        assert_eq!(records[1].ssh.as_ref().unwrap().host, "10.0.0.2");
    }

    #[test]
    fn same_session_name_in_two_folders_keeps_both() {
        // 同名会话可以分别存在于不同文件夹，ID 必须带上段落才不会互相吞掉。
        let ini = "[Bookmarks]\nSubRep=\nprod=#109#0%10.0.0.1%22%root%%\n\
                   [Bookmarks_1]\nSubRep=Staging\nprod=#109#0%10.0.0.2%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 2);
        assert_ne!(records[0].id, records[1].id);
        assert_eq!(
            records[1].ssh.as_ref().unwrap().group_path.as_deref(),
            Some("Staging")
        );
        assert_eq!(records[1].ssh.as_ref().unwrap().host, "10.0.0.2");
    }

    #[test]
    fn non_ssh_sessions_are_reported_instead_of_silently_dropped() {
        let ini = "[Bookmarks]\nSubRep=\n\
                   rdp-box=#91#4%10.0.0.20%3389%admin%\n\
                   vnc-box=#128#5%10.0.0.21%5900%\n\
                   ssh-box=#109#0%10.0.0.22%22%root%%\n";
        let report = preview_report_from_sources(
            vec![("MobaXterm.ini".to_string(), ini.as_bytes())],
            false,
            None,
        );

        assert_eq!(report.records.len(), 1);
        assert_eq!(
            report.skipped,
            vec![("RDP".to_string(), 1), ("VNC".to_string(), 1)]
        );
        let warning = report.records[0]
            .warnings
            .iter()
            .find(|warning| warning.code == "mobaxterm_non_ssh_sessions_skipped")
            .expect("skipped sessions warning");
        assert!(warning.message.contains("RDP ×1"));
        assert!(warning.message.contains("VNC ×1"));
    }

    #[test]
    fn imports_sections_written_as_bookmarks1() {
        let ini = "[Bookmarks1]\nSubRep=Prod\nImgNum=41\nweb=#109#0%10.0.0.10%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].ssh.as_ref().unwrap().group_path.as_deref(),
            Some("Prod")
        );
    }

    #[test]
    fn session_missing_host_is_skipped() {
        let ini = "[Bookmarks]\nSubRep=\nbroken=#109#0%%22%root%%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);
        assert!(records.is_empty());
    }

    #[test]
    fn registry_stored_passwords_are_reported_once() {
        let ini = "[Misc]\nPasswordsInRegistry=1\n\n\
                   [Bookmarks]\nSubRep=\nprod=#109#0%10.0.0.1%22%root%%-1%\n";
        let records = parse_ini_sessions("MobaXterm.ini", ini);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].password_status, "missing");
        assert!(
            records[0]
                .warnings
                .iter()
                .any(|warning| warning.code == "mobaxterm_passwords_in_windows_registry")
        );
    }

    #[test]
    fn password_key_matching_handles_scheme_prefixes() {
        assert_eq!(
            parse_password_key("ssh22:root@10.0.0.1"),
            (Some("root".to_string()), Some("10.0.0.1".to_string()))
        );
        assert_eq!(
            parse_password_key("root@10.0.0.1"),
            (Some("root".to_string()), Some("10.0.0.1".to_string()))
        );
        assert_eq!(parse_password_key("10.0.0.1"), (None, None));
    }
}
