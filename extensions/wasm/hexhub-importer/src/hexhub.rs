//! HexHub 资产导出 → Navop 导入记录。
//!
//! 契约来自 Desktop 客户端（`assets` 仓库类）：
//!
//! - 导出根是 `{version, time, data:[...], sign}`，每个元素是 Dexie `assets` 表的行；
//! - 元素的 `data` 是**模型 JSON 字符串**（`serializeData()` = `encryptData` + `serialize`）；
//! - `encryptData()` 只对两类资产动手：`SSH` 加密 `password` / `privateKey` /
//!   `jumpServer.password` / `jumpServer.privateKey`，`SSHPrivateKey` 加密
//!   `privateKey` / `password`。**数据库与 Redis 的口令不过是明文的**——别顺手解密，
//!   否则把「口令本身就是 base64 样子」的连接解成乱码。
//!
//! 所以这里能带全口令：`include_passwords` 只是「用户是否愿意把口令写进导入记录」的开关，
//! 不是能不能解的问题。

use serde_json::{Map, Value};
use std::collections::BTreeMap;

use crate::container::{self, AssetEntry, ContainerError};
use crate::decrypt::decrypt_secret;
use crate::model::{
    DatabaseImportRecord, DatabaseImportType, ImportRecord, ImportWarning,
    QuickCommandImportRecord, SshImportAuthMethod, SshImportRecord, SshJumpServerImportRecord,
};

pub(crate) const IMPORTER_ID: &str = "hexhub";
const SOURCE_LABEL: &str = "HexHub";
const DEFAULT_SSH_PORT: u16 = 22;

// 资产类型（客户端 `F` 枚举，元素上的 `type` 字段）。
const TYPE_SSH_PRIVATE_KEY: i64 = 1;
const TYPE_SSH: i64 = 2;
const TYPE_DB: i64 = 4;
const TYPE_QUICK_CMD: i64 = 5;
const TYPE_REDIS: i64 = 15;
const TYPE_SSH_PASSWORD_PAIR: i64 = 19;

// SSH 认证类型（客户端 `Ss` 枚举，SSH 模型上的 `authType`）。
const AUTH_PASSWORD: i64 = 0;
const AUTH_PRIVATE_KEY: i64 = 1;
const AUTH_INTERACTIVE: i64 = 2;
const AUTH_SERVER_PRIVATE_KEY: i64 = 3;
const AUTH_NONE: i64 = 4;
const AUTH_PASSWORD_PAIR: i64 = 5;
const AUTH_AGENT: i64 = 6;

// 数据库认证类型（客户端 `ms` 枚举，DB 模型上的 `authType`）。
const DB_AUTH_NONE: i64 = 2;

// 数据库类型（客户端 `z0` 枚举，DB 模型上的 `dbType`）。
const DB_MYSQL: i64 = 0;
const DB_POSTGRESQL: i64 = 1;
const DB_REDIS: i64 = 2;
const DB_MONGODB: i64 = 3;
const DB_SQLSERVER: i64 = 4;
const DB_ORACLE: i64 = 5;
const DB_SQLITE: i64 = 6;
const DB_CLICKHOUSE: i64 = 7;
const DB_MARIADB: i64 = 8;
const DB_TIDB: i64 = 9;
const DB_KINGBASE: i64 = 10;
const DB_OPENGAUSS: i64 = 11;
const DB_DORIS: i64 = 12;
const DB_OCEANBASE: i64 = 13;
const DB_DUCKDB: i64 = 14;
const DB_POLARDB: i64 = 15;

#[derive(Default)]
pub(crate) struct PreviewReport {
    pub(crate) records: Vec<ImportRecord>,
    /// 类型名 → 条数。导入协议只认 SSH / 数据库 / 端口转发 / 快捷命令 / 工作区，
    /// 其它资产（RDP、Docker、目录…）只能如实报数，否则用户只会觉得「少了几条」。
    pub(crate) skipped: BTreeMap<String, usize>,
    pub(crate) warnings: Vec<ImportWarning>,
}

impl PreviewReport {
    fn skip(&mut self, label: &str) {
        *self.skipped.entry(label.to_string()).or_default() += 1;
    }

    fn warn(&mut self, code: &str, message: String) {
        self.warnings.push(ImportWarning {
            code: code.to_string(),
            message,
        });
    }

    fn merge(&mut self, mut other: PreviewReport) {
        self.records.append(&mut other.records);
        for (label, count) in other.skipped {
            *self.skipped.entry(label).or_default() += count;
        }
        self.warnings.append(&mut other.warnings);
    }
}

/// 解析多个候选文件。同一个导出可能被扫描到两次（`~/Downloads` 与用户手选），
/// 记录 ID 里带了文件路径，重复文件会产生重复行，因此调用方先去重。
pub(crate) fn preview_report_from_exports<'a, I>(
    sources: I,
    include_passwords: bool,
) -> PreviewReport
where
    I: IntoIterator<Item = (String, &'a [u8])>,
{
    let mut report = PreviewReport::default();
    for (path, bytes) in sources {
        report.merge(preview_report_from_export(&path, bytes, include_passwords));
    }
    report
}

fn preview_report_from_export(path: &str, bytes: &[u8], include_passwords: bool) -> PreviewReport {
    let mut report = PreviewReport::default();
    let entries = match container::parse(bytes) {
        Ok(entries) => entries,
        Err(ContainerError::NotJson) => {
            report.warn(
                "hexhub_export_encrypted",
                format!(
                    "{path} is not plain JSON. HexHub encrypts the whole file when an export \
                     password is set; export again without a password to import it."
                ),
            );
            return report;
        }
        Err(ContainerError::NoAssets) => {
            report.warn(
                "hexhub_export_unrecognised",
                format!("{path} is JSON but carries no HexHub asset list."),
            );
            return report;
        }
    };
    build_records(path, &entries, include_passwords, &mut report);
    report
}

fn build_records(
    path: &str,
    entries: &[AssetEntry],
    include_passwords: bool,
    report: &mut PreviewReport,
) {
    let aux = collect_aux(entries, include_passwords);
    // 跳板机（`proxy.sshId`）引用的是另一条 SSH 资产，所以先把所有 SSH 资产解析好，
    // 免得记录顺序影响结果。
    let resolved: BTreeMap<String, ResolvedSsh> = entries
        .iter()
        .filter(|entry| entry.type_id == TYPE_SSH)
        .filter_map(|entry| {
            let data = entry.data.as_ref()?.as_object()?;
            Some((entry.id.clone(), resolve_ssh(data, &aux, include_passwords)))
        })
        .collect();

    for entry in entries {
        let Some(data) = entry.data.as_ref().and_then(Value::as_object) else {
            // 数据坏了不代表这条资产不存在：至少按类型记一次「跳过」，让用户知道。
            report.skip(asset_type_label(entry.type_id));
            continue;
        };
        match entry.type_id {
            TYPE_SSH => push_ssh_record(path, entry, data, &resolved, report),
            TYPE_DB => push_database_record(path, entry, data, include_passwords, report),
            TYPE_REDIS => push_redis_record(path, entry, data, include_passwords, report),
            TYPE_QUICK_CMD => push_quick_command_record(path, entry, data, report),
            // 私钥与口令对是辅助资产：被 SSH 记录引用，不单独成行。
            TYPE_SSH_PRIVATE_KEY | TYPE_SSH_PASSWORD_PAIR => {}
            other => report.skip(asset_type_label(other)),
        }
    }
}

// ---------------------------------------------------------------- 辅助资产索引

#[derive(Default)]
struct AuxAssets {
    private_keys: BTreeMap<String, PrivateKeyAsset>,
    password_pairs: BTreeMap<String, PasswordPairAsset>,
}

#[derive(Clone, Debug, Default)]
struct PrivateKeyAsset {
    file_name: Option<String>,
    /// 已解密的 OpenSSH/PEM 文本；未要求导入口令时是 `None`。
    material: Option<String>,
    passphrase: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct PasswordPairAsset {
    username: Option<String>,
    password: Option<String>,
}

fn collect_aux(entries: &[AssetEntry], include_passwords: bool) -> AuxAssets {
    let mut aux = AuxAssets::default();
    for entry in entries {
        let Some(data) = entry.data.as_ref().and_then(Value::as_object) else {
            continue;
        };
        match entry.type_id {
            TYPE_SSH_PRIVATE_KEY => {
                aux.private_keys.insert(
                    entry.id.clone(),
                    private_key_from_object(data, include_passwords),
                );
            }
            TYPE_SSH_PASSWORD_PAIR => {
                aux.password_pairs.insert(
                    entry.id.clone(),
                    PasswordPairAsset {
                        username: text(data, "username"),
                        // 口令对不在 `encryptFields` 名单里，导出文件里是明文。
                        password: text(data, "password"),
                    },
                );
            }
            _ => {}
        }
    }
    aux
}

fn private_key_from_object(
    object: &Map<String, Value>,
    include_passwords: bool,
) -> PrivateKeyAsset {
    PrivateKeyAsset {
        file_name: text(object, "filename").or_else(|| text(object, "name")),
        material: include_passwords
            .then(|| text(object, "privateKey").map(|raw| plain_or_raw(&raw)))
            .flatten(),
        passphrase: include_passwords
            .then(|| text(object, "password").map(|raw| plain_or_raw(&raw)))
            .flatten(),
    }
}

/// SSH 资产里的 `privateKey` 可能是：
/// 1. 内联 PEM 的密文（字符串 → `AES(PEM)`）；
/// 2. 整个私钥对象的密文（对象 → `AES(JSON.stringify(obj))`，因为 `encryptFields`
///    对非字符串值是先序列化再加密）。
fn inline_private_key(raw: &Value, include_passwords: bool) -> Option<PrivateKeyAsset> {
    match raw {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            let plain = plain_or_raw(trimmed);
            if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(&plain) {
                return Some(private_key_from_object(&object, include_passwords));
            }
            Some(PrivateKeyAsset {
                file_name: None,
                material: include_passwords.then_some(plain),
                passphrase: None,
            })
        }
        Value::Object(object) => Some(private_key_from_object(object, include_passwords)),
        _ => None,
    }
}

/// 密文就解密，解不开就当成明文——老备份/手工改过的文件里确实有明文。
fn plain_or_raw(value: &str) -> String {
    decrypt_secret(value).unwrap_or_else(|| value.trim().to_string())
}

// ---------------------------------------------------------------- SSH

#[derive(Clone, Debug)]
struct ResolvedSsh {
    host: String,
    port: u16,
    username: String,
    auth: SshImportAuthMethod,
    password_status: &'static str,
    warnings: Vec<ImportWarning>,
}

fn resolve_ssh(data: &Map<String, Value>, aux: &AuxAssets, include_passwords: bool) -> ResolvedSsh {
    let host = text(data, "host").unwrap_or_default();
    let port = number(data, "port")
        .and_then(|port| u16::try_from(port).ok())
        .unwrap_or(DEFAULT_SSH_PORT);
    let mut username = text(data, "user").unwrap_or_default();
    let raw_password = text(data, "password");
    let auth_type = number(data, "authType").unwrap_or(AUTH_PASSWORD);
    let mut warnings = Vec::new();

    let (auth, password_status) = match auth_type {
        AUTH_PASSWORD | AUTH_INTERACTIVE => {
            let password = resolve_secret(raw_password.as_deref(), include_passwords);
            let status = password_status(raw_password.is_some(), password.is_some());
            // keyboard-interactive 与「口令认证」在 Navop 侧是同一个存储形态。
            (SshImportAuthMethod::Password { password }, status)
        }
        AUTH_PRIVATE_KEY => resolve_key_auth(data, aux, include_passwords, &mut warnings),
        AUTH_PASSWORD_PAIR => {
            match text(data, "passwordPairId").and_then(|id| aux.password_pairs.get(&id)) {
                Some(pair) => {
                    if let Some(pair_username) = pair.username.as_deref() {
                        username = pair_username.to_string();
                    }
                    let password = resolve_secret(pair.password.as_deref(), include_passwords);
                    let status = password_status(pair.password.is_some(), password.is_some());
                    (SshImportAuthMethod::Password { password }, status)
                }
                None => {
                    warnings.push(ImportWarning {
                        code: "hexhub_password_pair_missing".to_string(),
                        message: "This session uses a shared account asset that is not part of \
                                  the export; set the account again after import."
                            .to_string(),
                    });
                    (
                        SshImportAuthMethod::Password { password: None },
                        password_status(raw_password.is_some(), false),
                    )
                }
            }
        }
        AUTH_AGENT => (SshImportAuthMethod::Agent, "missing"),
        AUTH_NONE => (
            SshImportAuthMethod::Password { password: None },
            if raw_password.is_some() {
                "unsupported"
            } else {
                "missing"
            },
        ),
        AUTH_SERVER_PRIVATE_KEY => {
            warnings.push(ImportWarning {
                code: "hexhub_auth_method_unsupported".to_string(),
                message: "This session authenticates with a server-side private key, which has no \
                          Navop equivalent; configure the authentication again after import."
                    .to_string(),
            });
            (
                SshImportAuthMethod::Password { password: None },
                "unsupported",
            )
        }
        _ => {
            warnings.push(ImportWarning {
                code: "hexhub_auth_method_unknown".to_string(),
                message: format!(
                    "HexHub auth type {auth_type} is not recognised; configure the \
                     authentication again after import."
                ),
            });
            (
                SshImportAuthMethod::Password { password: None },
                "unsupported",
            )
        }
    };

    ResolvedSsh {
        host,
        port,
        username,
        auth,
        password_status,
        warnings,
    }
}

fn resolve_key_auth(
    data: &Map<String, Value>,
    aux: &AuxAssets,
    include_passwords: bool,
    warnings: &mut Vec<ImportWarning>,
) -> (SshImportAuthMethod, &'static str) {
    let key = text(data, "privateKeyId")
        .and_then(|id| aux.private_keys.get(&id).cloned())
        .or_else(|| {
            data.get("privateKey")
                .and_then(|raw| inline_private_key(raw, include_passwords))
        });
    let Some(key) = key else {
        warnings.push(ImportWarning {
            code: "hexhub_private_key_missing".to_string(),
            message: "This session uses a private-key asset that is not part of the export; \
                      choose the key again after import."
                .to_string(),
        });
        return (
            SshImportAuthMethod::Password { password: None },
            "unsupported",
        );
    };

    // 私钥本身也是机密：没勾「导入密码」时不把它写进记录。
    if !include_passwords {
        return (
            SshImportAuthMethod::Password { password: None },
            "unsupported",
        );
    }

    match key
        .material
        .as_deref()
        .map(str::trim)
        .filter(|material| !material.is_empty())
    {
        Some(material) => (
            SshImportAuthMethod::PrivateKeyMaterial {
                private_key: Some(material.to_string()),
                passphrase: key.passphrase,
                file_name_hint: key.file_name,
            },
            "included",
        ),
        None => {
            warnings.push(ImportWarning {
                code: "hexhub_private_key_unreadable".to_string(),
                message: "The private key of this session could not be read from the export; \
                          choose the key again after import."
                    .to_string(),
            });
            (
                SshImportAuthMethod::Password { password: None },
                "unsupported",
            )
        }
    }
}

fn push_ssh_record(
    path: &str,
    entry: &AssetEntry,
    data: &Map<String, Value>,
    resolved: &BTreeMap<String, ResolvedSsh>,
    report: &mut PreviewReport,
) {
    let Some(session) = resolved.get(&entry.id) else {
        report.skip("SSH (unreadable)");
        return;
    };
    if session.host.is_empty() {
        report.skip("SSH (no host)");
        return;
    }

    let name = if entry.name.is_empty() {
        session.host.clone()
    } else {
        entry.name.clone()
    };
    let (jump_server, mut warnings) = resolve_jump_server(data, resolved);
    warnings.extend(session.warnings.iter().cloned());
    let source_id = format!("{path}#{}", entry.id);

    report.records.push(ImportRecord {
        id: record_id(&source_id),
        importer_id: IMPORTER_ID.to_string(),
        source_label: SOURCE_LABEL.to_string(),
        source_id: Some(source_id),
        kind: "ssh".to_string(),
        display_name: name.clone(),
        database: None,
        ssh: Some(SshImportRecord {
            name,
            host: session.host.clone(),
            port: Some(session.port),
            username: session.username.clone(),
            group_path: group_path(&entry.dir_path),
            auth_method: session.auth.clone(),
            init_script: text(data, "initCmd"),
            jump_server,
            // `proxy.method` 的取值没有可靠的公开定义，猜错会把连接导向错误端口，
            // 所以 SOCKS5/HTTP 代理不导入，只用警告说明。
            proxy: None,
        }),
        quick_command: None,
        password_status: session.password_status.to_string(),
        warnings,
    });
}

fn resolve_jump_server(
    data: &Map<String, Value>,
    resolved: &BTreeMap<String, ResolvedSsh>,
) -> (Option<SshJumpServerImportRecord>, Vec<ImportWarning>) {
    let Some(proxy) = data.get("proxy").and_then(Value::as_object) else {
        return (None, Vec::new());
    };
    let ssh_id = text(proxy, "sshId").unwrap_or_default();
    if !ssh_id.is_empty() {
        return match resolved.get(&ssh_id) {
            Some(jump) if !jump.host.is_empty() => (
                Some(SshJumpServerImportRecord {
                    host: jump.host.clone(),
                    port: jump.port,
                    username: jump.username.clone(),
                    auth_method: jump.auth.clone(),
                }),
                Vec::new(),
            ),
            _ => (
                None,
                vec![ImportWarning {
                    code: "hexhub_jump_server_missing".to_string(),
                    message: "This session reaches the host through another SSH connection that \
                              is not part of the export; configure the jump server again after \
                              import."
                        .to_string(),
                }],
            ),
        };
    }

    let method = number(proxy, "method").unwrap_or(0);
    let host = text(proxy, "host").unwrap_or_default();
    if method != 0 && !host.is_empty() {
        return (
            None,
            vec![ImportWarning {
                code: "hexhub_proxy_not_imported".to_string(),
                message: format!(
                    "This session uses a {host}:{} proxy, which is not imported; configure the \
                     proxy again after import.",
                    number(proxy, "port").unwrap_or_default()
                ),
            }],
        );
    }
    (None, Vec::new())
}

// ---------------------------------------------------------------- 数据库

fn push_database_record(
    path: &str,
    entry: &AssetEntry,
    data: &Map<String, Value>,
    include_passwords: bool,
    report: &mut PreviewReport,
) {
    let db_type = number(data, "dbType").unwrap_or(-1);
    let Some(mapping) = database_mapping(db_type) else {
        report.skip(&format!("Database ({})", database_engine_label(db_type)));
        return;
    };

    let name = database_name(entry, data);
    let raw_password = text(data, "password");
    let auth_type = number(data, "authType").unwrap_or(0);
    let password = if auth_type == DB_AUTH_NONE {
        None
    } else {
        resolve_secret(raw_password.as_deref(), include_passwords)
    };
    let status = if auth_type == DB_AUTH_NONE {
        "missing"
    } else {
        password_status(raw_password.is_some(), password.is_some())
    };

    let mut warnings = Vec::new();
    if let Some(engine) = mapping.compatible_with {
        warnings.push(ImportWarning {
            code: "hexhub_database_type_remapped".to_string(),
            message: format!(
                "{engine} has no dedicated Navop connection type and was imported as {}; \
                 credentials and host are unchanged.",
                mapping.database_type_label
            ),
        });
    }
    if number(data, "enableSsh").unwrap_or(0) != 0 && text(data, "sshId").is_some() {
        warnings.push(ImportWarning {
            code: "hexhub_database_ssh_tunnel_not_imported".to_string(),
            message: "This database is reached through an SSH tunnel, which is not imported; \
                      configure the tunnel again after import."
                .to_string(),
        });
    }

    let source_id = format!("{path}#{}", entry.id);
    report.records.push(ImportRecord {
        id: record_id(&source_id),
        importer_id: IMPORTER_ID.to_string(),
        source_label: SOURCE_LABEL.to_string(),
        source_id: Some(source_id),
        kind: "database".to_string(),
        display_name: name.clone(),
        database: Some(DatabaseImportRecord {
            database_type: mapping.database_type,
            name,
            host: text(data, "host").unwrap_or_else(|| "localhost".to_string()),
            port: number(data, "port").and_then(|port| u16::try_from(port).ok()),
            username: text(data, "user").unwrap_or_default(),
            password,
            database: text(data, "defaultDb"),
            // `params` 的键名是 HexHub 自己的（sslMode、charSet…），直接塞进 Navop 的
            // 连接串可能被驱动当成非法参数，所以只导入结构化的那部分。
            extra_params: BTreeMap::new(),
        }),
        ssh: None,
        quick_command: None,
        password_status: status.to_string(),
        warnings,
    });
}

/// HexHub 的 Redis 是独立资产类型（`type = 15`），模型字段和 DB 不同。
fn push_redis_record(
    path: &str,
    entry: &AssetEntry,
    data: &Map<String, Value>,
    include_passwords: bool,
    report: &mut PreviewReport,
) {
    let name = database_name(entry, data);
    let raw_password = text(data, "password");
    let password = resolve_secret(raw_password.as_deref(), include_passwords);
    let status = password_status(raw_password.is_some(), password.is_some());
    let source_id = format!("{path}#{}", entry.id);

    report.records.push(ImportRecord {
        id: record_id(&source_id),
        importer_id: IMPORTER_ID.to_string(),
        source_label: SOURCE_LABEL.to_string(),
        source_id: Some(source_id),
        kind: "database".to_string(),
        display_name: name.clone(),
        database: Some(DatabaseImportRecord {
            database_type: DatabaseImportType::External {
                id: "redis".to_string(),
            },
            name,
            host: text(data, "host").unwrap_or_else(|| "localhost".to_string()),
            port: number(data, "port")
                .and_then(|port| u16::try_from(port).ok())
                .or(Some(6379)),
            username: text(data, "user").unwrap_or_default(),
            password,
            database: text(data, "defaultDb"),
            extra_params: BTreeMap::new(),
        }),
        ssh: None,
        quick_command: None,
        password_status: status.to_string(),
        warnings: Vec::new(),
    });
}

struct DatabaseMapping {
    database_type: DatabaseImportType,
    database_type_label: &'static str,
    /// 源引擎（HexHub 有、Navop 没有独立类型时）——非空表示做过协议兼容降级。
    compatible_with: Option<&'static str>,
}

fn database_mapping(db_type: i64) -> Option<DatabaseMapping> {
    let (database_type, label) = match db_type {
        DB_MYSQL => (DatabaseImportType::MySql, "MySQL"),
        DB_POSTGRESQL => (DatabaseImportType::PostgreSql, "PostgreSQL"),
        DB_SQLSERVER => (DatabaseImportType::SqlServer, "SQL Server"),
        DB_ORACLE => (DatabaseImportType::Oracle, "Oracle"),
        DB_SQLITE => (DatabaseImportType::Sqlite, "SQLite"),
        DB_CLICKHOUSE => (DatabaseImportType::ClickHouse, "ClickHouse"),
        DB_DUCKDB => (DatabaseImportType::DuckDb, "DuckDB"),
        DB_MONGODB => (
            DatabaseImportType::External {
                id: "mongodb".to_string(),
            },
            "MongoDB",
        ),
        DB_REDIS => (
            DatabaseImportType::External {
                id: "redis".to_string(),
            },
            "Redis",
        ),
        // 下面这些引擎走协议兼容的基类型：MariaDB/TiDB/Doris/OceanBase/PolarDB 说
        // MySQL 协议，KingbaseES/OpenGauss 说 PostgreSQL 协议。降级比丢记录好，
        // 但要在记录上留一句说明。
        DB_MARIADB => (DatabaseImportType::MySql, "MySQL"),
        DB_TIDB => (DatabaseImportType::MySql, "MySQL"),
        DB_DORIS => (DatabaseImportType::MySql, "MySQL"),
        DB_OCEANBASE => (DatabaseImportType::MySql, "MySQL"),
        DB_POLARDB => (DatabaseImportType::MySql, "MySQL"),
        DB_KINGBASE => (DatabaseImportType::PostgreSql, "PostgreSQL"),
        DB_OPENGAUSS => (DatabaseImportType::PostgreSql, "PostgreSQL"),
        _ => return None,
    };
    let compatible_with = match db_type {
        DB_MARIADB => Some("MariaDB"),
        DB_TIDB => Some("TiDB"),
        DB_DORIS => Some("Doris"),
        DB_OCEANBASE => Some("OceanBase"),
        DB_POLARDB => Some("PolarDB"),
        DB_KINGBASE => Some("KingbaseES"),
        DB_OPENGAUSS => Some("OpenGauss"),
        _ => None,
    };
    Some(DatabaseMapping {
        database_type,
        database_type_label: label,
        compatible_with,
    })
}

fn database_engine_label(db_type: i64) -> &'static str {
    match db_type {
        16 => "Dameng",
        4095 => "no engine",
        _ => "unknown engine",
    }
}

// ---------------------------------------------------------------- 快捷命令

fn push_quick_command_record(
    path: &str,
    entry: &AssetEntry,
    data: &Map<String, Value>,
    report: &mut PreviewReport,
) {
    let Some(command) = text(data, "cmd") else {
        report.skip("Quick command (empty)");
        return;
    };
    let name = if entry.name.is_empty() {
        command.clone()
    } else {
        entry.name.clone()
    };
    let source_id = format!("{path}#{}", entry.id);

    report.records.push(ImportRecord {
        id: record_id(&source_id),
        importer_id: IMPORTER_ID.to_string(),
        source_label: SOURCE_LABEL.to_string(),
        source_id: Some(source_id),
        // 注意是 `quick_command`：宿主 `ImportRecordKind` 是 `rename_all = "snake_case"`，
        // 写成 `quick-command` 会在反序列化时整批失败（manifest 的 `outputKinds` 才是短横线）。
        kind: "quick_command".to_string(),
        display_name: name.clone(),
        database: None,
        ssh: None,
        quick_command: Some(QuickCommandImportRecord {
            name,
            command,
            group_name: group_path(&entry.dir_path),
            shortcut: None,
            description: text(data, "description"),
            sort_order: 0,
            connection_source_id: None,
        }),
        password_status: "missing".to_string(),
        warnings: Vec::new(),
    });
}

// ---------------------------------------------------------------- 公共小工具

/// 口令状态与宿主 `PasswordImportStatus` 对齐：
/// `included` 已带上、`missing` 源里没有、`unsupported` 源里有但没带过来。
fn password_status(present: bool, included: bool) -> &'static str {
    if included {
        "included"
    } else if present {
        "unsupported"
    } else {
        "missing"
    }
}

fn resolve_secret(raw: Option<&str>, include_passwords: bool) -> Option<String> {
    let raw = raw?;
    if raw.is_empty() || !include_passwords {
        return None;
    }
    Some(plain_or_raw(raw))
}

/// `/生产/数据库/` → `生产/数据库`；根目录（`/`）没有分组。
fn group_path(dir_path: &str) -> Option<String> {
    let trimmed = dir_path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .split('/')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn database_name(entry: &AssetEntry, data: &Map<String, Value>) -> String {
    let name = text(data, "name").unwrap_or_else(|| entry.name.clone());
    if name.is_empty() {
        text(data, "host").unwrap_or_else(|| "connection".to_string())
    } else {
        name
    }
}

fn asset_type_label(type_id: i64) -> &'static str {
    match type_id {
        0 => "Folder",
        1 => "SSH private key",
        3 => "FTP",
        6 => "Saved query",
        7 => "Docker",
        8 => "Docker registry",
        9 => "Settings",
        10 => "Hotkey",
        11 => "Quick command group",
        12 => "RDP",
        13 => "VNC",
        14 => "Repository source",
        16 => "Local terminal",
        17 => "Serial",
        18 => "Telnet",
        19 => "SSH account",
        20 => "SSH tunnel",
        21 => "LLM provider",
        _ => "Unknown asset",
    }
}

fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
    match object.get(key)? {
        Value::String(value) => {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn number(object: &Map<String, Value>, key: &str) -> Option<i64> {
    match object.get(key)? {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.trim().parse::<i64>().ok(),
        Value::Bool(value) => Some(i64::from(*value)),
        _ => None,
    }
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
        "connection".to_string()
    } else {
        out
    }
}

/// 预览层只按 `id` 去重（`seen.insert(record.id)`）：`slug` 是有损的（中文名会全变成
/// `-`），必须再挂一个稳定哈希，否则同名/中文记录会被静默吞掉。
fn record_id(source_id: &str) -> String {
    format!("hexhub:{}-{:016x}", slug(source_id), stable_hash(source_id))
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 与 `decrypt.rs` 同一组固定密钥：HexHub 客户端就是这么加密的。
    fn encrypt(plain: &str) -> String {
        use aes::Aes128;
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

        let cipher =
            cbc::Encryptor::<Aes128>::new(b"CsN#&Uc!aOUQbh&B".into(), b"w6KQ^MPlEx*mfHcb".into());
        STANDARD.encode(cipher.encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes()))
    }

    fn preview(export: Value, include_passwords: bool) -> PreviewReport {
        let bytes = serde_json::to_vec(&export).expect("export should serialize");
        preview_report_from_exports(
            vec![("HexHub-Assets.json".to_string(), bytes.as_slice())],
            include_passwords,
        )
    }

    fn asset(id: &str, type_id: i64, dir_path: &str, name: &str, data: Value) -> Value {
        json!({
            "id": id,
            "type": type_id,
            "dirPath": dir_path,
            "name": name,
            // 真实导出里 `data` 是 JSON 字符串，这里顺便覆盖那条路径。
            "data": serde_json::to_string(&data).expect("model should serialize"),
        })
    }

    fn ssh_model(host: &str, extras: Value) -> Value {
        let mut model = json!({
            "host": host,
            "port": 2222,
            "user": "deploy",
            "authType": AUTH_PASSWORD,
        });
        let object = model.as_object_mut().unwrap();
        for (key, value) in extras.as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        model
    }

    #[test]
    fn imports_ssh_session_with_encrypted_password() {
        let export = json!({
            "version": 1,
            "data": [asset(
                "ssh-1",
                TYPE_SSH,
                "/生产/跳板/",
                "prod-web",
                ssh_model(
                    "10.0.0.1",
                    json!({
                        "password": encrypt("p@ssw0rd!"),
                        "initCmd": "cd /srv",
                    }),
                ),
            )],
        });

        let report = preview(export, true);

        assert_eq!(1, report.records.len());
        assert!(report.skipped.is_empty());
        let record = &report.records[0];
        assert_eq!("ssh", record.kind);
        assert_eq!("hexhub", record.importer_id);
        assert_eq!("HexHub", record.source_label);
        assert_eq!("prod-web", record.display_name);
        assert_eq!("included", record.password_status);
        assert_eq!(
            Some("HexHub-Assets.json#ssh-1"),
            record.source_id.as_deref()
        );
        let ssh = record.ssh.as_ref().unwrap();
        assert_eq!("10.0.0.1", ssh.host);
        assert_eq!(Some(2222), ssh.port);
        assert_eq!("deploy", ssh.username);
        assert_eq!(Some("生产/跳板"), ssh.group_path.as_deref());
        assert_eq!(Some("cd /srv"), ssh.init_script.as_deref());
        assert_eq!(
            SshImportAuthMethod::Password {
                password: Some("p@ssw0rd!".to_string())
            },
            ssh.auth_method
        );
    }

    #[test]
    fn does_not_carry_password_when_not_requested() {
        let export = json!({
            "data": [asset(
                "ssh-1",
                TYPE_SSH,
                "/",
                "prod-web",
                ssh_model("10.0.0.1", json!({ "password": encrypt("p@ssw0rd!") })),
            )],
        });

        let report = preview(export, false);

        let record = &report.records[0];
        assert_eq!("unsupported", record.password_status);
        assert!(matches!(
            record.ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password { password: None }
        ));
        assert!(!serde_json::to_string(record).unwrap().contains("p@ssw0rd!"));
    }

    #[test]
    fn imports_private_key_from_referenced_asset() {
        let export = json!({
            "data": [
                asset(
                    "key-1",
                    TYPE_SSH_PRIVATE_KEY,
                    "/",
                    "deploy.pem",
                    json!({
                        "name": "deploy",
                        "filename": "deploy.pem",
                        "privateKey": encrypt("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"),
                        "password": encrypt("key-pass"),
                    }),
                ),
                asset(
                    "ssh-1",
                    TYPE_SSH,
                    "/",
                    "key-host",
                    ssh_model("10.0.0.2", json!({ "authType": AUTH_PRIVATE_KEY, "privateKeyId": "key-1" })),
                ),
            ],
        });

        let report = preview(export, true);

        assert_eq!(1, report.records.len());
        let record = &report.records[0];
        assert_eq!("included", record.password_status);
        assert_eq!(
            SshImportAuthMethod::PrivateKeyMaterial {
                private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nabc".to_string()),
                passphrase: Some("key-pass".to_string()),
                file_name_hint: Some("deploy.pem".to_string()),
            },
            record.ssh.as_ref().unwrap().auth_method
        );
    }

    #[test]
    fn private_key_is_not_embedded_when_passwords_are_skipped() {
        let export = json!({
            "data": [
                asset(
                    "key-1",
                    TYPE_SSH_PRIVATE_KEY,
                    "/",
                    "deploy.pem",
                    json!({ "privateKey": encrypt("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n") }),
                ),
                asset(
                    "ssh-1",
                    TYPE_SSH,
                    "/",
                    "key-host",
                    ssh_model("10.0.0.2", json!({ "authType": AUTH_PRIVATE_KEY, "privateKeyId": "key-1" })),
                ),
            ],
        });

        let report = preview(export, false);

        let record = &report.records[0];
        assert_eq!("unsupported", record.password_status);
        assert!(matches!(
            record.ssh.as_ref().unwrap().auth_method,
            SshImportAuthMethod::Password { password: None }
        ));
        assert!(
            !serde_json::to_string(record)
                .unwrap()
                .contains("BEGIN OPENSSH PRIVATE KEY")
        );
    }

    #[test]
    fn resolves_jump_server_from_referenced_ssh_asset() {
        let export = json!({
            "data": [
                asset(
                    "bastion",
                    TYPE_SSH,
                    "/",
                    "bastion",
                    ssh_model("10.0.0.9", json!({ "port": 22, "user": "ops", "password": encrypt("bastion-pass") })),
                ),
                asset(
                    "target",
                    TYPE_SSH,
                    "/",
                    "target",
                    ssh_model(
                        "10.0.0.10",
                        json!({ "proxy": { "method": 3, "host": "127.0.0.1", "port": 7890, "user": "", "password": "", "sshId": "bastion", "timeout": 5 } }),
                    ),
                ),
            ],
        });

        let report = preview(export, true);

        assert_eq!(2, report.records.len());
        let target = report
            .records
            .iter()
            .find(|record| record.display_name == "target")
            .expect("target session should be imported");
        let jump = target
            .ssh
            .as_ref()
            .unwrap()
            .jump_server
            .as_ref()
            .expect("jump server should be resolved");
        assert_eq!("10.0.0.9", jump.host);
        assert_eq!(22, jump.port);
        assert_eq!("ops", jump.username);
        assert_eq!(
            SshImportAuthMethod::Password {
                password: Some("bastion-pass".to_string())
            },
            jump.auth_method
        );
    }

    #[test]
    fn warns_when_proxy_is_not_importable() {
        let export = json!({
            "data": [asset(
                "ssh-1",
                TYPE_SSH,
                "/",
                "proxied",
                ssh_model(
                    "10.0.0.3",
                    json!({ "proxy": { "method": 1, "host": "127.0.0.1", "port": 7890, "user": "", "password": "", "sshId": "", "timeout": 5 } }),
                ),
            )],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        assert!(record.ssh.as_ref().unwrap().proxy.is_none());
        assert!(
            record
                .warnings
                .iter()
                .any(|warning| warning.code == "hexhub_proxy_not_imported")
        );
    }

    #[test]
    fn imports_mysql_database_with_plaintext_password() {
        // DB 资产的口令不在 `encryptFields` 名单里，导出文件里就是明文。
        let export = json!({
            "data": [asset(
                "db-1",
                TYPE_DB,
                "/生产/数据库/",
                "orders",
                json!({
                    "name": "orders",
                    "host": "db.example.test",
                    "port": 3307,
                    "user": "app",
                    "password": "db-pass",
                    "dbType": DB_MYSQL,
                    "authType": 0,
                    "defaultDb": "orders",
                }),
            )],
        });

        let report = preview(export, true);

        assert_eq!(1, report.records.len());
        let record = &report.records[0];
        assert_eq!("database", record.kind);
        assert_eq!("included", record.password_status);
        let database = record.database.as_ref().unwrap();
        assert_eq!(DatabaseImportType::MySql, database.database_type);
        assert_eq!("db.example.test", database.host);
        assert_eq!(Some(3307), database.port);
        assert_eq!("app", database.username);
        assert_eq!(Some("db-pass"), database.password.as_deref());
        assert_eq!(Some("orders"), database.database.as_deref());
    }

    #[test]
    fn remaps_protocol_compatible_engines_and_warns() {
        let export = json!({
            "data": [asset(
                "db-1",
                TYPE_DB,
                "/",
                "mariadb",
                json!({
                    "name": "mariadb",
                    "host": "db.example.test",
                    "port": 3306,
                    "user": "root",
                    "dbType": DB_MARIADB,
                    "authType": 0,
                }),
            )],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        assert_eq!(
            DatabaseImportType::MySql,
            record.database.as_ref().unwrap().database_type
        );
        assert!(
            record
                .warnings
                .iter()
                .any(|warning| warning.code == "hexhub_database_type_remapped")
        );
    }

    #[test]
    fn imports_redis_asset_as_native_driver() {
        let export = json!({
            "data": [asset(
                "redis-1",
                TYPE_REDIS,
                "/",
                "cache",
                json!({
                    "host": "redis.example.test",
                    "port": 6379,
                    "user": "default",
                    "password": "redis-pass",
                    "defaultDb": "3",
                }),
            )],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        let database = record.database.as_ref().unwrap();
        assert_eq!(
            DatabaseImportType::External {
                id: "redis".to_string()
            },
            database.database_type
        );
        assert_eq!(Some("3"), database.database.as_deref());
        assert_eq!(Some("redis-pass"), database.password.as_deref());
    }

    #[test]
    fn imports_quick_commands_with_folder_as_group() {
        let export = json!({
            "data": [asset(
                "cmd-1",
                TYPE_QUICK_CMD,
                "/运维/巡检/",
                "磁盘",
                json!({ "name": "磁盘", "cmd": "df -h", "description": "查看磁盘占用" }),
            )],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        assert_eq!("quick_command", record.kind);
        let quick_command = record.quick_command.as_ref().unwrap();
        assert_eq!("df -h", quick_command.command);
        assert_eq!(Some("运维/巡检"), quick_command.group_name.as_deref());
        assert_eq!(Some("查看磁盘占用"), quick_command.description.as_deref());
        assert_eq!("missing", record.password_status);
    }

    #[test]
    fn reports_asset_types_the_protocol_cannot_carry() {
        let export = json!({
            "data": [
                asset("rdp-1", 12, "/", "win", json!({ "host": "10.0.0.5", "port": 3389 })),
                asset("vnc-1", 13, "/", "vnc", json!({ "host": "10.0.0.6", "port": 5900 })),
                asset("telnet-1", 18, "/", "switch", json!({ "host": "10.0.0.7" })),
                asset("dir-1", 0, "/", "生产", json!({})),
            ],
        });

        let report = preview(export, true);

        assert!(report.records.is_empty());
        assert_eq!(Some(&1), report.skipped.get("RDP"));
        assert_eq!(Some(&1), report.skipped.get("VNC"));
        assert_eq!(Some(&1), report.skipped.get("Telnet"));
        assert_eq!(Some(&1), report.skipped.get("Folder"));
    }

    #[test]
    fn reports_password_protected_exports() {
        let bytes = [0x9c, 0x2f, 0x00, 0xff];
        let report = preview_report_from_exports(
            vec![("HexHub-Assets.json".to_string(), bytes.as_slice())],
            true,
        );

        assert!(report.records.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.code == "hexhub_export_encrypted")
        );
    }

    #[test]
    fn chinese_names_and_same_names_in_two_folders_keep_distinct_ids() {
        let export = json!({
            "data": [
                asset("a", TYPE_SSH, "/生产/", "服务器", ssh_model("10.0.0.1", json!({}))),
                asset("b", TYPE_SSH, "/测试/", "服务器", ssh_model("10.0.0.2", json!({}))),
            ],
        });

        let report = preview(export.clone(), true);

        assert_eq!(2, report.records.len());
        assert_ne!(report.records[0].id, report.records[1].id);
        assert_ne!(report.records[0].source_id, report.records[1].source_id);
        // 同一个导出解析两遍必须给出同样的 id（预览与落库要对得上）。
        let again = preview(export, true);
        assert_eq!(
            report.records.iter().map(|r| &r.id).collect::<Vec<_>>(),
            again.records.iter().map(|r| &r.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn shared_account_asset_supplies_username_and_password() {
        let export = json!({
            "data": [
                asset(
                    "pair-1",
                    TYPE_SSH_PASSWORD_PAIR,
                    "/",
                    "ops",
                    json!({ "name": "ops", "username": "ops-admin", "password": "shared-pass" }),
                ),
                asset(
                    "ssh-1",
                    TYPE_SSH,
                    "/",
                    "shared",
                    ssh_model("10.0.0.4", json!({ "authType": AUTH_PASSWORD_PAIR, "passwordPairId": "pair-1" })),
                ),
            ],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        let ssh = record.ssh.as_ref().unwrap();
        assert_eq!("ops-admin", ssh.username);
        assert_eq!("included", record.password_status);
        assert_eq!(
            SshImportAuthMethod::Password {
                password: Some("shared-pass".to_string())
            },
            ssh.auth_method
        );
    }

    #[test]
    fn agent_auth_keeps_the_agent_method() {
        let export = json!({
            "data": [asset(
                "ssh-1",
                TYPE_SSH,
                "/",
                "agent-host",
                ssh_model("10.0.0.8", json!({ "authType": AUTH_AGENT, "agentSocketPath": "/tmp/agent.sock" })),
            )],
        });

        let report = preview(export, true);

        let record = &report.records[0];
        assert_eq!(
            SshImportAuthMethod::Agent,
            record.ssh.as_ref().unwrap().auth_method
        );
        assert_eq!("missing", record.password_status);
    }
}
