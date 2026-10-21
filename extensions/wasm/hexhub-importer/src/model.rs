use serde::Serialize;
use std::collections::BTreeMap;

/// 与宿主 `connection-import-protocol` 的 `ImportRecord` 逐字段对齐：宿主按这些
/// snake_case 键反序列化，字段名写错就是 `missing field` 整批导入失败。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportRecord {
    pub id: String,
    pub importer_id: String,
    pub source_label: String,
    pub source_id: Option<String>,
    pub kind: String,
    pub display_name: String,
    pub database: Option<DatabaseImportRecord>,
    pub ssh: Option<SshImportRecord>,
    pub quick_command: Option<QuickCommandImportRecord>,
    pub password_status: String,
    pub warnings: Vec<ImportWarning>,
}

/// 与宿主 `ImportDatabaseType` 同构：内部标签枚举，`External` 会序列化成
/// `{"external":{"id":"..."}}`，宿主据此走 MongoDB / Redis 的原生建模。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseImportType {
    MySql,
    PostgreSql,
    Sqlite,
    DuckDb,
    SqlServer,
    Oracle,
    ClickHouse,
    External { id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatabaseImportRecord {
    pub database_type: DatabaseImportType,
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub database: Option<String>,
    pub extra_params: BTreeMap<String, String>,
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
    pub jump_server: Option<SshJumpServerImportRecord>,
    pub proxy: Option<SshProxyImportRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
// HexHub 的私钥永远内联在导出文件里，所以只用到 `private_key_material` / `password` /
// `agent` 三个分支；其余变体留着是为了和宿主 `SshImportAuthMethod` 保持逐字一致。
#[allow(dead_code)]
pub enum SshImportAuthMethod {
    Password {
        password: Option<String>,
    },
    PrivateKey {
        key_path: String,
        passphrase: Option<String>,
    },
    PrivateKeyMaterial {
        private_key: Option<String>,
        passphrase: Option<String>,
        file_name_hint: Option<String>,
    },
    Agent,
    AutoPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuickCommandImportRecord {
    pub name: String,
    pub command: String,
    pub group_name: Option<String>,
    pub shortcut: Option<String>,
    pub description: Option<String>,
    pub sort_order: i32,
    pub connection_source_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SshJumpServerImportRecord {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SshImportAuthMethod,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SshProxyImportRecord {
    /// `socks5` 或 `http`。
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub code: String,
    pub message: String,
}
