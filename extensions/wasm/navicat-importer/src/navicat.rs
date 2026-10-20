use plist::{Dictionary, Value};
use quick_xml::{Reader, events::Event};

#[path = "decrypt.rs"]
mod decrypt;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Cursor;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportRecord {
    pub id: String,
    pub importer_id: String,
    pub source_label: String,
    pub source_id: Option<String>,
    pub kind: String,
    pub display_name: String,
    pub database: Option<DatabaseImportRecord>,
    pub ssh: Option<serde_json::Value>,
    pub port_forwarding: Option<serde_json::Value>,
    pub password_status: String,
    pub warnings: Vec<ImportWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatabaseImportRecord {
    pub database_type: String,
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub database: Option<String>,
    pub extra_params: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub code: String,
    pub message: String,
}

pub fn preview_records_from_plists<'a, I>(plists: I, include_passwords: bool) -> Vec<ImportRecord>
where
    I: IntoIterator<Item = (String, &'a [u8])>,
{
    let mut records = Vec::new();
    for (path, bytes) in plists {
        if let Ok(value) = Value::from_reader(Cursor::new(bytes)) {
            collect_records(&path, "", &value, include_passwords, &mut records);
            continue;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };
        records.extend(records_from_ncx(&path, text, include_passwords));
    }
    records
}

fn collect_records(
    path: &str,
    key_path: &str,
    value: &Value,
    include_passwords: bool,
    records: &mut Vec<ImportRecord>,
) {
    let Some(dict) = value.as_dictionary() else {
        return;
    };
    if let Some(record) = record_from_dict(path, key_path, dict, include_passwords) {
        records.push(record);
    }
    for (key, child) in dict {
        let child_path = if key_path.is_empty() {
            key.to_string()
        } else {
            format!("{key_path}/{key}")
        };
        collect_records(path, &child_path, child, include_passwords, records);
    }
}

fn record_from_dict(
    path: &str,
    key_path: &str,
    dict: &Dictionary,
    include_passwords: bool,
) -> Option<ImportRecord> {
    if is_parameter_dict(key_path) {
        return None;
    }

    let raw_type = text_field(
        dict,
        &[
            "ConnType",
            "Type",
            "DatabaseType",
            "DBType",
            "Driver",
            "serviceprovider",
        ],
    )
    .filter(|value| !value.eq_ignore_ascii_case("default"))
    .or_else(|| database_type_from_key_path(key_path))?;
    let database_type = database_type(&raw_type)?;
    let host = database_host(dict, &database_type);
    if host.is_empty() && database_type != "sqlite" {
        return None;
    }
    let source_id = if key_path.is_empty() {
        path.to_string()
    } else {
        format!("{path}:{key_path}")
    };
    let fallback_name = key_path
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(path);
    let name = text_field(
        dict,
        &[
            "Name",
            "Title",
            "ConnectionName",
            "DisplayName",
            "name",
            "title",
            "connectionname",
            "displayname",
        ],
    )
    .unwrap_or_else(|| fallback_name.to_string());

    let (password, password_status, warnings) = resolve_password(dict, include_passwords);

    Some(ImportRecord {
        id: record_id(&source_id),
        importer_id: "navicat".to_string(),
        source_label: "Navicat".to_string(),
        source_id: Some(source_id),
        kind: "database".to_string(),
        display_name: name.clone(),
        database: Some(DatabaseImportRecord {
            database_type,
            name,
            host,
            port: port_field(dict, &["Port", "port"]),
            username: text_field(dict, &["UserName", "Username", "User", "UID", "username"])
                .unwrap_or_default(),
            password,
            database: text_field(
                dict,
                &[
                    "Database",
                    "DatabaseName",
                    "InitialDatabase",
                    "Schema",
                    "defaultdatabase",
                ],
            ),
            extra_params: BTreeMap::new(),
        }),
        ssh: None,
        port_forwarding: None,
        password_status: password_status.to_string(),
        warnings,
    })
}

/// 解 Navicat 口令。只有旧版（`libcc` 固定密钥 + 十六进制密文）解得开；
/// 12+ 的逐安装密钥解不开时保留 `unsupported` 并说明原因。
fn resolve_password(
    dict: &Dictionary,
    include_passwords: bool,
) -> (Option<String>, &'static str, Vec<ImportWarning>) {
    let Some(raw) = dict_value(dict, &["Password", "password"]) else {
        return (None, "missing", Vec::new());
    };
    // plist 里偶尔是 <data> 而不是 <string>，这种连密文都读不出来。
    let Some(ciphertext) = value_text(raw)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return (
            None,
            "unsupported",
            vec![ImportWarning {
                code: "navicat_password_unreadable".to_string(),
                message: "This Navicat password is stored as binary data and could not be read."
                    .to_string(),
            }],
        );
    };
    if !include_passwords {
        return (None, "unsupported", Vec::new());
    }
    match decrypt::decrypt_legacy_password(ciphertext) {
        Some(password) => (Some(password), "included", Vec::new()),
        None => (
            None,
            "unsupported",
            vec![ImportWarning {
                code: "navicat_password_decrypt_failed".to_string(),
                message: "This Navicat password uses a newer per-installation key and could \
                          not be decrypted; re-enter it after import."
                    .to_string(),
            }],
        ),
    }
}

fn records_from_ncx(path: &str, text: &str, include_passwords: bool) -> Vec<ImportRecord> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut records = Vec::new();
    let mut name_occurrences = BTreeMap::<String, usize>::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                if tag_name(event.name().as_ref()) != "Connection" {
                    continue;
                }
                let mut dict = Dictionary::new();
                for attr in event.attributes().flatten() {
                    let key = tag_name(attr.key.as_ref());
                    let Ok(value) = attr.decode_and_unescape_value(reader.decoder()) else {
                        continue;
                    };
                    dict.insert(key, Value::String(value.into_owned()));
                }
                let connection_name = text_field(&dict, &["ConnectionName"])
                    .unwrap_or_else(|| "connection".to_string());
                let occurrence = name_occurrences
                    .entry(connection_name.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                let key_path = if *occurrence == 1 {
                    format!("Connections/{connection_name}")
                } else {
                    format!("Connections/{connection_name}#{occurrence}")
                };
                if let Some(record) = record_from_dict(path, &key_path, &dict, include_passwords) {
                    records.push(record);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    records
}

fn database_host(dict: &Dictionary, database_type: &str) -> String {
    if database_type == "sqlite" {
        return text_field(
            dict,
            &[
                "DatabaseFile",
                "DatabaseFileName",
                "FilePath",
                "dbfilename",
                "savepath",
            ],
        )
        .or_else(|| {
            text_field(
                dict,
                &["Host", "Hostname", "Server", "IP", "SocketHost", "host"],
            )
        })
        .unwrap_or_default();
    }
    text_field(
        dict,
        &["Host", "Hostname", "Server", "IP", "SocketHost", "host"],
    )
    .or_else(|| {
        text_field(
            dict,
            &[
                "DatabaseFile",
                "DatabaseFileName",
                "FilePath",
                "dbfilename",
                "savepath",
            ],
        )
    })
    .unwrap_or_default()
}

fn text_field(dict: &Dictionary, keys: &[&str]) -> Option<String> {
    dict_value(dict, keys)
        .and_then(value_text)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn dict_value<'a>(dict: &'a Dictionary, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = dict.get(*key) {
            return Some(value);
        }
        if let Some((_, value)) = dict
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(key))
        {
            return Some(value);
        }
    }
    None
}

fn value_text(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) => Some(text),
        _ => None,
    }
}

fn tag_name(name: &[u8]) -> String {
    std::str::from_utf8(name)
        .unwrap_or_default()
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn port_field(dict: &Dictionary, keys: &[&str]) -> Option<u16> {
    keys.iter().find_map(|key| match dict_value(dict, &[*key]) {
        Some(Value::Integer(_)) => dict_value(dict, &[*key])
            .and_then(Value::as_unsigned_integer)
            .and_then(|port| u16::try_from(port).ok()),
        Some(Value::String(text)) => text.trim().parse::<u16>().ok(),
        _ => None,
    })
}

fn database_type_from_key_path(key_path: &str) -> Option<String> {
    key_path
        .split('/')
        .rev()
        .find(|segment| database_type(segment).is_some())
        .map(ToOwned::to_owned)
}

fn is_parameter_dict(key_path: &str) -> bool {
    key_path.split('/').any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "ssh_param" | "http_param" | "ssl_param" | "compatibility_param"
        )
    })
}

fn database_type(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '.'], "_");
    match normalized.as_str() {
        "mysql" | "mariadb" | "mysql8" | "mysql5" => Some("my_sql".to_string()),
        "postgres" | "postgresql" | "pgsql" | "postgres_jdbc" => Some("postgre_sql".to_string()),
        "sqlite" | "sqlite3" => Some("sqlite".to_string()),
        "oracle" | "oci" | "oracle_thin" => Some("oracle".to_string()),
        "sqlserver" | "sql_server" | "mssql" | "microsoft_sql_server" => {
            Some("sql_server".to_string())
        }
        _ => None,
    }
}

fn slug(value: &str) -> String {
    let stem = value.replace(".plist", "").replace(".ncx", "");
    let mut out = String::new();
    let mut last_dash = false;
    for ch in stem.chars().flat_map(char::to_lowercase) {
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

fn record_id(source_id: &str) -> String {
    format!(
        "navicat:{}:{:016x}",
        slug(source_id),
        stable_hash(source_id)
    )
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

    #[test]
    fn parses_navicat_mysql_server_from_preferences_plist_without_passwords() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Servers</key>
  <dict>
    <key>mysql-prod</key>
    <dict>
      <key>Name</key><string>Prod MySQL</string>
      <key>ConnType</key><string>MYSQL</string>
      <key>Host</key><string>db.example.test</string>
      <key>Port</key><integer>3307</integer>
      <key>UserName</key><string>root</string>
      <key>Database</key><string>app</string>
      <key>Password</key><string>encrypted-secret</string>
    </dict>
  </dict>
</dict>
</plist>"#;

        let records = preview_records_from_plists(
            vec![(
                "com.prect.NavicatPremium.plist".to_string(),
                plist.as_slice(),
            )],
            true,
        );

        assert_eq!(1, records.len());
        let record = &records[0];
        assert_eq!(
            record_id("com.prect.NavicatPremium.plist:Servers/mysql-prod"),
            record.id
        );
        assert_eq!("navicat", record.importer_id);
        assert_eq!("Navicat", record.source_label);
        assert_eq!(
            Some("com.prect.NavicatPremium.plist:Servers/mysql-prod"),
            record.source_id.as_deref()
        );
        assert_eq!("database", record.kind);
        assert_eq!("Prod MySQL", record.display_name);
        assert_eq!("unsupported", record.password_status);
        let database = record.database.as_ref().unwrap();
        assert_eq!("my_sql", database.database_type);
        assert_eq!("db.example.test", database.host);
        assert_eq!(Some(3307), database.port);
        assert_eq!("root", database.username);
        assert_eq!(Some("app"), database.database.as_deref());
        assert!(database.password.is_none());
    }

    #[test]
    fn parses_navicat_lite_conn_plist_and_ignores_nested_ssh_params() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Connections</key>
  <dict>
    <key>MySQL</key>
    <dict>
      <key>prod-lite</key>
      <dict>
        <key>host</key><string>lite-db.example.test</string>
        <key>port</key><string>3307</string>
        <key>username</key><string>lite_user</string>
        <key>defaultdatabase</key><string>orders</string>
        <key>serviceprovider</key><string>Default</string>
        <key>savepassword</key><true/>
        <key>ssh_param</key>
        <dict>
          <key>host</key><string>jump.example.test</string>
          <key>port</key><string>22</string>
          <key>username</key><string>jump_user</string>
          <key>authtype</key><integer>0</integer>
        </dict>
      </dict>
    </dict>
  </dict>
</dict>
</plist>"#;

        let records =
            preview_records_from_plists(vec![("conn.plist".to_string(), plist.as_slice())], true);

        assert_eq!(1, records.len());
        let record = &records[0];
        assert_eq!(
            record_id("conn.plist:Connections/MySQL/prod-lite"),
            record.id
        );
        assert_eq!("navicat", record.importer_id);
        assert_eq!("Navicat", record.source_label);
        assert_eq!(
            Some("conn.plist:Connections/MySQL/prod-lite"),
            record.source_id.as_deref()
        );
        assert_eq!("database", record.kind);
        assert_eq!("prod-lite", record.display_name);
        // conn.plist 里根本没有口令字段（Navicat Lite 存在别处），所以是 missing 不是 unsupported。
        assert_eq!("missing", record.password_status);

        let database = record.database.as_ref().unwrap();
        assert_eq!("my_sql", database.database_type);
        assert_eq!("lite-db.example.test", database.host);
        assert_eq!(Some(3307), database.port);
        assert_eq!("lite_user", database.username);
        assert_eq!(Some("orders"), database.database.as_deref());
        assert!(database.password.is_none());
    }

    #[test]
    fn uses_full_key_path_to_distinguish_same_named_connections() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Connections</key>
  <dict>
    <key>MySQL</key>
    <dict>
      <key>shared</key>
      <dict>
        <key>host</key><string>mysql.example.test</string>
        <key>serviceprovider</key><string>Default</string>
      </dict>
    </dict>
    <key>PostgreSQL</key>
    <dict>
      <key>shared</key>
      <dict>
        <key>host</key><string>postgres.example.test</string>
        <key>serviceprovider</key><string>Default</string>
      </dict>
    </dict>
  </dict>
</dict>
</plist>"#;

        let records =
            preview_records_from_plists(vec![("conn.plist".to_string(), plist.as_slice())], true);

        assert_eq!(2, records.len());
        assert_ne!(records[0].id, records[1].id);
        assert_eq!(
            Some("conn.plist:Connections/MySQL/shared"),
            records[0].source_id.as_deref()
        );
        assert_eq!(
            Some("conn.plist:Connections/PostgreSQL/shared"),
            records[1].source_id.as_deref()
        );
    }

    #[test]
    fn slug_collisions_and_unicode_paths_keep_distinct_stable_ids() {
        let connection = br#"<?xml version="1.0" encoding="UTF-8"?>
<Connections Ver="1.5">
  <Connection ConnectionName="Prod" ConnType="MYSQL" Host="db.example.test"/>
</Connections>"#;
        let sources = vec![
            ("A-B.ncx".to_string(), connection.as_slice()),
            ("A_B.ncx".to_string(), connection.as_slice()),
            ("生产.ncx".to_string(), connection.as_slice()),
            ("测试.ncx".to_string(), connection.as_slice()),
        ];

        let first = preview_records_from_plists(sources.clone(), true);
        let second = preview_records_from_plists(sources, true);

        assert_eq!(4, first.len());
        assert_eq!(
            4,
            first
                .iter()
                .map(|record| &record.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        assert_eq!(
            first.iter().map(|record| &record.id).collect::<Vec<_>>(),
            second.iter().map(|record| &record.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn duplicate_ncx_names_get_distinct_source_ids() {
        let ncx = br#"<?xml version="1.0" encoding="UTF-8"?>
<Connections Ver="1.5">
  <Connection ConnectionName="Prod" ConnType="MYSQL" Host="first.example.test"/>
  <Connection ConnectionName="Prod" ConnType="MYSQL" Host="second.example.test"/>
</Connections>"#;

        let records =
            preview_records_from_plists(vec![("connection.ncx".to_string(), ncx.as_slice())], true);

        assert_eq!(2, records.len());
        assert_ne!(records[0].id, records[1].id);
        assert_eq!(
            Some("connection.ncx:Connections/Prod"),
            records[0].source_id.as_deref()
        );
        assert_eq!(
            Some("connection.ncx:Connections/Prod#2"),
            records[1].source_id.as_deref()
        );
    }

    #[test]
    fn parses_navicat_connection_ncx_export() {
        let ncx = br#"<?xml version="1.0" encoding="UTF-8"?>
<Connections Ver="1.5">
  <Connection ConnectionName="Prod MySQL" ConnType="MYSQL" Host="db.example.test" Port="3308" Database="app" UserName="app_user" DatabaseFileName=""/>
  <Connection ConnectionName="Local SQLite" ConnType="SQLITE" Host="localhost" Port="" Database="" UserName="" DatabaseFileName="C:\Data\local.db"/>
</Connections>"#;

        let records =
            preview_records_from_plists(vec![("connection.ncx".to_string(), ncx.as_slice())], true);

        assert_eq!(2, records.len());

        let mysql = &records[0];
        assert_eq!(record_id("connection.ncx:Connections/Prod MySQL"), mysql.id);
        assert_eq!(
            Some("connection.ncx:Connections/Prod MySQL"),
            mysql.source_id.as_deref()
        );
        assert_eq!("Prod MySQL", mysql.display_name);
        let mysql_database = mysql.database.as_ref().unwrap();
        assert_eq!("my_sql", mysql_database.database_type);
        assert_eq!("db.example.test", mysql_database.host);
        assert_eq!(Some(3308), mysql_database.port);
        assert_eq!("app_user", mysql_database.username);
        assert_eq!(Some("app"), mysql_database.database.as_deref());
        assert!(mysql_database.password.is_none());

        let sqlite = &records[1];
        assert_eq!("Local SQLite", sqlite.display_name);
        let sqlite_database = sqlite.database.as_ref().unwrap();
        assert_eq!("sqlite", sqlite_database.database_type);
        assert_eq!("C:\\Data\\local.db", sqlite_database.host);
        assert_eq!(None, sqlite_database.port);
    }

    // ---- 口令解密（旧版 ncx，libcc 固定密钥） ----

    /// 密文由 Node `aes-128-cbc` 用同一组 key/iv 生成，明文 `database-secret`。
    const LEGACY_PASSWORD_CIPHERTEXT: &str = "9E3951B0152DA9E9391648E8B0B58029";

    #[test]
    fn decrypts_legacy_ncx_password_when_passwords_are_requested() {
        let ncx = format!(
            r#"<Connections>
  <Connection ConnType="MYSQL" ConnectionName="mysql-legacy" Host="db.example.test" Port="3306" UserName="root" Password="{LEGACY_PASSWORD_CIPHERTEXT}" />
</Connections>"#
        );
        let records =
            preview_records_from_plists(vec![("connection.ncx".to_string(), ncx.as_bytes())], true);

        let record = &records[0];
        assert_eq!("included", record.password_status);
        assert_eq!(
            record.database.as_ref().unwrap().password.as_deref(),
            Some("database-secret")
        );
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn password_is_not_decrypted_or_leaked_when_not_requested() {
        let ncx = format!(
            r#"<Connections>
  <Connection ConnType="MYSQL" ConnectionName="mysql-legacy" Host="db.example.test" UserName="root" Password="{LEGACY_PASSWORD_CIPHERTEXT}" />
</Connections>"#
        );
        let records = preview_records_from_plists(
            vec![("connection.ncx".to_string(), ncx.as_bytes())],
            false,
        );

        let record = &records[0];
        assert_eq!("unsupported", record.password_status);
        assert!(record.database.as_ref().unwrap().password.is_none());
        assert!(
            !serde_json::to_string(record)
                .unwrap()
                .contains("database-secret")
        );
    }

    #[test]
    fn newer_navicat_ciphertext_reports_that_it_could_not_be_decrypted() {
        // Navicat 12+ 用逐安装派生的密钥，密文不是十六进制。
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Servers</key>
  <dict>
    <key>mysql-prod</key>
    <dict>
      <key>Name</key><string>Prod MySQL</string>
      <key>ConnType</key><string>MYSQL</string>
      <key>Host</key><string>db.example.test</string>
      <key>UserName</key><string>root</string>
      <key>Password</key><string>dGhpcyBpcyBub3QgaGV4</string>
    </dict>
  </dict>
</dict>
</plist>"#;
        let records = preview_records_from_plists(
            vec![(
                "com.prect.NavicatPremium.plist".to_string(),
                plist.as_slice(),
            )],
            true,
        );

        let record = &records[0];
        assert_eq!("unsupported", record.password_status);
        assert!(
            record
                .warnings
                .iter()
                .any(|warning| warning.code == "navicat_password_decrypt_failed")
        );
    }
}
