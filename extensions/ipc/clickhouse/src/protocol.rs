//! 连接配置解析与 HTTP endpoint 构造。
//!
//! `conn/test` / `conn/open` 的 `config` 由宿主按 driver.json 的 Connection 表单生成:
//! `{ host, port, username, password, database?, schema?, compression?, connect_timeout?,
//!    extra_params? }`。表单里的高级字段可能落在 `extra_params` 里,这里两者都接受。
//!
//! 解析规则移植自主仓 `crates/db/src/clickhouse/connection.rs`:
//! - `schema` 即 HTTP scheme(http / https,默认 http);
//! - `compression` 为 `lz4` 时启用 LZ4(其余一律不压缩);
//! - `connect_timeout` 默认 30 秒。

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

/// ClickHouse 默认 HTTP 端口。
pub const CLICKHOUSE_DEFAULT_PORT: u16 = 8123;
/// 默认连接超时(秒)。
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// 驱动接受的连接配置(与 driver.json Connection 表单字段一一对应)。
#[derive(Clone, Debug, Deserialize)]
pub struct ClickHouseConfig {
    /// 主机名,默认 127.0.0.1。
    #[serde(default = "default_host")]
    pub host: String,
    /// HTTP 端口,默认 8123。
    #[serde(default = "default_port")]
    pub port: u16,
    /// 用户名,默认 default(ClickHouse 出厂默认用户)。
    #[serde(default = "default_username")]
    pub username: String,
    /// 密码,可为空。
    #[serde(default)]
    pub password: String,
    /// 默认数据库,可空。
    #[serde(default)]
    pub database: Option<String>,
    /// HTTP scheme:http(默认)/ https。
    #[serde(default)]
    pub schema: Option<String>,
    /// 压缩:lz4 / none。
    #[serde(default)]
    pub compression: Option<String>,
    /// 连接超时(秒),默认 30。
    #[serde(default)]
    pub connect_timeout: Option<u64>,
    /// 宿主透传的附加参数(高级表单字段可能落在这里)。
    #[serde(default)]
    pub extra_params: HashMap<String, String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    CLICKHOUSE_DEFAULT_PORT
}

fn default_username() -> String {
    "default".to_string()
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            username: default_username(),
            password: String::new(),
            database: None,
            schema: None,
            compression: None,
            connect_timeout: None,
            extra_params: HashMap::new(),
        }
    }
}

impl ClickHouseConfig {
    /// 从 `conn/test` / `conn/open` params 的 `config` 字段解析。
    pub fn from_config_value(config: &Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(config.clone())?)
    }

    /// 读取配置项:优先顶层字段,其次 `extra_params`。
    fn param(&self, key: &str) -> Option<&str> {
        let top_level = match key {
            "schema" => self.schema.as_deref(),
            "compression" => self.compression.as_deref(),
            _ => None,
        };
        top_level
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.extra_params
                    .get(key)
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
    }

    /// HTTP scheme(小写);非 http/https 一律回退 http(与主仓一致)。
    pub fn scheme(&self) -> &'static str {
        match self.param("schema").map(str::to_ascii_lowercase) {
            Some(scheme) if scheme == "https" => "https",
            _ => "http",
        }
    }

    /// 是否启用 LZ4 压缩。
    pub fn lz4(&self) -> bool {
        matches!(
            self.param("compression").map(str::to_ascii_lowercase),
            Some(value) if value == "lz4"
        )
    }

    /// 连接超时(秒),未配置时用默认值;0 视为未配置。
    pub fn connect_timeout_secs(&self) -> u64 {
        self.connect_timeout
            .filter(|secs| *secs > 0)
            .or_else(|| {
                self.extra_params
                    .get("connect_timeout")
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .filter(|secs| *secs > 0)
            })
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS)
    }

    /// 配置里的默认数据库(去空白,空串视为未配置)。
    pub fn configured_database(&self) -> Option<String> {
        self.database
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    /// HTTP endpoint: `http(s)://host:port`。
    ///
    /// 宿主已把 SSH 隧道解析成实际 host/port,这里不再处理隧道;
    /// 若表单里 host 自带 scheme(`http://x`),原样尊重,避免拼出双 scheme。
    pub fn endpoint(&self) -> String {
        let host = self.host.trim();
        if host.starts_with("http://") || host.starts_with("https://") {
            return host.trim_end_matches('/').to_string();
        }
        format!("{}://{}:{}", self.scheme(), host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: Value) -> ClickHouseConfig {
        ClickHouseConfig::from_config_value(&value).unwrap()
    }

    #[test]
    fn defaults_match_clickhouse_http() {
        let config = config(json!({}));
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8123);
        assert_eq!(config.username, "default");
        assert_eq!(config.scheme(), "http");
        assert!(!config.lz4());
        assert_eq!(config.connect_timeout_secs(), 30);
        assert_eq!(config.endpoint(), "http://127.0.0.1:8123");
    }

    #[test]
    fn https_and_lz4_from_top_level_fields() {
        let config = config(json!({
            "host": "ch.example.com",
            "port": 8443,
            "schema": "HTTPS",
            "compression": "lz4",
            "connect_timeout": 5,
        }));
        assert_eq!(config.scheme(), "https");
        assert!(config.lz4());
        assert_eq!(config.connect_timeout_secs(), 5);
        assert_eq!(config.endpoint(), "https://ch.example.com:8443");
    }

    #[test]
    fn advanced_fields_from_extra_params() {
        let config = config(json!({
            "host": "ch",
            "extra_params": { "schema": "https", "compression": "lz4", "connect_timeout": "7" },
        }));
        assert_eq!(config.scheme(), "https");
        assert!(config.lz4());
        assert_eq!(config.connect_timeout_secs(), 7);
    }

    #[test]
    fn unknown_scheme_falls_back_to_http() {
        let config = config(json!({ "schema": "tcp" }));
        assert_eq!(config.scheme(), "http");
    }

    #[test]
    fn host_with_scheme_is_kept_verbatim() {
        let config = config(json!({ "host": "https://ch.internal:9440/" }));
        assert_eq!(config.endpoint(), "https://ch.internal:9440");
    }

    #[test]
    fn blank_database_is_none() {
        assert_eq!(
            config(json!({ "database": "  " })).configured_database(),
            None
        );
        assert_eq!(
            config(json!({ "database": " analytics " })).configured_database(),
            Some("analytics".to_string())
        );
    }
}
