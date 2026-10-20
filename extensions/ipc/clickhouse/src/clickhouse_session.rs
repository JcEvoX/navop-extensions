//! ClickHouse HTTP 会话封装:连接、查询、执行与结果映射。
//!
//! 连接层复用官方 `clickhouse` crate(HTTP 接口,默认 8123):
//! - 取数走 `FORMAT JSONCompact`,与主仓 `crates/db/src/clickhouse/connection.rs`
//!   完全一致(列类型元数据 + 行数据);
//! - DDL/DML 走 `Query::execute`,不伪造受影响行数;
//! - 当前库由驱动自己维护:HTTP 接口是无状态的,切换库时重建 Client 的
//!   `database` 参数,而不是依赖 `USE` 语句的会话上下文。

use std::time::Duration;

use anyhow::{Context, Result};
use clickhouse::{Client, Compression};
use extension_protocol::row::{CellValue, ColumnSpec};
use serde::Deserialize;
use serde_json::Value;

use crate::protocol::ClickHouseConfig;
use crate::value;

/// `JSONCompact` 响应里的列元数据。
#[derive(Debug, Clone, Deserialize)]
pub struct JsonMeta {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

/// `FORMAT JSONCompact` 响应体(只取驱动需要的字段)。
#[derive(Debug, Default, Deserialize)]
pub struct JsonCompact {
    #[serde(default)]
    pub meta: Vec<JsonMeta>,
    #[serde(default)]
    pub data: Vec<Vec<Value>>,
}

/// 一个已建立的 ClickHouse 会话。
pub struct ClickHouseSession {
    config: ClickHouseConfig,
    client: Client,
    database: Option<String>,
    connect_timeout: Duration,
}

impl ClickHouseSession {
    /// 按连接配置建连:构造 HTTP 客户端并在超时窗口内跑 `SELECT 1`。
    pub async fn connect(config: &ClickHouseConfig) -> Result<Self> {
        let connect_timeout = Duration::from_secs(config.connect_timeout_secs());
        let database = config.configured_database();
        let client = build_client(config, database.as_deref());
        let session = Self {
            config: config.clone(),
            client,
            database,
            connect_timeout,
        };

        tracing::debug!(
            endpoint = %config.endpoint(),
            database = session.database.as_deref().unwrap_or("<default>"),
            "[ClickHouse] connecting"
        );

        timeout(session.ping(), connect_timeout, "connection")
            .await
            .with_context(|| format!("failed to connect to ClickHouse at {}", config.endpoint()))?;

        Ok(session)
    }

    /// 连接超时。
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// 调用方配置的连接超时(秒),供 `conn/test` 上报。
    pub fn connect_timeout_secs(&self) -> u64 {
        self.config.connect_timeout_secs()
    }

    /// 当前默认库(未选择时为 None)。
    pub fn current_database(&self) -> Option<String> {
        self.database.clone()
    }

    /// 服务端版本(`SELECT version()`)。
    pub async fn server_version(&self) -> Result<String> {
        let result = self
            .query_json_compact("SELECT version() AS version")
            .await?;
        Ok(result
            .data
            .first()
            .and_then(|row| row.first())
            .and_then(|cell| cell.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string()))
    }

    /// 连通性检查:`SELECT 1`。
    pub async fn ping(&self) -> Result<()> {
        self.client
            .query("SELECT 1")
            .execute()
            .await
            .context("ClickHouse ping failed")
    }

    /// 切换当前库。
    ///
    /// HTTP 接口不带会话状态,因此这里先确认库存在,再把 Client 重建到目标库;
    /// 与主仓 `switch_database`(执行 `USE`)的可见行为一致。
    pub async fn use_database(&mut self, database: &str) -> Result<()> {
        let database = database.trim();
        if database.is_empty() {
            return Ok(());
        }
        let literal = escape_single_quoted(database);
        let result = self
            .query_json_compact(&format!(
                "SELECT name FROM system.databases WHERE name = '{literal}'"
            ))
            .await
            .context("failed to query current databases")?;
        if result.data.is_empty() {
            anyhow::bail!("unknown database `{database}`");
        }

        self.client = build_client(&self.config, Some(database));
        self.database = Some(database.to_string());
        Ok(())
    }

    /// 执行非查询语句(DDL / DML / USE)。
    pub async fn execute(&self, sql: &str) -> Result<()> {
        self.client
            .query(sql)
            .execute()
            .await
            .with_context(|| format!("failed to execute statement: {}", preview(sql)))
    }

    /// 取 `JSONCompact` 结果集。
    pub async fn query_json_compact(&self, sql: &str) -> Result<JsonCompact> {
        let mut cursor = self
            .client
            .query(sql)
            .fetch_bytes("JSONCompact")
            .with_context(|| format!("failed to start query: {}", preview(sql)))?;
        let bytes = cursor
            .collect()
            .await
            .with_context(|| format!("failed to read query result: {}", preview(sql)))?;
        serde_json::from_slice(&bytes).context("failed to parse JSONCompact response")
    }

    /// 查询并返回类型化行(供 `query/start` 游标使用)。
    ///
    /// 语句本身不产生结果集(DDL 等)时返回 `None`,由调用方按「空结果集」处理。
    pub async fn query_typed(
        &self,
        sql: &str,
        max_rows: Option<u64>,
    ) -> Result<Option<(Vec<ColumnSpec>, Vec<Vec<CellValue>>)>> {
        let result = match self.query_json_compact(sql).await {
            Ok(result) => result,
            Err(error) => {
                // 与主仓 execute_single 一致:取数失败时尝试按语句执行,
                // 成功说明这不是查询(DDL/DML),返回空结果集。
                tracing::debug!(
                    error = %format!("{error:#}"),
                    "[ClickHouse] fetch failed, retrying as statement"
                );
                self.execute(sql).await?;
                return Ok(None);
            }
        };

        let columns: Vec<ColumnSpec> = result
            .meta
            .iter()
            .map(|meta| value::column_spec(&meta.name, &meta.data_type))
            .collect();
        let mut rows: Vec<Vec<CellValue>> = result
            .data
            .iter()
            .map(|row| {
                columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| match row.get(index) {
                        Some(cell) => value::decode_cell(&column.type_str, cell),
                        None => CellValue::Null,
                    })
                    .collect()
            })
            .collect();
        if let Some(max_rows) = max_rows {
            rows.truncate(max_rows.min(usize::MAX as u64) as usize);
        }
        Ok(Some((columns, rows)))
    }

    /// 元数据查询:返回列名 + 文本行(列探测按列名,不依赖列序)。
    pub async fn query_table(&self, sql: &str, context: &str) -> Result<TableRows> {
        let result = self
            .query_json_compact(sql)
            .await
            .with_context(|| context.to_string())?;
        let columns: Vec<String> = result.meta.iter().map(|meta| meta.name.clone()).collect();
        let rows: Vec<Vec<Option<String>>> = result
            .data
            .iter()
            .map(|row| row.iter().map(cell_text).collect())
            .collect();
        Ok(TableRows { columns, rows })
    }
}

/// 元数据查询结果(列名 + 文本单元格)。
#[derive(Debug, Clone, Default)]
pub struct TableRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
}

impl TableRows {
    /// 按列名取整列文本。
    pub fn column(&self, name: &str) -> Vec<Option<String>> {
        let Some(index) = self
            .columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(name))
        else {
            return Vec::new();
        };
        self.rows
            .iter()
            .map(|row| row.get(index).cloned().flatten())
            .collect()
    }

    /// 按列名取第 `row` 行的值。
    pub fn value(&self, row: usize, name: &str) -> Option<String> {
        let index = self
            .columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(name))?;
        self.rows.get(row)?.get(index)?.clone()
    }

    /// 行数。
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// 构造 HTTP 客户端(可选默认库 / LZ4)。
fn build_client(config: &ClickHouseConfig, database: Option<&str>) -> Client {
    let mut client = Client::default()
        .with_url(config.endpoint())
        .with_user(config.username.clone())
        .with_password(config.password.clone());
    if let Some(database) = database {
        client = client.with_database(database);
    }
    if config.lz4() {
        client = client.with_compression(Compression::Lz4);
    }
    client
}

/// 超时包装:统一错误文案。
async fn timeout<F, T>(future: F, duration: Duration, what: &str) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("{what} timed out after {}s", duration.as_secs()),
    }
}

/// `JSONCompact` 单元格 → 文本(元数据路径用)。
fn cell_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Array(_) | Value::Object(_) => Some(value.to_string()),
    }
}

/// SQL 字符串字面量转义。
pub fn escape_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

/// SQL 预览(日志用,截断到 200 字符)。
pub fn preview(sql: &str) -> String {
    let trimmed = sql.trim();
    match trimmed.char_indices().nth(200) {
        Some((index, _)) => format!("{}...", &trimmed[..index]),
        None => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> TableRows {
        TableRows {
            columns: vec!["name".into(), "engine".into()],
            rows: vec![
                vec![Some("analytics".into()), Some("Atomic".into())],
                vec![Some("logs".into()), None],
            ],
        }
    }

    #[test]
    fn column_and_value_probe_by_name_case_insensitively() {
        let rows = rows();
        assert_eq!(
            rows.column("NAME"),
            vec![Some("analytics".into()), Some("logs".into())]
        );
        assert_eq!(rows.value(0, "engine"), Some("Atomic".into()));
        assert_eq!(rows.value(1, "engine"), None);
        assert_eq!(rows.value(9, "name"), None);
        assert!(rows.column("missing").is_empty());
    }

    #[test]
    fn cell_text_maps_null_and_structures() {
        assert_eq!(cell_text(&Value::Null), None);
        assert_eq!(cell_text(&Value::from(1)), Some("1".into()));
        assert_eq!(
            cell_text(&serde_json::json!({"a": 1})),
            Some("{\"a\":1}".into())
        );
    }

    #[test]
    fn preview_is_bounded() {
        let long = "SELECT ".repeat(100);
        assert!(preview(&long).len() <= 204);
        assert_eq!(preview(" SELECT 1 "), "SELECT 1");
    }

    #[test]
    fn escape_doubles_single_quotes() {
        assert_eq!(escape_single_quoted("o'brien"), "o''brien");
    }
}
