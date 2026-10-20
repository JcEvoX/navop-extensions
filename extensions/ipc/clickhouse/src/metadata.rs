//! ClickHouse 元数据查询与对象视图映射。
//!
//! SQL 与映射逻辑移植自主仓 `crates/db/src/clickhouse/plugin.rs`:
//! - 库:`system.databases`(过滤 system / INFORMATION_SCHEMA);
//! - 表 / 视图:`system.tables`,`engine LIKE '%View%'` 区分视图;
//! - 列:`system.columns`(类型 / 默认值 / 注释 / 主键);
//! - 数据跳过索引:`system.data_skipping_indices`;
//! - 用户自定义函数:`system.functions WHERE origin = 'SQLUserDefined'`;
//! - 表 DDL:`SHOW CREATE TABLE`(官方 DDL,不拼装)。
//!
//! 所有查询都走文本探测(按列名取列),不依赖服务端列序。

use anyhow::{Context, Result};
use extension_protocol::schema::{
    ColumnInfo, DatabaseInfo, FunctionInfo, IndexInfo, ObjectInfo, ObjectKind, ObjectView,
    ObjectViewColumn, ViewInfo,
};
use serde_json::json;

use crate::clickhouse_session::{ClickHouseSession, TableRows, escape_single_quoted};

/// 系统库(不出现在树里)。
const HIDDEN_DATABASES: &[&str] = &["system", "INFORMATION_SCHEMA", "information_schema"];

/// 库列表:schema/objects 与树根共用。
pub async fn databases(session: &ClickHouseSession) -> Result<Vec<DatabaseInfo>> {
    let sql = "SELECT name, engine, comment FROM system.databases \
               WHERE name NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') \
               ORDER BY name";
    let rows = session.query_table(sql, "failed to list databases").await?;
    Ok(rows
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let name = rows.value(index, "name")?;
            Some(DatabaseInfo {
                name,
                // 与主仓一致:charset 字段承载库引擎。
                charset: rows.value(index, "engine"),
                collation: None,
                comment: rows.value(index, "comment").unwrap_or_default(),
                owner: None,
                size_bytes: None,
                extra: json!({ "engine": rows.value(index, "engine") }),
            })
        })
        .collect())
}

/// 库名列表(供解析默认库)。
pub async fn database_names(session: &ClickHouseSession) -> Result<Vec<String>> {
    Ok(databases(session)
        .await?
        .into_iter()
        .map(|database| database.name)
        .collect())
}

/// 表列表(不含视图)。
pub async fn tables(session: &ClickHouseSession, database: &str) -> Result<Vec<ObjectInfo>> {
    let sql = format!(
        "SELECT name, engine, comment FROM system.tables \
         WHERE database = '{}' AND engine NOT LIKE '%View%' AND name NOT LIKE '.inner_id.%' \
         ORDER BY name",
        escape_single_quoted(database)
    );
    let rows = session
        .query_table(&sql, "failed to list tables")
        .await
        .context("list tables")?;
    Ok(rows
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let name = rows.value(index, "name")?;
            Some(ObjectInfo {
                name,
                kind: ObjectKind::Table,
                schema: String::new(),
                comment: rows.value(index, "comment").unwrap_or_default(),
                row_count_estimate: None,
                size_bytes: None,
                created_at: None,
                updated_at: None,
                extra: json!({ "engine": rows.value(index, "engine") }),
            })
        })
        .collect())
}

/// 视图列表(普通视图 + 物化视图)。
pub async fn view_objects(session: &ClickHouseSession, database: &str) -> Result<Vec<ObjectInfo>> {
    let sql = format!(
        "SELECT name, engine, comment FROM system.tables \
         WHERE database = '{}' AND engine LIKE '%View%' AND name NOT LIKE '.inner_id.%' \
         ORDER BY name",
        escape_single_quoted(database)
    );
    let rows = session.query_table(&sql, "failed to list views").await?;
    Ok(rows
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let name = rows.value(index, "name")?;
            let engine = rows.value(index, "engine").unwrap_or_default();
            let kind = if engine.eq_ignore_ascii_case("MaterializedView") {
                ObjectKind::MaterializedView
            } else {
                ObjectKind::View
            };
            Some(ObjectInfo {
                name,
                kind,
                schema: String::new(),
                comment: rows.value(index, "comment").unwrap_or_default(),
                row_count_estimate: None,
                size_bytes: None,
                created_at: None,
                updated_at: None,
                extra: json!({ "engine": engine }),
            })
        })
        .collect())
}

/// 视图定义(供 `schema/views`)。
pub async fn views(session: &ClickHouseSession, database: &str) -> Result<Vec<ViewInfo>> {
    let sql = format!(
        "SELECT name, engine, create_table_query FROM system.tables \
         WHERE database = '{}' AND engine LIKE '%View%' AND name NOT LIKE '.inner_id.%' \
         ORDER BY name",
        escape_single_quoted(database)
    );
    let rows = session.query_table(&sql, "failed to list views").await?;
    Ok(rows
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let name = rows.value(index, "name")?;
            let engine = rows.value(index, "engine").unwrap_or_default();
            Some(ViewInfo {
                name,
                kind: if engine.eq_ignore_ascii_case("MaterializedView") {
                    ObjectKind::MaterializedView
                } else {
                    ObjectKind::View
                },
                definition_sql: rows.value(index, "create_table_query").unwrap_or_default(),
                comment: String::new(),
                extra: json!({ "engine": engine }),
            })
        })
        .collect())
}

/// 列详情。
pub async fn columns(
    session: &ClickHouseSession,
    database: &str,
    table: &str,
) -> Result<Vec<ColumnInfo>> {
    let sql = format!(
        "SELECT name, type, default_kind, default_expression, comment, is_in_primary_key \
         FROM system.columns WHERE database = '{}' AND table = '{}' ORDER BY position",
        escape_single_quoted(database),
        escape_single_quoted(table)
    );
    let rows = session.query_table(&sql, "failed to list columns").await?;

    let mut columns = Vec::new();
    for index in 0..rows.len() {
        let Some(name) = rows.value(index, "name") else {
            continue;
        };
        let Some(data_type) = rows.value(index, "type") else {
            continue;
        };
        let default_kind = rows.value(index, "default_kind");
        let default_expression = rows.value(index, "default_expression");
        let is_primary = rows
            .value(index, "is_in_primary_key")
            .map(|value| value == "1")
            .unwrap_or(false);
        let default = if default_kind.as_deref() == Some("DEFAULT") {
            default_expression
        } else {
            None
        };
        let nullable = data_type
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("nullable(");
        let spec = crate::value::column_spec(&name, &data_type);

        columns.push(ColumnInfo {
            ordinal: (columns.len() + 1) as u32,
            name,
            type_str: data_type.clone(),
            raw_type: Some(data_type),
            nullable,
            default,
            is_primary,
            is_unique: false,
            is_partition_key: false,
            is_clustering_key: false,
            max_length: spec.max_length,
            precision: spec.precision,
            scale: spec.scale,
            comment: rows.value(index, "comment").unwrap_or_default(),
            // ClickHouse 没有列级自增概念(wire 层的 is_auto_increment 缺省即 false)。
            extra: serde_json::Value::Null,
        });
    }
    Ok(columns)
}

/// 数据跳过索引。
pub async fn indexes(
    session: &ClickHouseSession,
    database: &str,
    table: &str,
) -> Result<Vec<IndexInfo>> {
    let sql = format!(
        "SELECT name, type, expr, granularity FROM system.data_skipping_indices \
         WHERE database = '{}' AND table = '{}' ORDER BY name",
        escape_single_quoted(database),
        escape_single_quoted(table)
    );
    let rows = session.query_table(&sql, "failed to list indexes").await?;

    let mut indexes = Vec::new();
    for index in 0..rows.len() {
        let Some(name) = rows.value(index, "name") else {
            continue;
        };
        let index_type = rows.value(index, "type").unwrap_or_else(|| "minmax".into());
        let expression = rows.value(index, "expr").unwrap_or_default();
        let granularity = rows
            .value(index, "granularity")
            .unwrap_or_else(|| "1".into());
        indexes.push(IndexInfo {
            name,
            table: table.to_string(),
            columns: if expression.trim().is_empty() {
                Vec::new()
            } else {
                vec![expression]
            },
            kind: Some(format!("{index_type} (granularity: {granularity})")),
            is_unique: false,
            is_primary: false,
            where_clause: None,
            comment: String::new(),
            extra: json!({ "type": index_type, "granularity": granularity }),
        });
    }
    Ok(indexes)
}

/// 用户自定义函数。
pub async fn functions(session: &ClickHouseSession) -> Result<Vec<FunctionInfo>> {
    let sql = "SELECT name, create_query FROM system.functions \
               WHERE origin = 'SQLUserDefined' ORDER BY name";
    let rows = session.query_table(sql, "failed to list functions").await?;
    Ok(rows
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            let name = rows.value(index, "name")?;
            Some(FunctionInfo {
                name,
                return_type: None,
                args: Vec::new(),
                language: Some("SQL".to_string()),
                definition: rows.value(index, "create_query"),
                comment: String::new(),
                extra: serde_json::Value::Null,
            })
        })
        .collect())
}

/// 表 DDL:`SHOW CREATE TABLE`,去掉结尾分号(脚本收尾由宿主负责)。
pub async fn table_ddl(session: &ClickHouseSession, database: &str, table: &str) -> Result<String> {
    let qualified = format!("{}.{}", quote_identifier(database), quote_identifier(table));
    let rows = session
        .query_table(&format!("SHOW CREATE TABLE {qualified}"), "dump table ddl")
        .await?;
    let ddl = ddl_column_value(&rows)
        .and_then(|ddl| normalize_ddl(&ddl))
        .with_context(|| format!("SHOW CREATE TABLE returned no DDL for {qualified}"))?;
    Ok(ddl)
}

/// `SHOW CREATE TABLE` 返回的 DDL 列:按常见列名取,取不到再退化为
/// 「单列取第 0 列 / 两列取第 1 列」(与主仓一致)。
fn ddl_column_value(rows: &TableRows) -> Option<String> {
    for name in [
        "statement",
        "create_table",
        "create_table_query",
        "create_statement",
    ] {
        if let Some(value) = rows.value(0, name) {
            return Some(value);
        }
    }
    let row = rows.rows.first()?;
    match row.len() {
        0 => None,
        1 => row[0].clone(),
        _ => row[1].clone(),
    }
}

/// 去掉首尾空白与结尾分号。
fn normalize_ddl(ddl: &str) -> Option<String> {
    let trimmed = ddl.trim().trim_end_matches(';').trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// 反引号标识符。
pub fn quote_identifier(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

// ===================== 对象视图 =====================

fn column(key: &str, name: &str, width_px: f32) -> ObjectViewColumn {
    ObjectViewColumn {
        key: key.to_string(),
        name: name.to_string(),
        width_px: Some(width_px),
        align: None,
    }
}

/// 库视图:名称 | 引擎 | 表数量 | 注释。
pub fn databases_object_view(databases: &[DatabaseInfo]) -> ObjectView {
    ObjectView {
        title: "Databases".to_string(),
        columns: vec![
            column("name", "Name", 220.0),
            column("engine", "Engine", 140.0),
            column("comment", "Comment", 300.0),
        ],
        rows: databases
            .iter()
            .map(|database| {
                vec![
                    database.name.clone(),
                    database.charset.clone().unwrap_or_else(|| "-".into()),
                    database.comment.clone(),
                ]
            })
            .collect(),
    }
}

/// 表视图:名称 | 引擎 | 注释。
pub fn tables_object_view(tables: &[ObjectInfo]) -> ObjectView {
    ObjectView {
        title: "Tables".to_string(),
        columns: vec![
            column("name", "Name", 220.0),
            column("engine", "Engine", 160.0),
            column("comment", "Comment", 320.0),
        ],
        rows: tables
            .iter()
            .map(|table| {
                vec![
                    table.name.clone(),
                    table
                        .extra
                        .get("engine")
                        .and_then(|value| value.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    table.comment.clone(),
                ]
            })
            .collect(),
    }
}

/// 列视图:名称 | 类型 | 可空 | 默认值 | 注释。
pub fn columns_object_view(columns: &[ColumnInfo]) -> ObjectView {
    ObjectView {
        title: "Columns".to_string(),
        columns: vec![
            column("name", "Name", 180.0),
            column("type", "Type", 180.0),
            column("nullable", "Nullable", 90.0),
            column("default", "Default", 160.0),
            column("comment", "Comment", 220.0),
        ],
        rows: columns
            .iter()
            .map(|info| {
                vec![
                    info.name.clone(),
                    info.raw_type
                        .clone()
                        .unwrap_or_else(|| info.type_str.clone()),
                    if info.nullable { "YES" } else { "NO" }.to_string(),
                    info.default.clone().unwrap_or_default(),
                    info.comment.clone(),
                ]
            })
            .collect(),
    }
}

/// 索引视图:名称 | 类型 | 表达式。
pub fn indexes_object_view(indexes: &[IndexInfo]) -> ObjectView {
    ObjectView {
        title: "Data Skipping Indexes".to_string(),
        columns: vec![
            column("name", "Name", 180.0),
            column("type", "Type", 240.0),
            column("expression", "Expression", 320.0),
        ],
        rows: indexes
            .iter()
            .map(|info| {
                vec![
                    info.name.clone(),
                    info.kind.clone().unwrap_or_else(|| "-".into()),
                    info.columns.join(", "),
                ]
            })
            .collect(),
    }
}

/// 视图视图:名称 | 引擎 | 定义。
pub fn views_object_view(views: &[ViewInfo]) -> ObjectView {
    ObjectView {
        title: "Views".to_string(),
        columns: vec![
            column("name", "Name", 200.0),
            column("engine", "Engine", 150.0),
            column("definition", "Definition", 600.0),
        ],
        rows: views
            .iter()
            .map(|view| {
                vec![
                    view.name.clone(),
                    view.extra
                        .get("engine")
                        .and_then(|value| value.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    view.definition_sql.clone(),
                ]
            })
            .collect(),
    }
}

/// 函数视图:名称 | 定义。
pub fn functions_object_view(functions: &[FunctionInfo]) -> ObjectView {
    ObjectView {
        title: "User Defined Functions".to_string(),
        columns: vec![
            column("name", "Name", 200.0),
            column("definition", "Definition", 500.0),
        ],
        rows: functions
            .iter()
            .map(|function| {
                vec![
                    function.name.clone(),
                    function.definition.clone().unwrap_or_default(),
                ]
            })
            .collect(),
    }
}

/// 是否为隐藏系统库。
pub fn is_hidden_database(name: &str) -> bool {
    HIDDEN_DATABASES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(columns: &[&str], data: Vec<Vec<Option<&str>>>) -> TableRows {
        TableRows {
            columns: columns.iter().map(|c| (*c).to_string()).collect(),
            rows: data
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|cell| cell.map(str::to_string))
                        .collect()
                })
                .collect(),
        }
    }

    #[test]
    fn ddl_column_prefers_named_column_then_position() {
        let named = rows(
            &["table", "statement"],
            vec![vec![Some("t"), Some("CREATE TABLE t (x Int32)")]],
        );
        assert_eq!(
            ddl_column_value(&named),
            Some("CREATE TABLE t (x Int32)".to_string())
        );

        let single = rows(&["ddl"], vec![vec![Some("CREATE TABLE t (x Int32);")]]);
        assert_eq!(
            normalize_ddl(&ddl_column_value(&single).unwrap()),
            Some("CREATE TABLE t (x Int32)".to_string())
        );

        let two = rows(
            &["t", "ddl"],
            vec![vec![Some("t"), Some("CREATE TABLE t;")]],
        );
        assert_eq!(ddl_column_value(&two), Some("CREATE TABLE t;".to_string()));

        let empty = rows(&["t", "ddl"], vec![]);
        assert_eq!(ddl_column_value(&empty), None);
    }

    #[test]
    fn normalize_ddl_strips_semicolon_and_blank() {
        assert_eq!(
            normalize_ddl("  CREATE TABLE t (x Int32);  "),
            Some("CREATE TABLE t (x Int32)".into())
        );
        assert_eq!(normalize_ddl("   ;  "), None);
    }

    #[test]
    fn quote_identifier_escapes_backticks() {
        assert_eq!(quote_identifier("db"), "`db`");
        assert_eq!(quote_identifier("a`b"), "`a``b`");
    }

    #[test]
    fn hidden_databases_cover_system_schemas() {
        assert!(is_hidden_database("system"));
        assert!(is_hidden_database("INFORMATION_SCHEMA"));
        assert!(!is_hidden_database("analytics"));
    }
}
