//! ClickHouse 方言的 DDL 构造(`ddl/build*`)。
//!
//! SQL 模式移植自主仓 `crates/db/src/clickhouse/plugin.rs`:
//! - 标识符用反引号(`` `name` ``);
//! - 列可空通过 `Nullable(T)` 表达(已带 `Nullable` 的不重复包裹);
//! - 建表必须带 `ENGINE`,默认 `MergeTree()`;主键落成 `ORDER BY (...)`;
//! - 数据跳过索引写进表定义:`INDEX name expr TYPE type GRANULARITY n`;
//! - ClickHouse 不支持列自增 / 二级唯一索引 / 外键 / 修改库属性,
//!   这些声明一律汇入 warnings 而不是生成非法 SQL;
//! - ALTER 先做 `RENAME COLUMN`(需要先于增删改,否则旧列名对不上),
//!   再做 DROP / MODIFY / ADD。

use std::collections::{HashMap, HashSet};

use extension_protocol::ddl::{
    BuildAlterTableParams, BuildAlterTableResult, BuildCreateTableParams, BuildCreateTableResult,
    BuildDdlParams, BuildDdlResult, BuildDropParams, BuildDropResult, ColumnRenameSpec, ColumnSpec,
    DdlBuildOp, IndexSpec, TableSpec,
};
use extension_protocol::schema::ObjectKind;
use serde_json::Value;

use crate::metadata::quote_identifier;

/// 建表默认引擎(与主仓一致)。
const DEFAULT_ENGINE: &str = "MergeTree()";

/// `ddl/build` 分发。
pub fn build_ddl(params: BuildDdlParams) -> Result<BuildDdlResult, String> {
    match params.op {
        DdlBuildOp::CreateTable => {
            let (result, warnings) = build_create_table_inner(decode_payload(params.payload)?);
            Ok(BuildDdlResult {
                statements: result.statements,
                warnings,
            })
        }
        DdlBuildOp::AlterTable => {
            let result = build_alter_table(decode_payload(params.payload)?)?;
            Ok(BuildDdlResult {
                statements: result.statements,
                warnings: result.warnings,
            })
        }
        DdlBuildOp::DropTable => {
            let result = build_drop(decode_drop_payload(params.payload, ObjectKind::Table)?);
            Ok(single_statement(result.sql))
        }
        DdlBuildOp::DropView => {
            let result = build_drop(decode_drop_payload(params.payload, ObjectKind::View)?);
            Ok(single_statement(result.sql))
        }
        DdlBuildOp::CreateDatabase | DdlBuildOp::CreateSchema => {
            Ok(single_statement(build_create_database(params.payload)?))
        }
        DdlBuildOp::DropDatabase | DdlBuildOp::DropSchema => {
            Ok(single_statement(build_drop_database(params.payload)?))
        }
        DdlBuildOp::ModifyDatabase | DdlBuildOp::CommentSchema => {
            Ok(single_statement(build_modify_database(params.payload)?))
        }
        DdlBuildOp::RenameTable => Ok(single_statement(build_rename_table(params.payload)?)),
        DdlBuildOp::TruncateTable => Ok(single_statement(build_truncate_table(params.payload)?)),
        DdlBuildOp::ColumnDefinition => {
            let column: ColumnSpec = decode_payload(params.payload)?;
            let mut warnings = Vec::new();
            Ok(BuildDdlResult {
                statements: vec![column_definition_with(&column, &mut warnings)],
                warnings,
            })
        }
    }
}

/// `ddl/build_create_table` 入口(warnings 由 `ddl/build` 路径汇出)。
pub fn build_create_table(params: BuildCreateTableParams) -> BuildCreateTableResult {
    build_create_table_inner(params).0
}

fn build_create_table_inner(
    params: BuildCreateTableParams,
) -> (BuildCreateTableResult, Vec<String>) {
    let table = table_reference(&params.spec);
    let mut warnings = Vec::new();

    let mut definitions: Vec<String> = params
        .spec
        .columns
        .iter()
        .map(|column| format!("  {}", column_definition_with(column, &mut warnings)))
        .collect();

    if params.options.with_comments {
        // 列注释已写在列定义里;表注释走表级 COMMENT。
    } else if params
        .spec
        .columns
        .iter()
        .any(|c| !c.comment.trim().is_empty())
    {
        warnings.push("column comments are disabled by options".to_string());
    }

    if params.options.with_indexes {
        for index in &params.spec.indexes {
            match index_definition(index) {
                Ok(definition) => definitions.push(format!("  {definition}")),
                Err(warning) => warnings.push(warning),
            }
        }
    } else if !params.spec.indexes.is_empty() {
        warnings.push("index declarations are disabled by options".to_string());
    }

    if params.options.with_foreign_keys && !params.spec.foreign_keys.is_empty() {
        warnings.push("ClickHouse does not support foreign keys; declarations are ignored".into());
    }

    if params.options.temporary {
        warnings.push("ClickHouse does not support CREATE TEMPORARY TABLE".to_string());
    }

    let if_not_exists = if params.options.if_not_exists {
        " IF NOT EXISTS"
    } else {
        ""
    };

    // 主键:优先 TableSpec.primary_key,其次列上的 is_primary 标记。
    let mut order_by: Vec<String> = params.spec.primary_key.clone();
    for column in &params.spec.columns {
        if column.is_primary && !order_by.iter().any(|name| name == &column.name) {
            order_by.push(column.name.clone());
        }
    }

    let mut sql = format!(
        "CREATE TABLE{if_not_exists} {table} (\n{}\n)",
        definitions.join(",\n")
    );
    sql.push_str(&format!(" ENGINE = {}", table_engine(&params.spec)));
    if !order_by.is_empty() {
        let quoted: Vec<String> = order_by.iter().map(|name| quote_identifier(name)).collect();
        sql.push_str(&format!(" ORDER BY ({})", quoted.join(", ")));
    }
    if let Some(partition_by) = option_string(&params.spec.options, "partition_by") {
        sql.push_str(&format!(" PARTITION BY {partition_by}"));
    }
    if params.options.with_comments
        && let Some(comment) = table_comment(&params.spec)
    {
        sql.push_str(&format!(" COMMENT '{}'", escape_string(&comment)));
    }
    if let Some(settings) = option_string(&params.spec.options, "settings") {
        sql.push_str(&format!(" SETTINGS {settings}"));
    }
    sql.push(';');

    (
        BuildCreateTableResult {
            sql: sql.clone(),
            statements: vec![sql],
        },
        warnings,
    )
}

/// ALTER TABLE:列重命名 → 删除 → 修改 → 新增,以及索引增删。
pub fn build_alter_table(params: BuildAlterTableParams) -> Result<BuildAlterTableResult, String> {
    let table = table_reference(&params.to_spec);
    let mut statements = Vec::new();
    let mut warnings = Vec::new();

    // 1) 重命名必须先于后续按新列名的比较。
    for rename in &params.column_renames {
        if rename.old_name.trim().is_empty() || rename.new_name.trim().is_empty() {
            return Err("column rename requires both old_name and new_name".to_string());
        }
        statements.push(format!(
            "ALTER TABLE {table} RENAME COLUMN {} TO {};",
            quote_identifier(&rename.old_name),
            quote_identifier(&rename.new_name)
        ));
    }
    let renamed_old: HashSet<&str> = params
        .column_renames
        .iter()
        .map(|ColumnRenameSpec { old_name, .. }| old_name.as_str())
        .collect();
    // 新列名 → 旧列名,用于让重命名后的列继续按「同一列」参与修改判断,
    // 而不是被当成新增列再 ADD 一遍。
    let rename_to_old: HashMap<&str, &str> = params
        .column_renames
        .iter()
        .map(|ColumnRenameSpec { old_name, new_name }| (new_name.as_str(), old_name.as_str()))
        .collect();
    let original_column = |name: &str| -> Option<&ColumnSpec> {
        params
            .from_spec
            .columns
            .iter()
            .find(|old| old.name == name)
            .or_else(|| {
                rename_to_old.get(name).and_then(|old_name| {
                    params
                        .from_spec
                        .columns
                        .iter()
                        .find(|c| c.name == *old_name)
                })
            })
    };

    // 2) 删除列。
    let dropped: Vec<&ColumnSpec> = params
        .from_spec
        .columns
        .iter()
        .filter(|old| {
            !renamed_old.contains(old.name.as_str())
                && params
                    .to_spec
                    .columns
                    .iter()
                    .all(|new| new.name != old.name)
        })
        .collect();
    if params.options.allow_destructive {
        for column in dropped {
            statements.push(format!(
                "ALTER TABLE {table} DROP COLUMN {};",
                quote_identifier(&column.name)
            ));
        }
    } else if !dropped.is_empty() {
        warnings.push(format!(
            "{} column(s) would be dropped; enable allow_destructive to generate DROP COLUMN statements",
            dropped.len()
        ));
    }

    // 3) 修改列(类型 / 可空 / 默认值)。
    for column in &params.to_spec.columns {
        let Some(old) = original_column(&column.name) else {
            continue;
        };
        let old_type = effective_type(old);
        let new_type = effective_type(column);
        let type_changed = !old_type.eq_ignore_ascii_case(&new_type);
        let default_changed = old.default.as_deref() != column.default.as_deref();
        if !type_changed && !default_changed {
            continue;
        }
        if !params.options.allow_destructive && (type_changed || old.nullable != column.nullable) {
            warnings.push(format!(
                "column `{}` type/nullability change is destructive; enable allow_destructive to generate MODIFY COLUMN",
                column.name
            ));
            continue;
        }
        if old.nullable != column.nullable {
            warnings.push(format!(
                "column `{}` nullability change rewrites existing data",
                column.name
            ));
        }
        statements.push(format!(
            "ALTER TABLE {table} MODIFY COLUMN {};",
            column_definition(column)
        ));
    }

    // 4) 新增列(重命名后的列已在 from_spec 里存在,不重复 ADD)。
    for column in &params.to_spec.columns {
        if original_column(&column.name).is_some() {
            continue;
        }
        statements.push(format!(
            "ALTER TABLE {table} ADD COLUMN {};",
            column_definition_with(column, &mut warnings)
        ));
    }

    // 5) 索引增删。
    let old_indexes: HashMap<&str, &IndexSpec> = params
        .from_spec
        .indexes
        .iter()
        .map(|index| (index.name.as_str(), index))
        .collect();
    for index in &params.from_spec.indexes {
        if !params
            .to_spec
            .indexes
            .iter()
            .any(|new| new.name == index.name)
        {
            statements.push(format!(
                "ALTER TABLE {table} DROP INDEX {};",
                quote_identifier(&index.name)
            ));
        }
    }
    for index in &params.to_spec.indexes {
        if old_indexes.contains_key(index.name.as_str()) {
            continue;
        }
        match index_definition(index) {
            Ok(definition) => statements.push(format!("ALTER TABLE {table} ADD {definition};")),
            Err(warning) => warnings.push(warning),
        }
    }

    if statements.is_empty() && warnings.is_empty() {
        warnings.push("No changes detected".to_string());
    }

    Ok(BuildAlterTableResult {
        statements,
        // ClickHouse 没有事务,但 DDL 可逆性有限,不生成回滚脚本。
        rollback_statements: Vec::new(),
        warnings,
    })
}

/// DROP TABLE / DROP VIEW IF EXISTS。
pub fn build_drop(params: BuildDropParams) -> BuildDropResult {
    let if_exists = if params.if_exists { " IF EXISTS" } else { "" };
    let database = params
        .database
        .as_deref()
        .or(params.schema.as_deref())
        .filter(|database| !database.trim().is_empty());
    let qualified = match database {
        Some(database) => format!(
            "{}.{}",
            quote_identifier(database.trim()),
            quote_identifier(params.name.trim())
        ),
        None => quote_identifier(params.name.trim()),
    };
    let object = match params.kind {
        ObjectKind::View | ObjectKind::MaterializedView => "VIEW",
        _ => "TABLE",
    };
    BuildDropResult {
        sql: format!("DROP {object}{if_exists} {qualified}"),
    }
}

/// 列定义:`` `name` Type [DEFAULT expr] [COMMENT '...'] ``。
pub fn column_definition(column: &ColumnSpec) -> String {
    column_definition_with(column, &mut Vec::new())
}

fn column_definition_with(column: &ColumnSpec, warnings: &mut Vec<String>) -> String {
    let data_type = column.type_str.trim();
    let data_type = if data_type.is_empty() {
        warnings.push(format!(
            "column `{}` has no type; defaulting to String",
            column.name
        ));
        "String".to_string()
    } else {
        data_type.to_string()
    };
    let data_type = if column.nullable && !is_nullable_type(&data_type) {
        format!("Nullable({data_type})")
    } else {
        data_type
    };

    let mut definition = format!("{} {}", quote_identifier(&column.name), data_type);
    if let Some(default) = column.default.as_deref().map(str::trim)
        && !default.is_empty()
        && !default.eq_ignore_ascii_case("null")
    {
        definition.push_str(&format!(" DEFAULT {default}"));
    }
    if !column.comment.trim().is_empty() {
        definition.push_str(&format!(" COMMENT '{}'", escape_string(&column.comment)));
    }
    if column.auto_increment {
        warnings.push(format!(
            "ClickHouse has no auto increment column; `{}` is created without it",
            column.name
        ));
    }
    if column.is_unique {
        warnings.push(format!(
            "ClickHouse does not enforce UNIQUE constraints; `{}` is created without it",
            column.name
        ));
    }
    definition
}

/// 数据跳过索引定义:`INDEX name expr TYPE type GRANULARITY n`。
fn index_definition(index: &IndexSpec) -> Result<String, String> {
    let expression = index.columns.join(", ");
    if expression.trim().is_empty() {
        return Err(format!("index `{}` has no expression; skipped", index.name));
    }
    if index.is_unique {
        return Err(format!(
            "ClickHouse does not support unique indexes; `{}` is skipped",
            index.name
        ));
    }
    // kind 形如 `minmax` / `bloom_filter` / `bloom_filter(0.01)`;未给出时用 minmax。
    let kind = index
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .unwrap_or("minmax");
    // wire 的 IndexSpec 不含粒度字段,统一用 1;需要更大粒度可在 kind 里
    // 写 `bloom_filter(0.01)` 这类带参类型,粒度仍按 1 生成。
    let granularity = 1;
    if index.where_clause.is_some() {
        // 条件索引在 ClickHouse 用 SETTINGS 或物化视图实现,这里保留表达式。
        tracing::debug!("index `{}` WHERE clause is ignored", index.name);
    }
    Ok(format!(
        "INDEX {} {} TYPE {} GRANULARITY {}",
        quote_identifier(&index.name),
        expression,
        kind,
        granularity
    ))
}

/// 表引用:`` `db`.`table` ``,wire 的 schema 在 ClickHouse 里没有意义。
fn table_reference(spec: &TableSpec) -> String {
    let database = spec
        .database
        .as_deref()
        .filter(|database| !database.trim().is_empty());
    match database {
        Some(database) => format!(
            "{}.{}",
            quote_identifier(database.trim()),
            quote_identifier(spec.name.trim())
        ),
        None => quote_identifier(spec.name.trim()),
    }
}

/// 引擎:TableSpec.options.engine,缺省 MergeTree()。
fn table_engine(spec: &TableSpec) -> String {
    option_string(&spec.options, "engine").unwrap_or_else(|| DEFAULT_ENGINE.to_string())
}

/// 表注释:TableSpec.comment,或 options.comment。
fn table_comment(spec: &TableSpec) -> Option<String> {
    let comment = spec.comment.trim();
    if !comment.is_empty() {
        return Some(comment.to_string());
    }
    option_string(&spec.options, "comment")
}

/// 从 `options` 里取字符串(支持字符串或字符串数组拼接)。
fn option_string(options: &Value, key: &str) -> Option<String> {
    match options.get(key)? {
        Value::String(text) => {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        Value::Array(items) => {
            let values: Vec<String> = items
                .iter()
                .filter_map(|item| item.as_str().map(quote_identifier))
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        }
        Value::Object(_) => options.get(key).map(Value::to_string),
        _ => None,
    }
}

/// 实际类型(含可选包装)。
fn effective_type(column: &ColumnSpec) -> String {
    let data_type = column.type_str.trim();
    if column.nullable && !is_nullable_type(data_type) {
        format!("Nullable({data_type})")
    } else {
        data_type.to_string()
    }
}

fn is_nullable_type(data_type: &str) -> bool {
    data_type
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("nullable(")
}

/// SQL 字符串字面量转义。
fn escape_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

fn decode_payload<T>(payload: Value) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(payload).map_err(|error| error.to_string())
}

fn decode_drop_payload(mut payload: Value, kind: ObjectKind) -> Result<BuildDropParams, String> {
    if let Value::Object(object) = &mut payload
        && !object.contains_key("kind")
    {
        object.insert("kind".to_string(), serde_json::to_value(kind).unwrap());
    }
    decode_payload(payload)
}

fn single_statement(sql: String) -> BuildDdlResult {
    BuildDdlResult {
        statements: vec![sql],
        warnings: Vec::new(),
    }
}

/// 库管理 payload(宿主表单可能用多种键名)。
#[derive(serde::Deserialize)]
struct DatabaseDdlPayload {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    database_name: Option<String>,
    #[serde(default)]
    engine: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    field_values: HashMap<String, String>,
}

impl DatabaseDdlPayload {
    fn database_name(&self) -> Result<String, String> {
        self.name
            .as_deref()
            .or(self.database.as_deref())
            .or(self.database_name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .ok_or_else(|| "database name is required".to_string())
    }

    fn field(&self, key: &str) -> Option<String> {
        self.field_values
            .get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

/// CREATE DATABASE `name` [ENGINE = x] [COMMENT '...']。
fn build_create_database(payload: Value) -> Result<String, String> {
    let payload: DatabaseDdlPayload = decode_payload(payload)?;
    let name = payload.database_name()?;
    let mut sql = format!("CREATE DATABASE {}", quote_identifier(&name));
    if let Some(engine) = payload
        .field("engine")
        .or_else(|| payload.engine.clone())
        .filter(|engine| !engine.is_empty())
    {
        sql.push_str(&format!(" ENGINE = {engine}"));
    }
    if let Some(comment) = payload
        .field("comment")
        .or_else(|| payload.comment.clone())
        .filter(|comment| !comment.is_empty())
    {
        sql.push_str(&format!(" COMMENT '{}'", escape_string(&comment)));
    }
    Ok(sql)
}

/// DROP DATABASE IF EXISTS `name`。
fn build_drop_database(payload: Value) -> Result<String, String> {
    let payload: DatabaseDdlPayload = decode_payload(payload)?;
    Ok(format!(
        "DROP DATABASE IF EXISTS {}",
        quote_identifier(&payload.database_name()?)
    ))
}

/// ClickHouse 不支持 ALTER DATABASE 修改属性,输出注释提示(与主仓一致)。
fn build_modify_database(payload: Value) -> Result<String, String> {
    let payload: DatabaseDdlPayload = decode_payload(payload)?;
    Ok(format!(
        "-- ClickHouse does not support modifying database properties for '{}'",
        payload.database_name()?
    ))
}

#[derive(serde::Deserialize)]
struct RenameTablePayload {
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    old_name: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    new_name: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

/// RENAME TABLE `db`.`old` TO `db`.`new`。
fn build_rename_table(payload: Value) -> Result<String, String> {
    let payload: RenameTablePayload = decode_payload(payload)?;
    let old_name = payload
        .old_name
        .as_deref()
        .or(payload.table.as_deref())
        .or(payload.name.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "table name is required".to_string())?;
    let new_name = payload
        .new_name
        .as_deref()
        .or(payload.to.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "new table name is required".to_string())?;
    let database = payload
        .database
        .as_deref()
        .or(payload.schema.as_deref())
        .map(str::trim)
        .filter(|database| !database.is_empty());

    let (from, to) = match database {
        Some(database) => (
            format!(
                "{}.{}",
                quote_identifier(database),
                quote_identifier(old_name)
            ),
            format!(
                "{}.{}",
                quote_identifier(database),
                quote_identifier(new_name)
            ),
        ),
        None => (quote_identifier(old_name), quote_identifier(new_name)),
    };
    Ok(format!("RENAME TABLE {from} TO {to}"))
}

#[derive(serde::Deserialize)]
struct TableDdlPayload {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    schema: Option<String>,
}

/// TRUNCATE TABLE(ClickHouse 直接支持)。
fn build_truncate_table(payload: Value) -> Result<String, String> {
    let payload: TableDdlPayload = decode_payload(payload)?;
    let table = payload
        .table
        .as_deref()
        .or(payload.name.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "table name is required".to_string())?;
    let database = payload
        .database
        .as_deref()
        .or(payload.schema.as_deref())
        .map(str::trim)
        .filter(|database| !database.is_empty());
    let qualified = match database {
        Some(database) => format!("{}.{}", quote_identifier(database), quote_identifier(table)),
        None => quote_identifier(table),
    };
    Ok(format!("TRUNCATE TABLE {qualified}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use extension_protocol::ddl::{BuildCreateTableParams, CreateTableOptions};
    use serde_json::json;

    fn column(name: &str, type_str: &str) -> ColumnSpec {
        ColumnSpec {
            name: name.into(),
            type_str: type_str.into(),
            nullable: false,
            ..Default::default()
        }
    }

    fn spec() -> TableSpec {
        TableSpec {
            name: "events".into(),
            database: Some("analytics".into()),
            columns: vec![
                column("id", "UInt64"),
                ColumnSpec {
                    nullable: true,
                    default: Some("now()".into()),
                    comment: "ingest time".into(),
                    ..column("ts", "DateTime")
                },
            ],
            primary_key: vec!["id".into()],
            ..Default::default()
        }
    }

    fn create(
        spec: TableSpec,
        options: CreateTableOptions,
    ) -> (BuildCreateTableResult, Vec<String>) {
        build_create_table_inner(BuildCreateTableParams {
            conn_id: None,
            spec,
            options,
        })
    }

    #[test]
    fn create_table_quotes_and_wraps_nullable() {
        let (result, warnings) = create(spec(), CreateTableOptions::default());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            result
                .sql
                .starts_with("CREATE TABLE `analytics`.`events` (\n")
        );
        assert!(result.sql.contains("`id` UInt64"));
        assert!(
            result
                .sql
                .contains("`ts` Nullable(DateTime) DEFAULT now() COMMENT 'ingest time'")
        );
        assert!(result.sql.contains("ENGINE = MergeTree()"));
        assert!(result.sql.contains("ORDER BY (`id`)"));
        assert!(result.sql.ends_with(';'));
    }

    #[test]
    fn create_table_honours_engine_partition_and_comment() {
        let mut spec = spec();
        spec.comment = "user events".into();
        spec.options = json!({ "engine": "ReplacingMergeTree()", "partition_by": "toYYYYMM(ts)" });
        let (result, _) = create(spec, CreateTableOptions::default());
        assert!(result.sql.contains("ENGINE = ReplacingMergeTree()"));
        assert!(result.sql.contains("PARTITION BY toYYYYMM(ts)"));
        assert!(result.sql.contains("COMMENT 'user events'"));
    }

    #[test]
    fn create_table_renders_data_skipping_index() {
        let mut spec = spec();
        spec.indexes = vec![IndexSpec {
            name: "idx_ts".into(),
            columns: vec!["ts".into()],
            kind: Some("bloom_filter".into()),
            is_unique: false,
            where_clause: None,
        }];
        let (result, warnings) = create(spec, CreateTableOptions::default());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            result
                .sql
                .contains("INDEX `idx_ts` ts TYPE bloom_filter GRANULARITY 1")
        );
    }

    #[test]
    fn unsupported_declarations_become_warnings() {
        let mut spec = spec();
        spec.foreign_keys = vec![Default::default()];
        spec.indexes = vec![IndexSpec {
            name: "uniq".into(),
            columns: vec!["id".into()],
            is_unique: true,
            ..Default::default()
        }];
        spec.columns[0].auto_increment = true;
        spec.columns[0].is_unique = true;
        let (result, warnings) = create(spec, CreateTableOptions::default());
        assert!(!result.sql.contains("UNIQUE"));
        assert!(!result.sql.contains("FOREIGN KEY"));
        assert!(warnings.iter().any(|w| w.contains("foreign keys")));
        assert!(warnings.iter().any(|w| w.contains("unique indexes")));
        assert!(warnings.iter().any(|w| w.contains("auto increment")));
    }

    #[test]
    fn if_not_exists_and_temp_flag() {
        let (result, warnings) = create(
            spec(),
            CreateTableOptions {
                if_not_exists: true,
                temporary: true,
                ..Default::default()
            },
        );
        assert!(result.sql.starts_with("CREATE TABLE IF NOT EXISTS"));
        assert!(warnings.iter().any(|w| w.contains("TEMPORARY")));
    }

    fn alter(
        from: TableSpec,
        to: TableSpec,
        renames: Vec<ColumnRenameSpec>,
        allow: bool,
    ) -> BuildAlterTableResult {
        build_alter_table(BuildAlterTableParams {
            conn_id: None,
            from_spec: from,
            to_spec: to,
            column_renames: renames,
            options: extension_protocol::ddl::AlterTableOptions {
                allow_destructive: allow,
                with_rollback: false,
            },
        })
        .unwrap()
    }

    #[test]
    fn alter_renames_before_other_operations() {
        let from = spec();
        let mut to = spec();
        to.columns[0].name = "event_id".into();
        to.primary_key = vec!["event_id".into()];
        let result = alter(
            from,
            to,
            vec![ColumnRenameSpec {
                old_name: "id".into(),
                new_name: "event_id".into(),
            }],
            true,
        );
        assert_eq!(result.statements.len(), 1);
        assert_eq!(
            result.statements[0],
            "ALTER TABLE `analytics`.`events` RENAME COLUMN `id` TO `event_id`;"
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[test]
    fn alter_adds_and_drops_columns_respecting_destructive_flag() {
        let from = spec();
        let mut to = spec();
        to.columns.pop();
        to.columns.push(column("user_id", "UInt64"));

        let guarded = alter(from.clone(), to.clone(), Vec::new(), false);
        // ADD COLUMN 无破坏性,照常生成;DROP COLUMN 被拦下并转成 warning。
        assert_eq!(
            guarded.statements,
            vec!["ALTER TABLE `analytics`.`events` ADD COLUMN `user_id` UInt64;".to_string()]
        );
        assert!(
            guarded
                .warnings
                .iter()
                .any(|w| w.contains("allow_destructive"))
        );

        let destructive = alter(from, to, Vec::new(), true);
        assert_eq!(
            destructive.statements,
            vec![
                "ALTER TABLE `analytics`.`events` DROP COLUMN `ts`;".to_string(),
                "ALTER TABLE `analytics`.`events` ADD COLUMN `user_id` UInt64;".to_string(),
            ]
        );
    }

    #[test]
    fn alter_modifies_type_with_warning_on_nullability() {
        let from = spec();
        let mut to = spec();
        to.columns[1].type_str = "DateTime64(3)".into();
        to.columns[1].nullable = false;
        let result = alter(from, to, Vec::new(), true);
        assert!(
            result
                .statements
                .iter()
                .any(|sql| sql.contains("MODIFY COLUMN `ts` DateTime64(3)"))
        );
        assert!(result.warnings.iter().any(|w| w.contains("nullability")));
    }

    #[test]
    fn alter_reports_no_changes() {
        let result = alter(spec(), spec(), Vec::new(), true);
        assert!(result.statements.is_empty());
        assert_eq!(result.warnings, vec!["No changes detected".to_string()]);
    }

    #[test]
    fn alter_index_add_and_drop() {
        let mut from = spec();
        from.indexes = vec![IndexSpec {
            name: "old_idx".into(),
            columns: vec!["ts".into()],
            ..Default::default()
        }];
        let mut to = spec();
        to.indexes = vec![IndexSpec {
            name: "new_idx".into(),
            columns: vec!["id".into()],
            kind: Some("minmax".into()),
            ..Default::default()
        }];
        let result = alter(from, to, Vec::new(), true);
        assert!(
            result
                .statements
                .contains(&"ALTER TABLE `analytics`.`events` DROP INDEX `old_idx`;".to_string())
        );
        assert!(result.statements.contains(
            &"ALTER TABLE `analytics`.`events` ADD INDEX `new_idx` id TYPE minmax GRANULARITY 1;"
                .to_string()
        ));
    }

    #[test]
    fn drop_uses_object_kind() {
        let table = build_drop(BuildDropParams {
            kind: ObjectKind::Table,
            name: "events".into(),
            schema: None,
            database: Some("analytics".into()),
            if_exists: true,
            cascade: false,
        });
        assert_eq!(table.sql, "DROP TABLE IF EXISTS `analytics`.`events`");

        let view = build_drop(BuildDropParams {
            kind: ObjectKind::MaterializedView,
            name: "mv".into(),
            schema: None,
            database: None,
            if_exists: false,
            cascade: false,
        });
        assert_eq!(view.sql, "DROP VIEW `mv`");
    }

    #[test]
    fn database_operations() {
        let create_sql = build_create_database(json!({
            "database_name": "analytics",
            "engine": "Atomic",
            "comment": "it's mine",
        }))
        .unwrap();
        assert_eq!(
            create_sql,
            "CREATE DATABASE `analytics` ENGINE = Atomic COMMENT 'it''s mine'"
        );

        let create_sql = build_create_database(json!({
            "field_values": { "engine": "Memory", "comment": "cache" },
            "name": "cache_db"
        }))
        .unwrap();
        assert_eq!(
            create_sql,
            "CREATE DATABASE `cache_db` ENGINE = Memory COMMENT 'cache'"
        );

        assert_eq!(
            build_drop_database(json!({ "database": "cache_db" })).unwrap(),
            "DROP DATABASE IF EXISTS `cache_db`"
        );
        assert!(build_create_database(json!({})).is_err());
    }

    #[test]
    fn rename_and_truncate() {
        assert_eq!(
            build_rename_table(json!({
                "database": "analytics",
                "old_name": "events",
                "new_name": "events_v2",
            }))
            .unwrap(),
            "RENAME TABLE `analytics`.`events` TO `analytics`.`events_v2`"
        );
        assert_eq!(
            build_truncate_table(json!({ "database": "analytics", "table": "events" })).unwrap(),
            "TRUNCATE TABLE `analytics`.`events`"
        );
    }

    #[test]
    fn ddl_build_dispatches_create_and_alter() {
        let result = build_ddl(BuildDdlParams {
            conn_id: None,
            op: DdlBuildOp::CreateTable,
            payload: serde_json::to_value(BuildCreateTableParams {
                conn_id: None,
                spec: spec(),
                options: CreateTableOptions::default(),
            })
            .unwrap(),
        })
        .unwrap();
        assert_eq!(result.statements.len(), 1);
        assert!(result.statements[0].starts_with("CREATE TABLE `analytics`.`events`"));

        let dropped = build_ddl(BuildDdlParams {
            conn_id: None,
            op: DdlBuildOp::DropTable,
            payload: json!({ "name": "events", "database": "analytics", "if_exists": true }),
        })
        .unwrap();
        assert_eq!(
            dropped.statements,
            vec!["DROP TABLE IF EXISTS `analytics`.`events`".to_string()]
        );
    }

    #[test]
    fn column_definition_does_not_double_wrap_nullable() {
        let column = ColumnSpec {
            nullable: true,
            ..column("tags", "Nullable(String)")
        };
        assert_eq!(column_definition(&column), "`tags` Nullable(String)");
    }
}
