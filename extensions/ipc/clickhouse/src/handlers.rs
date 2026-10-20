//! ClickHouse 驱动的方法处理函数集合。
//!
//! 每个 handler 接收 `params: &Value`,返回 `Result<Value, ProtocolError>`。
//! 数据面委托给 [`crate::clickhouse_session`],元数据面(`system.*` + `SHOW CREATE`)
//! 委托给 [`crate::metadata`],这里只做参数解码 / 结果编码 / 错误码归类。

// ProtocolError 是 wire 契约类型,Err 类型大小固定,统一 allow。
#![allow(clippy::result_large_err)]

use extension_protocol::conn::{ConnPingParams, ConnTestParams, ConnUseParams};
use extension_protocol::ddl::{
    BuildAlterTableParams, BuildCreateTableParams, BuildDdlParams, BuildDropParams,
};
use extension_protocol::error::{ProtocolError, error_codes};
use extension_protocol::query::{
    BatchError, CursorCancelParams, CursorCloseParams, CursorFetchParams, ExecBatchParams,
    ExecBatchResult, ExecRunParams, ExecRunResult, QueryStartParams,
};
use extension_protocol::schema::{
    ColumnsParams, DumpDdlParams, DumpDdlResult, IndexesParams, ObjectKind, ObjectViewKind,
    ObjectViewParams, ObjectsParams, ViewsParams,
};
use serde_json::Value;

use crate::clickhouse_session::ClickHouseSession;
use crate::metadata;
use crate::protocol::ClickHouseConfig;
use crate::server::{
    invalid_params, missing_param, params_deserialize_error, protocol_error_from_anyhow,
    serialize_error,
};
use crate::state::{ConnectionState, CursorState};

// ===================== Connection =====================

/// `conn/test`:短连接 + `SELECT 1` + 版本探测。
pub async fn handle_conn_test(params: &Value) -> Result<Value, ProtocolError> {
    let started = std::time::Instant::now();
    let p: ConnTestParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    ensure_clickhouse_driver(&p.driver_id)?;

    let config = ClickHouseConfig::from_config_value(&p.config)
        .map_err(|e| invalid_params(format!("invalid connection config: {e}")))?;
    let session = ClickHouseSession::connect(&config)
        .await
        .map_err(|e| protocol_error_from_anyhow(error_codes::IO_CONNECTION_REFUSED, e))?;
    let server_version = session
        .server_version()
        .await
        .map_err(|e| protocol_error_from_anyhow(error_codes::SERVER_CLOSED_CONNECTION, e))?;

    Ok(serde_json::json!({
        "ok": true,
        "server_version": server_version,
        "warnings": [],
        "latency_ms": started.elapsed().as_millis() as u32,
    }))
}

/// `conn/ping`:`SELECT 1` 计时。
pub async fn handle_conn_ping(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let _: ConnPingParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let started = std::time::Instant::now();
    session
        .ping()
        .await
        .map_err(|e| protocol_error_from_anyhow(error_codes::SERVER_CLOSED_CONNECTION, e))?;
    Ok(serde_json::json!({ "latency_ms": started.elapsed().as_millis() as u32 }))
}

/// `conn/use`:切换当前库。
///
/// HTTP 接口无会话状态,驱动的做法是确认库存在后重建 Client 的默认库参数
/// (见 [`ClickHouseSession::use_database`]),对外语义与 `USE db` 一致。
pub async fn handle_conn_use(
    session: &mut ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ConnUseParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if let Some(database) = p.database.as_deref().filter(|db| !db.trim().is_empty()) {
        session
            .use_database(database.trim())
            .await
            .map_err(|e| protocol_error_from_anyhow(error_codes::SQL_OBJECT_NOT_FOUND, e))?;
    }
    Ok(Value::Null)
}

// ===================== Query / Cursor =====================

/// `query/start`:取回 `JSONCompact` 结果集并建立内存缓冲游标。
///
/// `clickhouse` crate 的 HTTP 通道不支持语句级参数绑定(只有 INSERT 的 typed
/// API),`params` 非空时直接报 INVALID_PARAMS,避免静默丢参数。
pub async fn handle_query_start(
    session: &ClickHouseSession,
    state: &mut ConnectionState,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: QueryStartParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if !p.params.is_empty() {
        return Err(invalid_params(
            "ClickHouse HTTP interface does not support bound query parameters; inline the values in SQL",
        ));
    }
    let sql = p.sql.trim();
    if sql.is_empty() {
        return Err(missing_param("sql"));
    }

    let query = session.query_typed(sql, p.max_rows);
    let fetched = match p.timeout_ms {
        Some(ms) if ms > 0 => {
            tokio::time::timeout(std::time::Duration::from_millis(u64::from(ms)), query)
                .await
                .map_err(|_| {
                    ProtocolError::new(
                        error_codes::IO_TIMEOUT,
                        format!("query timed out after {ms}ms"),
                    )
                })?
        }
        _ => query.await,
    }
    .map_err(clickhouse_sql_error)?;

    let (columns, rows) = fetched.unwrap_or_default();
    let cursor_state = CursorState::new(columns.clone(), rows, p.fetch_size, p.max_rows);
    let cursor_id = state.open_cursor(cursor_state);

    Ok(serde_json::json!({
        "cursor_id": cursor_id,
        "columns": columns,
        "row_count_known": false,
        "row_count_estimate": Value::Null,
    }))
}

/// `cursor/fetch`:从缓冲弹出一页。
pub async fn handle_cursor_fetch(
    state: &mut ConnectionState,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: CursorFetchParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let cursor = state
        .get_cursor_mut(&p.cursor_id)
        .ok_or_else(|| unknown_cursor(&p.cursor_id))?;
    let n = cursor.page_size(p.n);
    let (rows, done) = cursor.fetch(n);
    Ok(serde_json::json!({ "rows": rows, "done": done }))
}

/// `cursor/close`:释放游标。
pub async fn handle_cursor_close(
    state: &mut ConnectionState,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: CursorCloseParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if !state.close_cursor(&p.cursor_id) {
        return Err(unknown_cursor(&p.cursor_id));
    }
    Ok(Value::Null)
}

/// `cursor/cancel`:丢弃剩余缓冲,保留游标 id 直到 close。
pub async fn handle_cursor_cancel(
    state: &mut ConnectionState,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: CursorCancelParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let cursor = state
        .get_cursor_mut(&p.cursor_id)
        .ok_or_else(|| unknown_cursor(&p.cursor_id))?;
    cursor.cancel();
    Ok(Value::Null)
}

// ===================== Exec =====================

/// `exec/run`:执行单条非查询语句。
pub async fn handle_exec_run(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ExecRunParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if !p.params.is_empty() {
        return Err(invalid_params(
            "ClickHouse HTTP interface does not support bound statement parameters; inline the values in SQL",
        ));
    }
    let result = exec_statement(session, &p.sql, p.timeout_ms).await?;
    serde_json::to_value(result).map_err(serialize_error)
}

/// `exec/batch`:逐条执行;`stop_on_error` 控制首个错误后是否继续。
///
/// ClickHouse 的 HTTP 通道每次请求独立,没有跨语句事务,
/// `in_transaction` 请求被忽略并在结果 warnings 中说明。
pub async fn handle_exec_batch(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ExecBatchParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;

    let mut results = Vec::with_capacity(p.statements.len());
    let mut errors = Vec::new();
    for (index, sql) in p.statements.iter().enumerate() {
        match exec_statement(session, sql, p.timeout_ms).await {
            Ok(mut result) => {
                if p.in_transaction {
                    result.warnings.push(
                        "ClickHouse does not provide multi-statement transactions over HTTP"
                            .to_string(),
                    );
                }
                results.push(result);
            }
            Err(error) => {
                results.push(ExecRunResult::default());
                errors.push(BatchError {
                    index: index as u32,
                    code: error.code,
                    message: error.message,
                });
                if p.stop_on_error {
                    break;
                }
            }
        }
    }
    serde_json::to_value(ExecBatchResult { results, errors }).map_err(serialize_error)
}

async fn exec_statement(
    session: &ClickHouseSession,
    sql: &str,
    timeout_ms: Option<u32>,
) -> Result<ExecRunResult, ProtocolError> {
    let sql = sql.trim();
    if sql.is_empty() {
        return Err(invalid_params("sql must not be empty"));
    }
    let execution = session.execute(sql);
    let outcome = match timeout_ms {
        Some(ms) if ms > 0 => {
            tokio::time::timeout(std::time::Duration::from_millis(u64::from(ms)), execution)
                .await
                .map_err(|_| {
                    ProtocolError::new(
                        error_codes::IO_TIMEOUT,
                        format!("statement timed out after {ms}ms"),
                    )
                })?
        }
        _ => execution.await,
    };
    outcome.map_err(clickhouse_sql_error)?;

    Ok(ExecRunResult {
        // clickhouse crate 的 execute 不回传受影响行数;不猜测,统一 0。
        affected_rows: 0,
        last_insert_id: None,
        warnings: Vec::new(),
    })
}

// ===================== Schema =====================

/// `schema/databases`:`system.databases`(过滤系统库)。
pub async fn handle_schema_databases(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let _: extension_protocol::schema::DatabasesParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let databases = metadata::databases(session)
        .await
        .map_err(clickhouse_sql_error)?;
    serde_json::to_value(databases).map_err(serialize_error)
}

/// `schema/objects`:按 kinds 返回表 / 视图对象。
pub async fn handle_schema_objects(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ObjectsParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let database = resolve_database(session, p.database.as_deref())?;

    let wants_tables = p.kinds.is_empty() || p.kinds.contains(&ObjectKind::Table);
    let wants_views = p.kinds.is_empty()
        || p.kinds.contains(&ObjectKind::View)
        || p.kinds.contains(&ObjectKind::MaterializedView);

    if !wants_tables && !wants_views {
        return Err(method_not_found(format!(
            "schema/objects supports only table/view kinds for ClickHouse (requested {:?})",
            p.kinds
        )));
    }

    let mut objects = Vec::new();
    if wants_tables {
        objects.extend(
            metadata::tables(session, &database)
                .await
                .map_err(clickhouse_sql_error)?,
        );
    }
    if wants_views {
        objects.extend(
            metadata::view_objects(session, &database)
                .await
                .map_err(clickhouse_sql_error)?,
        );
    }
    objects.sort_by(|a, b| a.name.cmp(&b.name));
    serde_json::to_value(objects).map_err(serialize_error)
}

/// `schema/columns`:`system.columns` 列详情。
pub async fn handle_schema_columns(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ColumnsParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if p.table.trim().is_empty() {
        return Err(missing_param("table"));
    }
    let database = resolve_database(session, p.database.as_deref())?;
    let columns = metadata::columns(session, &database, p.table.trim())
        .await
        .map_err(clickhouse_sql_error)?;
    serde_json::to_value(columns).map_err(serialize_error)
}

/// `schema/indexes`:`system.data_skipping_indices`。
pub async fn handle_schema_indexes(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: IndexesParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    if p.table.trim().is_empty() {
        return Err(missing_param("table"));
    }
    let database = resolve_database(session, p.database.as_deref())?;
    let indexes = metadata::indexes(session, &database, p.table.trim())
        .await
        .map_err(clickhouse_sql_error)?;
    serde_json::to_value(indexes).map_err(serialize_error)
}

/// `schema/views`:`system.tables` 里 engine 为 View/MaterializedView 的对象。
pub async fn handle_schema_views(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ViewsParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let database = resolve_database(session, p.database.as_deref())?;
    let views = metadata::views(session, &database)
        .await
        .map_err(clickhouse_sql_error)?;
    serde_json::to_value(views).map_err(serialize_error)
}

/// `schema/functions`:`system.functions WHERE origin = 'SQLUserDefined'`。
pub async fn handle_schema_functions(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let _: extension_protocol::schema::FunctionsParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let functions = metadata::functions(session)
        .await
        .map_err(clickhouse_sql_error)?;
    serde_json::to_value(functions).map_err(serialize_error)
}

/// `schema/dump_ddl`:官方 DDL——`SHOW CREATE TABLE`。
pub async fn handle_schema_dump_ddl(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: DumpDdlParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let mut statements = Vec::new();
    for object in &p.objects {
        if !matches!(
            object.kind,
            ObjectKind::Table | ObjectKind::View | ObjectKind::MaterializedView
        ) {
            continue;
        }
        let table = object.name.trim();
        if table.is_empty() {
            continue;
        }
        let database = resolve_database(session, object.database.as_deref())?;
        let ddl = metadata::table_ddl(session, &database, table)
            .await
            .map_err(clickhouse_sql_error)?;
        statements.push(ddl);
    }
    serde_json::to_value(DumpDdlResult { statements }).map_err(serialize_error)
}

/// `schema/object_view`:ClickHouse 方言的列视图。
pub async fn handle_schema_object_view(
    session: &ClickHouseSession,
    params: &Value,
) -> Result<Value, ProtocolError> {
    let p: ObjectViewParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let view = match p.view {
        ObjectViewKind::Databases => {
            let databases = metadata::databases(session)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::databases_object_view(&databases)
        }
        ObjectViewKind::Tables => {
            let database = resolve_database(session, p.database.as_deref())?;
            let tables = metadata::tables(session, &database)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::tables_object_view(&tables)
        }
        ObjectViewKind::Columns => {
            let table = required_table(&p)?;
            let database = resolve_database(session, p.database.as_deref())?;
            let columns = metadata::columns(session, &database, &table)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::columns_object_view(&columns)
        }
        ObjectViewKind::Indexes => {
            let table = required_table(&p)?;
            let database = resolve_database(session, p.database.as_deref())?;
            let indexes = metadata::indexes(session, &database, &table)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::indexes_object_view(&indexes)
        }
        ObjectViewKind::Views => {
            let database = resolve_database(session, p.database.as_deref())?;
            let views = metadata::views(session, &database)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::views_object_view(&views)
        }
        ObjectViewKind::Functions => {
            let functions = metadata::functions(session)
                .await
                .map_err(clickhouse_sql_error)?;
            metadata::functions_object_view(&functions)
        }
        other => {
            return Err(method_not_found(format!(
                "ClickHouse driver does not provide object view `{}`",
                other.as_str()
            )));
        }
    };
    serde_json::to_value(view).map_err(serialize_error)
}

fn required_table(p: &ObjectViewParams) -> Result<String, ProtocolError> {
    p.table
        .as_deref()
        .map(str::trim)
        .filter(|table| !table.is_empty())
        .map(str::to_string)
        .ok_or_else(|| missing_param("table"))
}

// ===================== DDL builder =====================

pub fn handle_ddl_build(params: &Value) -> Result<Value, ProtocolError> {
    let p: BuildDdlParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let result = crate::ddl::build_ddl(p).map_err(invalid_params)?;
    serde_json::to_value(result).map_err(serialize_error)
}

pub fn handle_ddl_build_create_table(params: &Value) -> Result<Value, ProtocolError> {
    let p: BuildCreateTableParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    serde_json::to_value(crate::ddl::build_create_table(p)).map_err(serialize_error)
}

pub fn handle_ddl_build_alter_table(params: &Value) -> Result<Value, ProtocolError> {
    let p: BuildAlterTableParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    let result = crate::ddl::build_alter_table(p).map_err(invalid_params)?;
    serde_json::to_value(result).map_err(serialize_error)
}

pub fn handle_ddl_build_drop(params: &Value) -> Result<Value, ProtocolError> {
    let p: BuildDropParams =
        serde_json::from_value(params.clone()).map_err(params_deserialize_error)?;
    serde_json::to_value(crate::ddl::build_drop(p)).map_err(serialize_error)
}

// ===================== Helpers =====================

/// 校验 driver_id 必须是 clickhouse。
pub fn ensure_clickhouse_driver(driver_id: &str) -> Result<(), ProtocolError> {
    if driver_id != "clickhouse" {
        return Err(invalid_params(format!(
            "unsupported driver_id `{driver_id}` (this driver only handles `clickhouse`)"
        )));
    }
    Ok(())
}

/// 解析目标库:显式 database 优先,否则取连接当前库。
///
/// ClickHouse 的表必须隶属某个库,连接未指定库时需要宿主显式传入。
fn resolve_database(
    session: &ClickHouseSession,
    database: Option<&str>,
) -> Result<String, ProtocolError> {
    if let Some(database) = database.filter(|database| !database.trim().is_empty()) {
        return Ok(database.trim().to_string());
    }
    session
        .current_database()
        .filter(|database| !metadata::is_hidden_database(database))
        .ok_or_else(|| {
            invalid_params("database is required: no database selected on this connection")
        })
}

fn unknown_cursor(id: &str) -> ProtocolError {
    ProtocolError::new(
        error_codes::UNKNOWN_CURSOR_ID,
        format!("unknown cursor_id `{id}`"),
    )
}

fn method_not_found(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(error_codes::METHOD_NOT_FOUND, message)
}

/// ClickHouse 错误 → 按文本保守归类错误码。
fn clickhouse_sql_error(error: anyhow::Error) -> ProtocolError {
    let code = classify_clickhouse_error(&error.to_string());
    protocol_error_from_anyhow(code, error)
}

/// 服务端错误文本归类(表不存在 / 已存在 / 鉴权 / 超时 / 连接失败)。
fn classify_clickhouse_error(message: &str) -> i32 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("connection refused")
        || lower.contains("failed to connect")
        || lower.contains("dns error")
        || lower.contains("tcp connect error")
    {
        error_codes::IO_CONNECTION_REFUSED
    } else if lower.contains("authentication failed")
        || lower.contains("password is incorrect")
        || lower.contains("unknown user")
        || lower.contains("code: 516")
    {
        error_codes::AUTH_FAILED
    } else if lower.contains("timeout") || lower.contains("timed out") {
        error_codes::IO_TIMEOUT
    } else if lower.contains("already exists")
        || lower.contains("code: 57")
        || lower.contains("code: 81")
    {
        error_codes::SQL_OBJECT_ALREADY_EXISTS
    } else if lower.contains("unknown table")
        || lower.contains("unknown database")
        || lower.contains("doesn't exist")
        || lower.contains("does not exist")
        || lower.contains("code: 60")
    {
        error_codes::SQL_UNKNOWN_TABLE
    } else {
        error_codes::SQL_SYNTAX_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_id_guard_rejects_other_drivers() {
        assert!(ensure_clickhouse_driver("clickhouse").is_ok());
        let error = ensure_clickhouse_driver("mysql").unwrap_err();
        assert_eq!(error.code, error_codes::INVALID_PARAMS);
        assert!(error.message.contains("mysql"));
    }

    #[test]
    fn error_classification_covers_common_server_codes() {
        assert_eq!(
            classify_clickhouse_error("Code: 60. DB::Exception: Table default.x doesn't exist"),
            error_codes::SQL_UNKNOWN_TABLE
        );
        assert_eq!(
            classify_clickhouse_error("Code: 81. DB::Exception: Database analytics already exists"),
            error_codes::SQL_OBJECT_ALREADY_EXISTS
        );
        assert_eq!(
            classify_clickhouse_error("Code: 516. DB::Exception: default: Authentication failed"),
            error_codes::AUTH_FAILED
        );
        assert_eq!(
            classify_clickhouse_error("tcp connect error: Connection refused (os error 61)"),
            error_codes::IO_CONNECTION_REFUSED
        );
        assert_eq!(
            classify_clickhouse_error("Code: 62. DB::Exception: Syntax error"),
            error_codes::SQL_SYNTAX_ERROR
        );
    }

    #[test]
    fn required_table_rejects_blank() {
        let params = ObjectViewParams {
            conn_id: 1,
            view: ObjectViewKind::Columns,
            database: None,
            schema: None,
            table: Some("  ".into()),
        };
        assert_eq!(
            required_table(&params).unwrap_err().code,
            error_codes::INVALID_PARAMS
        );
    }
}
