//! ClickHouse IPC 驱动的端到端测试(不依赖真实 ClickHouse 服务端)。
//!
//! 仿 tdengine / duckdb 的 tests/:用 `tokio::io::duplex` 内存 transport 拉起驱动
//! server(`clickhouse_driver::server::handle_stream`),再以 `extension-host` 的
//! JsonRpcClient 走完整 wire 协议:
//! - init 握手与 methods/features 声明;
//! - `$/ping`、重复 init、未 init 先调方法等协议行为;
//! - `conn/test` / `conn/open` 的失败路径(连接不可达端口);
//! - `ddl/build*` 纯方法在无连接状态下可用。

use std::time::Duration;

use extension_host::{FramedTransport, HostError, JsonRpcClient, RequestOptions};
use extension_protocol::conn::ConnOpenParams;
use extension_protocol::error::error_codes;
use extension_protocol::lifecycle::{Capability, InitParams, InitResult};
use extension_protocol::method;
use serde_json::{Value, json};

/// 与 driver.json `methods` / `src/driver.rs::declared_methods` 保持一致的全集。
const DECLARED_METHODS: &[&str] = &[
    method::PING,
    method::SHUTDOWN,
    method::CONN_TEST,
    method::CONN_OPEN,
    method::CONN_CLOSE,
    method::CONN_PING,
    method::CONN_USE,
    method::QUERY_START,
    method::CURSOR_FETCH,
    method::CURSOR_CLOSE,
    method::CURSOR_CANCEL,
    method::EXEC_RUN,
    method::EXEC_BATCH,
    method::SCHEMA_OBJECT_VIEW,
    method::SCHEMA_DATABASES,
    method::SCHEMA_OBJECTS,
    method::SCHEMA_COLUMNS,
    method::SCHEMA_INDEXES,
    method::SCHEMA_VIEWS,
    method::SCHEMA_FUNCTIONS,
    method::SCHEMA_DUMP_DDL,
    method::DDL_BUILD,
    method::DDL_BUILD_CREATE_TABLE,
    method::DDL_BUILD_ALTER_TABLE,
    method::DDL_BUILD_DROP,
];

type JsonRpcClientHandle = extension_host::JsonRpcClientHandle;

/// 拉起内存 transport 的驱动 server。
async fn start_driver() -> (
    JsonRpcClient,
    JsonRpcClientHandle,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (client_stream, server_stream) = tokio::io::duplex(1024 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let server = tokio::spawn(async move {
        clickhouse_driver::server::handle_stream(server_reader, server_writer).await
    });
    let (reader, writer) = tokio::io::split(client_stream);
    let client = JsonRpcClient::start(FramedTransport::new(reader, writer));
    let handle = client.handle();
    (client, handle, server)
}

/// 不可达的连接目标:127.0.0.1 的 tcpmux 保留端口,本地必然连接拒绝。
fn unreachable_config() -> Value {
    json!({
        "host": "127.0.0.1",
        "port": 1,
        "username": "default",
        "password": "",
        "connect_timeout": 3,
    })
}

async fn init(handle: &JsonRpcClientHandle, timeout: &RequestOptions) -> InitResult {
    handle
        .call(
            method::INIT,
            serde_json::to_value(InitParams::new("0.10.0", "clickhouse-e2e")).unwrap(),
            timeout.clone(),
        )
        .await
        .expect("init should succeed")
}

#[tokio::test]
async fn clickhouse_driver_declares_full_method_set() {
    let (client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(5));

    let ping: Value = handle
        .call(method::PING, json!({}), timeout.clone())
        .await
        .expect("$/ping should answer before init");
    assert_eq!(Some(true), ping["pong"].as_bool());

    let init = init(&handle, &timeout).await;
    assert_eq!(init.extension_version, env!("CARGO_PKG_VERSION"));
    assert!(init.has_feature(Capability::RICH_ERRORS));
    assert!(init.has_feature(Capability::DDL_BUILDER));
    assert!(init.has_feature(Capability::BATCH_EXEC));
    assert!(init.has_feature(Capability::SCHEMA_INTROSPECTION));
    // ClickHouse HTTP 通道没有多语句事务,不应声明。
    assert!(!init.has_feature(Capability::TRANSACTIONS));
    assert!(init.drivers_ready.iter().any(|d| d == "clickhouse"));
    for method_name in DECLARED_METHODS {
        assert!(
            init.declares_method(method_name),
            "init result should declare {method_name}"
        );
    }

    client_shutdown(client, server).await;
}

#[tokio::test]
async fn method_calls_before_init_are_rejected() {
    let (client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(5));

    let err = handle
        .call_raw(
            method::CONN_TEST,
            json!({ "driver_id": "clickhouse", "config": unreachable_config() }),
            timeout.clone(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::NOT_INITIALIZED
        ),
        "expected NOT_INITIALIZED before init, got {err:?}"
    );

    let _ = init(&handle, &timeout).await;
    let err = handle
        .call_raw(
            method::INIT,
            serde_json::to_value(InitParams::new("0.10.0", "clickhouse-e2e-2")).unwrap(),
            timeout,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::ALREADY_INITIALIZED
        ),
        "expected ALREADY_INITIALIZED on second init, got {err:?}"
    );

    client_shutdown(client, server).await;
}

#[tokio::test]
async fn conn_test_failure_path_reports_connection_refused() {
    let (client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(20));

    let _ = init(&handle, &timeout).await;
    let err = handle
        .call_raw(
            method::CONN_TEST,
            json!({ "driver_id": "clickhouse", "config": unreachable_config() }),
            timeout.clone(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::IO_CONNECTION_REFUSED
        ),
        "expected IO_CONNECTION_REFUSED for unreachable host, got {err:?}"
    );

    // 错误 driver_id 在连接之前即被拒绝。
    let err = handle
        .call_raw(
            method::CONN_TEST,
            json!({ "driver_id": "postgres", "config": unreachable_config() }),
            timeout,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::INVALID_PARAMS
        ),
        "expected INVALID_PARAMS for foreign driver_id, got {err:?}"
    );

    client_shutdown(client, server).await;
}

#[tokio::test]
async fn conn_open_failure_path_reports_connection_refused() {
    let (client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(20));

    let _ = init(&handle, &timeout).await;
    let err = handle
        .call_raw(
            method::CONN_OPEN,
            serde_json::to_value(ConnOpenParams::new("clickhouse", unreachable_config())).unwrap(),
            timeout,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::IO_CONNECTION_REFUSED
        ),
        "expected IO_CONNECTION_REFUSED for conn/open failure, got {err:?}"
    );

    client_shutdown(client, server).await;
}

#[tokio::test]
async fn connless_ddl_builders_work_without_connection() {
    let (client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(5));

    let _ = init(&handle, &timeout).await;

    // ddl/build:create_database → CREATE DATABASE ... ENGINE/COMMENT。
    let create_db: Value = handle
        .call(
            method::DDL_BUILD,
            json!({
                "op": "create_database",
                "payload": { "database_name": "metrics", "engine": "Atomic", "comment": "it's mine" }
            }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build create_database should succeed");
    assert_eq!(
        create_db["statements"][0],
        "CREATE DATABASE `metrics` ENGINE = Atomic COMMENT 'it''s mine'",
        "unexpected create_database statement: {create_db}"
    );

    // ddl/build:drop_database → DROP DATABASE IF EXISTS。
    let drop_db: Value = handle
        .call(
            method::DDL_BUILD,
            json!({ "op": "drop_database", "payload": { "name": "log_db" } }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build drop_database should succeed");
    assert_eq!(drop_db["statements"][0], "DROP DATABASE IF EXISTS `log_db`");

    // ddl/build:rename_table → RENAME TABLE(ClickHouse 用独立语句而非 ALTER)。
    let rename: Value = handle
        .call(
            method::DDL_BUILD,
            json!({ "op": "rename_table", "payload": { "database": "db1", "old_name": "t1", "new_name": "t2" } }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build rename_table should succeed");
    assert_eq!(
        rename["statements"][0],
        "RENAME TABLE `db1`.`t1` TO `db1`.`t2`"
    );

    // ddl/build:truncate_table。
    let truncate: Value = handle
        .call(
            method::DDL_BUILD,
            json!({ "op": "truncate_table", "payload": { "database": "db1", "table": "t1" } }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build truncate_table should succeed");
    assert_eq!(truncate["statements"][0], "TRUNCATE TABLE `db1`.`t1`");

    // ddl/build_create_table:库限定名 + Nullable 包装 + ENGINE/ORDER BY。
    let create_table: Value = handle
        .call(
            method::DDL_BUILD_CREATE_TABLE,
            json!({
                "spec": {
                    "name": "events",
                    "database": "analytics",
                    "columns": [
                        { "name": "id", "type": "UInt64", "nullable": false },
                        { "name": "ts", "type": "DateTime", "nullable": true, "default": "now()" }
                    ],
                    "primary_key": ["id"],
                    "options": { "engine": "MergeTree()", "partition_by": "toYYYYMM(ts)" }
                },
                "options": { "if_not_exists": true }
            }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build_create_table should succeed");
    assert_eq!(
        create_table["sql"],
        "CREATE TABLE IF NOT EXISTS `analytics`.`events` (\n  `id` UInt64,\n  `ts` Nullable(DateTime) DEFAULT now()\n) ENGINE = MergeTree() ORDER BY (`id`) PARTITION BY toYYYYMM(ts);"
    );

    // ddl/build_drop:表。
    let drop: Value = handle
        .call(
            method::DDL_BUILD_DROP,
            json!({
                "kind": "table",
                "name": "events",
                "database": "analytics",
                "if_exists": true
            }),
            timeout.clone(),
        )
        .await
        .expect("ddl/build_drop should succeed");
    assert_eq!(drop["sql"], "DROP TABLE IF EXISTS `analytics`.`events`");

    // 未实现的 connless 方法 → METHOD_NOT_FOUND。
    let err = handle
        .call_raw(method::SQL_FORMAT, json!({ "sql": "SELECT 1" }), timeout)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            HostError::Protocol(pe) if pe.code == error_codes::METHOD_NOT_FOUND
        ),
        "expected METHOD_NOT_FOUND for sql/format, got {err:?}"
    );

    client_shutdown(client, server).await;
}

#[tokio::test]
async fn shutdown_acknowledges_and_closes_transport() {
    let (_client, handle, server) = start_driver().await;
    let timeout = RequestOptions::default().with_timeout(Duration::from_secs(5));

    let _: Value = handle
        .call(method::SHUTDOWN, json!({ "grace_ms": 100 }), timeout)
        .await
        .expect("shutdown should be acknowledged");

    let result = server.await.expect("server task should join cleanly");
    result.expect("server should exit without error");
}

/// 关闭客户端并中止 server task。
async fn client_shutdown(
    client: JsonRpcClient,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    client.shutdown().await;
    server.abort();
}
