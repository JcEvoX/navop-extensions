//! ClickHouse IPC 驱动扩展(`clickhouse_driver`)。
//!
//! 基于 [`extension_driver`] 的 Tokio-first 运行时([`extension_driver::serve_async`])
//! 实现 database wire 协议;连接层复用官方 `clickhouse` crate 的 HTTP 接口
//! (默认 8123 端口,可选 LZ4 压缩与 HTTPS)。
//!
//! 模块划分对齐 tdengine / duckdb IPC 驱动:
//! - `driver`:控制面 / 工厂(init / conn/open / connless 纯方法)。
//! - `handlers`:全部 wire 方法的处理函数。
//! - `clickhouse_session`:clickhouse 客户端封装(连接、查询、执行、结果映射)。
//! - `metadata`:`system.*` 元数据查询与对象视图映射,逻辑移植自主仓
//!   `crates/db/src/clickhouse/plugin.rs`。
//! - `protocol`:连接配置解析与 HTTP endpoint 构造(移植自主仓
//!   `crates/db/src/clickhouse/connection.rs`)。
//! - `value`:`JSONCompact` 值 → wire `CellValue` / `ColumnSpec` 映射(移植自
//!   主仓 `crates/db/src/clickhouse/codec.rs`)。
//! - `state`:每连接的游标状态机。
//! - `ddl`:ClickHouse 方言的 DDL 构造。
//! - `server`:transport 接入与共享错误 helper。

pub mod clickhouse_session;
pub mod ddl;
pub mod driver;
pub mod handlers;
pub mod metadata;
pub mod protocol;
pub mod server;
pub mod state;
pub mod value;
