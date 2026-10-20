//! `JSONCompact` 值 → wire [`CellValue`] / [`ColumnSpec`] 映射。
//!
//! 逻辑移植自主仓 `crates/db/src/clickhouse/codec.rs`,但输出改成扩展 wire 的
//! 类型化 IR(主仓用的是 `db_value::DbValue`)。
//!
//! 关键取舍:
//! - 数值/布尔/时间/UUID 保持类型化,host 可以按类型渲染与排序;
//! - `Decimal` 走字符串,保留精确位数(不经浮点);
//! - `Array`/`Tuple`/`Map`/`JSON` 在 JSONCompact 里本来就是结构化 JSON,直接
//!   交给 [`CellValue::Json`],不做猜测性解码;
//! - `String`/`FixedString` 的原始字节在 JSONCompact 链路已经过一次 JSON
//!   字符串化,这里按文本承载(与主仓 `LegacyText` 的展示语义一致);
//! - 未知/无法识别的值不伪造类型,降级为文本展示。

use extension_protocol::row::{CellValue, ColumnSpec, ColumnTypeKind};
use serde_json::Value;

/// 逐层剥离 `Nullable(...)` / `LowCardinality(...)` 包装,返回内层类型。
pub fn strip_wrappers(data_type: &str) -> &str {
    let mut current = data_type.trim();
    loop {
        let lower = current.to_ascii_lowercase();
        let inner = if lower.starts_with("nullable(") {
            &current["nullable(".len()..]
        } else if lower.starts_with("lowcardinality(") {
            &current["lowcardinality(".len()..]
        } else {
            return current;
        };
        let Some(inner) = inner.strip_suffix(')') else {
            return current;
        };
        current = inner.trim();
    }
}

/// 取类型基本名(去掉参数),例如 `"DateTime64(3, 'UTC')"` → `"DATETIME64"`。
pub fn base_type(data_type: &str) -> String {
    let stripped = strip_wrappers(data_type);
    let end = stripped.find('(').unwrap_or(stripped.len());
    stripped[..end].trim().to_ascii_uppercase()
}

/// 是否被 `Nullable(...)` 包裹(含 `LowCardinality(Nullable(...))`)。
pub fn is_nullable(data_type: &str) -> bool {
    let mut current = data_type.trim();
    loop {
        let lower = current.to_ascii_lowercase();
        if lower.starts_with("nullable(") {
            return true;
        }
        let Some(inner) = lower
            .starts_with("lowcardinality(")
            .then(|| &current["lowcardinality(".len()..])
        else {
            return false;
        };
        let Some(inner) = inner.strip_suffix(')') else {
            return false;
        };
        current = inner.trim();
    }
}

/// 声明类型 → wire 粗粒度类型。
pub fn type_kind_of(data_type: &str) -> ColumnTypeKind {
    use ColumnTypeKind as K;
    match base_type(data_type).as_str() {
        "BOOL" => K::Bool,
        "INT8" | "INT16" | "INT32" | "INT64" | "INT128" | "INT256" => K::I64,
        "UINT8" | "UINT16" | "UINT32" | "UINT64" | "UINT128" | "UINT256" => K::U64,
        "FLOAT32" | "FLOAT64" => K::F64,
        "DECIMAL" | "DECIMAL32" | "DECIMAL64" | "DECIMAL128" | "DECIMAL256" => K::Decimal,
        "DATE" | "DATE32" => K::Date,
        "DATETIME" | "DATETIME64" => K::Datetime,
        "TIME" | "TIME64" => K::Time,
        "UUID" => K::Uuid,
        "JSON" | "OBJECT" => K::Json,
        "ARRAY" | "TUPLE" | "MAP" | "NESTED" => K::Json,
        "STRING" | "FIXEDSTRING" | "ENUM8" | "ENUM16" | "IPV4" | "IPV6" | "INTERVAL" => K::Text,
        _ => K::Text,
    }
}

/// 结果集列描述。
pub fn column_spec(name: &str, data_type: &str) -> ColumnSpec {
    let mut spec =
        ColumnSpec::new(name, data_type, type_kind_of(data_type)).nullable(is_nullable(data_type));
    match base_type(data_type).as_str() {
        "DECIMAL" => {
            if let Some((precision, scale)) = decimal_precision_scale(data_type) {
                spec = spec.precision(precision).scale(scale as i32);
            }
        }
        "FIXEDSTRING" => {
            if let Some(length) = first_numeric_argument(data_type) {
                spec = spec.max_length(length);
            }
        }
        _ => {}
    }
    spec
}

/// `Decimal(p, s)` → (p, s)。
fn decimal_precision_scale(data_type: &str) -> Option<(u32, u32)> {
    let args = type_arguments(data_type)?;
    let mut parts = args.split(',');
    let precision = parts.next()?.trim().parse::<u32>().ok()?;
    let scale = parts.next().unwrap_or("0").trim().parse::<u32>().ok()?;
    Some((precision, scale))
}

/// 第一个数值参数,例如 `FixedString(16)` → 16。
fn first_numeric_argument(data_type: &str) -> Option<u32> {
    type_arguments(data_type)?
        .split(',')
        .next()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// 取最内层类型的参数列表(剥掉 Nullable/LowCardinality 包装)。
fn type_arguments(data_type: &str) -> Option<&str> {
    let stripped = strip_wrappers(data_type);
    let start = stripped.find('(')?;
    let end = stripped.rfind(')')?;
    (end > start).then(|| &stripped[start + 1..end])
}

/// 解码单个单元格。
pub fn decode_cell(data_type: &str, value: &Value) -> CellValue {
    if value.is_null() {
        return CellValue::Null;
    }
    let kind = type_kind_of(data_type);
    let base = base_type(data_type);
    match base.as_str() {
        "BOOL" => decode_bool(value),
        "INT8" | "INT16" | "INT32" | "INT64" | "INT128" | "INT256" => decode_i64(value),
        "UINT8" | "UINT16" | "UINT32" | "UINT64" | "UINT128" | "UINT256" => decode_u64(value),
        "FLOAT32" | "FLOAT64" => decode_f64(value),
        "DECIMAL" | "DECIMAL32" | "DECIMAL64" | "DECIMAL128" | "DECIMAL256" => {
            match json_scalar_text(value) {
                Some(text) => CellValue::Decimal { value: text },
                None => fallback(value),
            }
        }
        "DATE" | "DATE32" => match json_text(value) {
            Some(text) => CellValue::Date { value: text },
            None => fallback(value),
        },
        "DATETIME" | "DATETIME64" => match json_text(value) {
            Some(text) => CellValue::Datetime {
                value: normalize_datetime(&text),
            },
            None => fallback(value),
        },
        "TIME" | "TIME64" => match json_text(value) {
            Some(text) => CellValue::Time { value: text },
            None => fallback(value),
        },
        "UUID" => match json_text(value) {
            Some(text) => CellValue::Uuid { value: text },
            None => fallback(value),
        },
        "ENUM8" | "ENUM16" | "IPV4" | "IPV6" | "STRING" | "FIXEDSTRING" => match json_text(value) {
            Some(mut text) => {
                if base == "FIXEDSTRING" {
                    text = text.trim_end_matches('\0').to_string();
                }
                CellValue::Text { value: text }
            }
            None => fallback(value),
        },
        "JSON" | "OBJECT" | "ARRAY" | "TUPLE" | "MAP" | "NESTED" => match value {
            Value::Object(_) | Value::Array(_) => CellValue::Json {
                value: value.clone(),
            },
            _ => CellValue::Text {
                value: json_scalar_text(value).unwrap_or_else(|| value.to_string()),
            },
        },
        _ => match kind {
            ColumnTypeKind::Text => CellValue::Text {
                value: json_scalar_text(value).unwrap_or_else(|| value.to_string()),
            },
            _ => fallback(value),
        },
    }
}

fn decode_bool(value: &Value) -> CellValue {
    match value {
        Value::Bool(flag) => CellValue::Bool { value: *flag },
        Value::Number(number) => match number.as_u64() {
            Some(0) => CellValue::Bool { value: false },
            Some(1) => CellValue::Bool { value: true },
            _ => fallback(value),
        },
        Value::String(text) => match text.as_str() {
            "true" | "1" => CellValue::Bool { value: true },
            "false" | "0" => CellValue::Bool { value: false },
            _ => fallback(value),
        },
        _ => fallback(value),
    }
}

fn decode_i64(value: &Value) -> CellValue {
    let parsed = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    };
    match parsed {
        Some(inner) => CellValue::I64 { value: inner },
        // 超出 i64 的 Int128/Int256 仍按文本保留精确位数。
        None => match json_scalar_text(value) {
            Some(text) => CellValue::Text { value: text },
            None => fallback(value),
        },
    }
}

fn decode_u64(value: &Value) -> CellValue {
    let parsed = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    match parsed {
        Some(inner) => CellValue::U64 { value: inner },
        None => match json_scalar_text(value) {
            Some(text) => CellValue::Text { value: text },
            None => fallback(value),
        },
    }
}

fn decode_f64(value: &Value) -> CellValue {
    let parsed = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    };
    match parsed {
        Some(inner) => CellValue::F64 { value: inner },
        None => match json_scalar_text(value) {
            Some(text) => CellValue::Text { value: text },
            None => fallback(value),
        },
    }
}

/// 标量 → 文本(字符串不带引号,数字/布尔用自身字面量)。
fn json_scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// `YYYY-MM-DD HH:MM:SS[.fff]` → `YYYY-MM-DDTHH:MM:SS[.fff]`(已带 T 的保持原样)。
fn normalize_datetime(text: &str) -> String {
    match text.split_once(' ') {
        Some((date, time)) if date.len() == 10 => format!("{date}T{time}"),
        _ => text.to_string(),
    }
}

/// 无法类型化的值:对象/数组保留 JSON,标量降级为文本。
fn fallback(value: &Value) -> CellValue {
    match value {
        Value::Object(_) | Value::Array(_) => CellValue::Json {
            value: value.clone(),
        },
        other => CellValue::Text {
            value: json_scalar_text(other).unwrap_or_else(|| other.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode(data_type: &str, value: Value) -> CellValue {
        decode_cell(data_type, &value)
    }

    #[test]
    fn null_is_sql_null() {
        assert_eq!(decode("Nullable(String)", Value::Null), CellValue::Null);
        assert_eq!(decode("Nullable(Int64)", Value::Null), CellValue::Null);
    }

    #[test]
    fn bool_decodes_from_bool_number_and_string() {
        assert_eq!(decode("Bool", json!(true)), CellValue::Bool { value: true });
        assert_eq!(decode("Bool", json!(1)), CellValue::Bool { value: true });
        assert_eq!(
            decode("Bool", json!("false")),
            CellValue::Bool { value: false }
        );
    }

    #[test]
    fn integers_keep_width_and_fall_back_to_text_when_huge() {
        assert_eq!(decode("Int32", json!(-300)), CellValue::I64 { value: -300 });
        assert_eq!(
            decode("UInt64", json!("18446744073709551615")),
            CellValue::U64 {
                value: 18446744073709551615
            }
        );
        // Int128 超过 u64/i64 时按文本保留精确数字。
        assert_eq!(
            decode("Int128", json!("170141183460469231731687303715884105727")),
            CellValue::Text {
                value: "170141183460469231731687303715884105727".into()
            }
        );
    }

    #[test]
    fn floats_and_decimal_keep_precision_semantics() {
        assert_eq!(decode("Float64", json!(1.5)), CellValue::F64 { value: 1.5 });
        // NaN 不能用 == 比较,单独确认走的是 F64 分支。
        match decode("Float64", json!("nan")) {
            CellValue::F64 { value } => assert!(value.is_nan()),
            other => panic!("expected F64(NaN), got {other:?}"),
        }
        assert_eq!(
            decode("Decimal(18, 4)", json!("12345.6789")),
            CellValue::Decimal {
                value: "12345.6789".into()
            }
        );
    }

    #[test]
    fn temporal_types_normalize_datetime_separator() {
        assert_eq!(
            decode("Date", json!("2026-09-11")),
            CellValue::Date {
                value: "2026-09-11".into()
            }
        );
        assert_eq!(
            decode("DateTime64(3, 'UTC')", json!("2026-09-11 12:33:00.123")),
            CellValue::Datetime {
                value: "2026-09-11T12:33:00.123".into()
            }
        );
        assert_eq!(
            decode("Time", json!("12:33:00")),
            CellValue::Time {
                value: "12:33:00".into()
            }
        );
    }

    #[test]
    fn uuid_enum_and_ip_are_typed_text() {
        assert_eq!(
            decode("UUID", json!("67e55044-10b1-426f-9247-bb680e5fe0c8")),
            CellValue::Uuid {
                value: "67e55044-10b1-426f-9247-bb680e5fe0c8".into()
            }
        );
        assert_eq!(
            decode("Enum8('a' = 1)", json!("a")),
            CellValue::Text { value: "a".into() }
        );
        assert_eq!(
            decode("IPv4", json!("127.0.0.1")),
            CellValue::Text {
                value: "127.0.0.1".into()
            }
        );
    }

    #[test]
    fn fixed_string_trims_trailing_nul_padding() {
        assert_eq!(
            decode("FixedString(8)", json!("abc\0\0\0\0\0")),
            CellValue::Text {
                value: "abc".into()
            }
        );
        assert_eq!(
            decode("Nullable(LowCardinality(FixedString(4)))", json!("a\0\0\0")),
            CellValue::Text { value: "a".into() }
        );
    }

    #[test]
    fn structured_types_keep_json_instead_of_fabricating_values() {
        assert_eq!(
            decode("Array(UInt8)", json!([1, 2, 3])),
            CellValue::Json {
                value: json!([1, 2, 3])
            }
        );
        assert_eq!(
            decode("JSON", json!({"a": 1})),
            CellValue::Json {
                value: json!({"a": 1})
            }
        );
    }

    #[test]
    fn column_spec_carries_nullable_precision_and_length() {
        let spec = column_spec("amount", "Nullable(Decimal(18, 4))");
        assert_eq!(spec.type_kind, ColumnTypeKind::Decimal);
        assert_eq!(spec.nullable, Some(true));
        assert_eq!(spec.precision, Some(18));
        assert_eq!(spec.scale, Some(4));

        let spec = column_spec("code", "FixedString(16)");
        assert_eq!(spec.type_kind, ColumnTypeKind::Text);
        assert_eq!(spec.max_length, Some(16));

        let spec = column_spec("id", "UInt64");
        assert_eq!(spec.type_kind, ColumnTypeKind::U64);
        assert_eq!(spec.nullable, Some(false));
    }
}
