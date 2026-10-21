//! `HexHub-Assets.json` 容器解析。
//!
//! 客户端导出（`exportJSON()` / 资产导出对话框）产出的根对象是
//! `{version, time, data:[...], sign}`，`data` 里每个元素是 Dexie `assets` 表的一行：
//! `{id, type, dirPath, name, keyword, delFlag, accessed, updated, created, data}`。
//! 其中 `data` 是**模型 JSON 字符串**（`serializeData()` 先 `JSON.stringify` 再入库），
//! 所以这里要二次解析；顺便兼容「已经是对象」的写法，免得换一版客户端就全空。

use serde_json::{Map, Value};

/// 承载资产数组的根键。`exportJSON()` 用 `data`，导出对话框那条路径用 `list`，
/// 历史/同步备份里还出现过 `assets`——三个都认。
const ROOT_ARRAY_KEYS: [&str; 3] = ["data", "list", "assets"];

/// `delFlag` 的已删除取值（Dexie 侧写的是 `"all"`，同步侧出现过布尔值）。
const DELETED_FLAGS: [&str; 3] = ["all", "deleted", "true"];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AssetEntry {
    /// 资产 uuid。既要当 `source_id` 的一部分，也是私钥/口令对/跳板机的引用键。
    pub(crate) id: String,
    /// 资产类型，见 `hexhub::asset_type_label`（客户端 `F` 枚举）。
    pub(crate) type_id: i64,
    pub(crate) name: String,
    /// 形如 `/生产/数据库/`；转成分组路径时要去掉首尾斜杠。
    pub(crate) dir_path: String,
    /// 解析后的模型对象；`data` 缺失或不是合法 JSON 时为 `None`。
    pub(crate) data: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContainerError {
    /// 不是 JSON 文本。最常见的原因是导出时填了「加密密码」——整份文件被加密过。
    NotJson,
    /// 是 JSON，但根上找不到资产数组：不是 HexHub 的资产导出（或者是空导出）。
    NoAssets,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<AssetEntry>, ContainerError> {
    // 导出在 Windows 上可能带 BOM；`serde_json` 不认，先剥掉。
    let text = std::str::from_utf8(bytes).map_err(|_| ContainerError::NotJson)?;
    let text = text.trim_start_matches('\u{feff}').trim_start();
    let root: Value = serde_json::from_str(text).map_err(|_| ContainerError::NotJson)?;
    let items = asset_array(&root).ok_or(ContainerError::NoAssets)?;
    Ok(items.iter().filter_map(asset_entry).collect())
}

fn asset_array(root: &Value) -> Option<&Vec<Value>> {
    if let Value::Array(items) = root {
        return Some(items);
    }
    let object = root.as_object()?;
    ROOT_ARRAY_KEYS
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_array))
}

fn asset_entry(value: &Value) -> Option<AssetEntry> {
    let object = value.as_object()?;
    if is_deleted(object) {
        return None;
    }
    let type_id = number(object, "type")?;
    let name = text(object, "name").unwrap_or_default();
    let dir_path = text(object, "dirPath").unwrap_or_default();
    // 正常导出一定有 `id`；缺失时用「类型+目录+名字」兜一个稳定键，避免整条被丢掉。
    let id = text(object, "id").unwrap_or_else(|| format!("{type_id}:{dir_path}{name}"));
    Some(AssetEntry {
        id,
        type_id,
        name,
        dir_path,
        data: parse_data(object.get("data")),
    })
}

fn parse_data(value: Option<&Value>) -> Option<Value> {
    match value? {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            serde_json::from_str(trimmed).ok()
        }
        Value::Object(_) => value.cloned(),
        _ => None,
    }
}

fn is_deleted(object: &Map<String, Value>) -> bool {
    match object.get("delFlag") {
        Some(Value::String(flag)) => {
            let flag = flag.trim().to_ascii_lowercase();
            !flag.is_empty() && DELETED_FLAGS.contains(&flag.as_str())
        }
        Some(Value::Bool(flag)) => *flag,
        _ => false,
    }
}

fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
    match object.get(key)? {
        Value::String(text) => {
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn number(object: &Map<String, Value>, key: &str) -> Option<i64> {
    match object.get(key)? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_root_with_data_array() {
        let bytes = br#"{
            "version": 1,
            "time": "Date(1730000000000)",
            "sign": "abc",
            "data": [
                { "id": "asset-1", "type": 2, "dirPath": "/Prod/", "name": "web", "data": "{\"host\":\"10.0.0.1\"}" },
                { "id": "asset-2", "type": 12, "dirPath": "/", "name": "win", "data": "{}" }
            ]
        }"#;

        let entries = parse(bytes).expect("export root should parse");

        assert_eq!(2, entries.len());
        assert_eq!("asset-1", entries[0].id);
        assert_eq!(2, entries[0].type_id);
        assert_eq!("/Prod/", entries[0].dir_path);
        assert_eq!(
            Some("10.0.0.1"),
            entries[0].data.as_ref().unwrap()["host"].as_str()
        );
        assert_eq!(12, entries[1].type_id);
    }

    #[test]
    fn accepts_list_key_and_object_payloads() {
        // 资产导出对话框走的是 `{version, list, password}` 这条路径。
        let bytes = br#"{
            "version": 1,
            "list": [
                { "id": "db-1", "type": "4", "name": "db", "data": { "dbType": 0 } }
            ]
        }"#;

        let entries = parse(bytes).expect("list root should parse");

        assert_eq!(1, entries.len());
        assert_eq!(4, entries[0].type_id);
        // `data` 已经是对象时直接沿用。
        assert_eq!(0, entries[0].data.as_ref().unwrap()["dbType"]);
    }

    #[test]
    fn tolerates_utf8_bom_and_top_level_array() {
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend_from_slice(br#"[{"id":"a","type":5,"name":"cmd","data":"{\"cmd\":\"ls\"}"}]"#);

        let entries = parse(&bytes).expect("BOM + bare array should parse");

        assert_eq!(1, entries.len());
        assert_eq!("a", entries[0].id);
    }

    #[test]
    fn skips_soft_deleted_assets() {
        let bytes = br#"{
            "data": [
                { "id": "gone", "type": 2, "name": "old", "delFlag": "all" },
                { "id": "kept", "type": 2, "name": "new", "delFlag": "" }
            ]
        }"#;

        let entries = parse(bytes).expect("export should parse");

        assert_eq!(1, entries.len());
        assert_eq!("kept", entries[0].id);
    }

    #[test]
    fn reports_encrypted_exports_as_not_json() {
        // 设置了「加密密码」时导出的不是 JSON，而是加密后的字节。
        assert_eq!(
            Err(ContainerError::NotJson),
            parse(&[0x9c, 0x2f, 0x00, 0xff, 0x12])
        );
    }

    #[test]
    fn reports_json_without_assets() {
        assert_eq!(
            Err(ContainerError::NoAssets),
            parse(br#"{"version":1,"sign":"x"}"#)
        );
    }

    #[test]
    fn keeps_entries_with_broken_inline_data() {
        // `data` 坏了不该让整条消失：主机/名字还在，至少能提示用户手工补。
        let bytes = br#"{"data":[{"id":"x","type":2,"name":"web","data":"not-json"}]}"#;

        let entries = parse(bytes).expect("export should parse");

        assert_eq!(1, entries.len());
        assert_eq!(None, entries[0].data);
    }
}
