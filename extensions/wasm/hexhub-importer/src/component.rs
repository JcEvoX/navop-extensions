wit_bindgen::generate!({
    path: "../../../wit",
    world: "connection-importer",
});

use onet::extension::{connection_import::CandidateFile, connection_import_host};
use std::collections::BTreeSet;

struct HexhubImporter;

impl Guest for HexhubImporter {
    fn descriptor() -> String {
        serde_json::json!({
            "id": "hexhub",
            "display_name": "HexHub",
            "description": "Import SSH sessions, database connections and quick commands from a \
                            HexHub asset export (HexHub-Assets.json)",
            "icon": "terminal",
            "vendor": "Navop",
            "supported_platforms": ["macos", "windows", "linux"],
            // 宿主 `ImporterDescriptor.output_kinds` 是 `ImportRecordKind`（snake_case），
            // 和 manifest 里 `outputKinds` 的短横线写法不是一套。
            "output_kinds": ["ssh", "database", "quick_command"],
            "capabilities": {
                "supports_scan": true,
                // 口令与私钥用客户端内置的固定密钥加密，导出文件里就能解开。
                "supports_password_import": true,
                "supports_manual_file_pick": true,
                "supports_incremental_preview": false
            }
        })
        .to_string()
    }

    fn scan() -> String {
        let exports = read_exports();
        // 扫描阶段只统计条数，不解密口令（`include_passwords = false`）。
        let report = crate::hexhub::preview_report_from_exports(
            exports
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.as_slice())),
            false,
        );
        let record_count = report.records.len();
        let availability = if record_count == 0 {
            serde_json::json!("no_data")
        } else {
            serde_json::json!({ "available": { "estimated_count": record_count } })
        };

        let mut warnings = report
            .warnings
            .iter()
            .map(|warning| {
                serde_json::json!({
                    "code": warning.code,
                    "message": warning.message
                })
            })
            .collect::<Vec<_>>();
        if !report.skipped.is_empty() {
            let total: usize = report.skipped.values().sum();
            let detail = report
                .skipped
                .iter()
                .map(|(label, count)| format!("{label} ×{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(serde_json::json!({
                "code": "hexhub_assets_not_importable",
                "message": format!(
                    "{total} asset(s) were skipped ({detail}). HexHub RDP, VNC, Telnet, FTP, \
                     Docker and saved-query assets have no Navop connection type."
                )
            }));
        }

        serde_json::json!({
            "importer_id": "hexhub",
            "availability": availability,
            "discovered_files": exports.iter().map(|(path, _)| {
                serde_json::json!({
                    "candidate_id": path,
                    "display_path": path
                })
            }).collect::<Vec<_>>(),
            "warnings": warnings
        })
        .to_string()
    }

    fn preview(options: ImportOptions) -> String {
        let exports = read_exports();
        let records = crate::hexhub::preview_report_from_exports(
            exports
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.as_slice())),
            options.include_passwords,
        )
        .records;
        serde_json::to_string(&records).unwrap_or_else(|_| "[]".to_string())
    }
}

/// HexHub 的资产存在应用自己的库里（Dexie/IndexedDB），唯一能离线读的就是客户端导出的
/// `HexHub-Assets.json`。候选路径负责「刚导出完就自动扫到」，用户从别处拷来的文件走手选。
fn read_exports() -> Vec<(String, Vec<u8>)> {
    let candidates = connection_import_host::list_candidate_files("hexhub");
    let mut seen = BTreeSet::new();
    let mut exports = Vec::new();
    for CandidateFile { id, path, .. } in candidates {
        // 手选同一个文件可能产生新的候选 id，但路径一样，别导两遍。
        if !seen.insert(path.clone()) {
            continue;
        }
        if let Ok(bytes) = connection_import_host::read_file(&id)
            && !bytes.is_empty()
        {
            exports.push((path, bytes));
        }
    }
    exports
}

export!(HexhubImporter);
