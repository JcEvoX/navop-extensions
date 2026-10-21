wit_bindgen::generate!({
    path: "../../../wit",
    world: "connection-importer",
});

use onet::extension::{
    connection_import::{CandidateFile, DirectoryEntry},
    connection_import_host,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// 便携版目录里可能有一堆无关文件，限制递归深度与读取文件数。
const MAX_DIRECTORY_DEPTH: usize = 6;
const MAX_SOURCE_FILES: usize = 256;

struct MobaxtermImporter;

impl Guest for MobaxtermImporter {
    fn descriptor() -> String {
        serde_json::json!({
            "id": "mobaxterm",
            "display_name": "MobaXterm",
            "description": "Import SSH sessions from MobaXterm.ini, .mxtsessions or .moba files",
            "icon": "terminal",
            "vendor": "Navop",
            "supported_platforms": ["macos", "windows", "linux"],
            "output_kinds": ["ssh"],
            "capabilities": {
                "supports_scan": true,
                "supports_password_import": true,
                "supports_manual_file_pick": true,
                "supports_incremental_preview": false
            }
        })
        .to_string()
    }

    fn scan() -> String {
        let candidates = connection_import_host::list_candidate_files("mobaxterm");
        let sessions = read_sessions(&candidates);
        // 扫描阶段只统计条数，不解密口令（`include_passwords = false`）。
        let report = crate::mobaxterm::preview_report_from_sources(
            sessions
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.as_slice())),
            false,
            None,
        );
        let record_count = report.records.len();
        let availability = if record_count == 0 {
            serde_json::json!("no_data")
        } else {
            serde_json::json!({ "available": { "estimated_count": record_count } })
        };
        // 非 SSH 会话（RDP/VNC/telnet…）导入协议里没有对应类型，扫到就如实报数，
        // 否则用户只会看到「条数比 MobaXterm 里少」而不知道少在哪。
        let warnings = if report.skipped.is_empty() {
            Vec::new()
        } else {
            let total: usize = report.skipped.iter().map(|(_, count)| count).sum();
            let detail = report
                .skipped
                .iter()
                .map(|(label, count)| format!("{label} ×{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            vec![serde_json::json!({
                "code": "mobaxterm_non_ssh_sessions_skipped",
                "message": format!(
                    "{total} non-SSH session(s) were skipped ({detail}). Only SSH, database \
                     and port-forwarding connections can be imported."
                )
            })]
        };

        serde_json::json!({
            "importer_id": "mobaxterm",
            "availability": availability,
            "discovered_files": sessions.iter().map(|(path, _)| {
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
        let candidates = connection_import_host::list_candidate_files("mobaxterm");
        let sessions = read_sessions(&candidates);
        // 主密码目前没有宿主输入口（`import-options` 只有 `include-passwords`）。
        // 配了主密码的配置会以 `mobaxterm_master_password_required` 警告如实标注；
        // 未配主密码的走弱密钥路径，是全自动的。
        let records = crate::mobaxterm::preview_records_from_sources_with_master_password(
            sessions
                .iter()
                .map(|(path, bytes)| (path.clone(), bytes.as_slice())),
            options.include_passwords,
            None,
        );
        serde_json::to_string(&records).unwrap_or_else(|_| "[]".to_string())
    }
}

/// 声明的候选既可能是目录（安装版 `Documents/MobaXterm`、老版本 `%APPDATA%/MobaXterm`），
/// 也可能是用户手动选中的单个文件（`MobaXterm.ini` / `.mxtsessions` / `.moba`）。
/// 目录必须先枚举再读子文件 —— 只调 `read_file` 会拿到 EISDIR，扫描结果永远是空。
fn read_sessions(candidates: &[CandidateFile]) -> Vec<(String, Vec<u8>)> {
    let mut sessions = Vec::new();
    for candidate in candidates {
        if let Ok(entries) = connection_import_host::read_directory(&candidate.id) {
            collect_directory(
                &candidate.id,
                &candidate.path,
                "",
                0,
                entries,
                &mut sessions,
            );
            continue;
        }
        if crate::mobaxterm::is_supported_source_path(&candidate.path)
            && let Ok(bytes) = connection_import_host::read_file(&candidate.id)
        {
            sessions.push((candidate.path.clone(), bytes));
        }
    }
    dedupe_identical_files(sessions)
}

/// `Documents` 被 OneDrive 接管时，`~/Documents/MobaXterm` 与
/// `~/OneDrive/Documents/MobaXterm` 会指向同一份配置；按内容去掉重复，
/// 避免导入列表里出现两份一样的会话。
fn dedupe_identical_files(sessions: Vec<(String, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for (path, bytes) in sessions {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        if seen.insert(hasher.finalize()) {
            unique.push((path, bytes));
        }
    }
    unique
}

fn collect_directory(
    candidate_id: &str,
    root: &str,
    host_prefix: &str,
    depth: usize,
    mut entries: Vec<DirectoryEntry>,
    sessions: &mut Vec<(String, Vec<u8>)>,
) {
    if sessions.len() >= MAX_SOURCE_FILES || depth > MAX_DIRECTORY_DEPTH {
        return;
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    for entry in entries {
        let Some(relative) = join_relative(host_prefix, &entry.name) else {
            continue;
        };
        if entry.is_dir {
            if let Ok(children) =
                connection_import_host::read_candidate_directory(candidate_id, &relative)
            {
                collect_directory(candidate_id, root, &relative, depth + 1, children, sessions);
            }
            continue;
        }
        if !crate::mobaxterm::is_supported_source_path(&entry.name) {
            continue;
        }
        if sessions.len() >= MAX_SOURCE_FILES {
            return;
        }
        if let Ok(bytes) =
            connection_import_host::read_candidate_child_file(candidate_id, &relative)
        {
            sessions.push((format!("{root}/{relative}"), bytes));
        }
    }
}

/// 只接受单层的普通文件名，挡掉 `..` 与自带分隔符的条目。
fn join_relative(prefix: &str, name: &str) -> Option<String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return None;
    }
    if prefix.is_empty() {
        Some(name.to_string())
    } else {
        Some(format!("{prefix}/{name}"))
    }
}

export!(MobaxtermImporter);
