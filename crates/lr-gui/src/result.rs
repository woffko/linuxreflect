//! Human-readable successful job reports; raw daemon reports remain available.

fn consistency_description(value: &str) -> &'static str {
    match value {
        "per_file" | "per-file" => {
            "Files were copied individually, not as one point-in-time snapshot."
        }
        "point_in_time" | "point-in-time" => "Consistency: a point-in-time copy.",
        "frozen" => "Filesystem writes were paused while the backup was made.",
        "offline" => "The source was offline while the backup was made.",
        "none" | "none (inconsistent)" => {
            "The source was read live without a consistent snapshot. Backup data may be inconsistent."
        }
        _ => "See technical details for the engine's reported consistency.",
    }
}

/// Explain only facts supplied by PrepareRestore; never expose its token.
pub(crate) fn restore_plan(plan: &lr_proto::v1::RestorePlanInfo) -> String {
    let action = match plan.image_kind.as_str() {
        "File" => "Restore files and folders to the selected destination.",
        "Block" => "Restore disk or partition data to the selected destination.",
        "Stream" => "Restore a filesystem snapshot to the selected destination.",
        _ => "Restore the selected backup. See the technical plan for its format.",
    };
    let mut text = format!(
        "{action}\nSource data: {}\nBackup images required: {}\n{}",
        crate::human_size(plan.source_size_bytes),
        plan.members.len(),
        consistency_description(&plan.consistency),
    );
    for warning in &plan.warnings {
        text.push_str(&format!("\nNote: {warning}"));
    }
    text
}

pub(crate) fn describe(operation: &str, raw: &str) -> String {
    let mut text = match operation {
        "backup" => "Backup completed.".to_owned(),
        "restore" => "Restore completed.".to_owned(),
        _ => "Operation completed.".to_owned(),
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        text.push_str("\nThe detailed report could not be interpreted. Open technical details.");
        return text;
    };
    for (label, field) in [
        ("Backup image", "image_path"),
        ("Backup location", "image_uri"),
        ("Destination", "target"),
    ] {
        if let Some(path) = value.get(field).and_then(serde_json::Value::as_str) {
            text.push_str(&format!("\n{label}: {path}"));
        }
    }
    if let Some(files) = value.get("files").and_then(serde_json::Value::as_u64) {
        text.push_str(&format!("\nFiles: {files}"));
    }
    for (label, field) in [
        ("Source data", "total_bytes"),
        ("Image size", "image_bytes"),
        ("Restored data", "restored_bytes"),
        ("Written data", "bytes_written"),
    ] {
        if let Some(bytes) = value.get(field).and_then(serde_json::Value::as_u64) {
            text.push_str(&format!("\n{label}: {}", crate::human_size(bytes)));
        }
    }
    if let Some(consistency) = value.get("consistency").and_then(serde_json::Value::as_str) {
        text.push('\n');
        text.push_str(consistency_description(consistency));
    }
    if let Some(encrypted) = value.get("encrypted").and_then(serde_json::Value::as_bool) {
        text.push_str(if encrypted {
            "\nEncryption: enabled."
        } else {
            "\nEncryption: off."
        });
    }
    if let Some(warnings) = value.get("warnings").and_then(serde_json::Value::as_array) {
        for warning in warnings.iter().filter_map(serde_json::Value::as_str) {
            text.push_str(&format!("\nNote: {warning}"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    #[test]
    fn restore_review_preserves_warnings_and_never_exposes_authorization() {
        let plan = lr_proto::v1::RestorePlanInfo {
            image_kind: "File".into(),
            consistency: "per-file".into(),
            token: "opaque-authorization".into(),
            warnings: vec!["Destination requires attention".into()],
            ..Default::default()
        };
        let text = super::restore_plan(&plan);
        assert!(text.contains("Restore files and folders"));
        assert!(text.contains("not as one point-in-time snapshot"));
        assert!(text.contains("Destination requires attention"));
        assert!(!text.contains(&plan.token));
        let unknown = lr_proto::v1::RestorePlanInfo {
            image_kind: "future-format".into(),
            consistency: "future-consistency".into(),
            ..Default::default()
        };
        let text = super::restore_plan(&unknown);
        assert!(!text.contains("point-in-time copy"));
        assert!(text.contains("technical plan"));
    }

    #[test]
    fn preserves_consistency_limitations_and_warnings() {
        let report = super::describe(
            "backup",
            r#"{"image_path":"/copies/a.lrimg","consistency":"per_file","encrypted":false,"warnings":["Source changed during copy"]}"#,
        );
        assert!(report.contains("not as one point-in-time snapshot"));
        assert!(report.contains("Source changed during copy"));
        assert!(report.contains("/copies/a.lrimg"));
        assert!(report.contains("Encryption: off"));
    }

    #[test]
    fn missing_or_unknown_facts_are_not_invented() {
        let report = super::describe(
            "restore",
            r#"{"target":"/restored","consistency":"future_value"}"#,
        );
        assert!(report.contains("Destination: /restored"));
        assert!(!report.contains("point-in-time copy"));
        assert!(!report.contains("Files:"));
        assert!(super::describe("backup", "invalid JSON").contains("could not be interpreted"));
    }
}
