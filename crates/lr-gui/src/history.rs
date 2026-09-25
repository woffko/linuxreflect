//! Catalog members are relative to the set, including their chain directory.

/// Missing or unsupported timestamps remain visibly unknown.
pub(crate) fn created_at(seconds: Option<u64>) -> String {
    seconds
        .and_then(|seconds| i64::try_from(seconds).ok())
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map(|date| date.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

pub(crate) fn backup_kind(kind: &str) -> &str {
    match kind {
        "full" => "Full backup",
        "incremental" => "Incremental backup",
        "differential" => "Differential backup",
        _ => "Unknown backup type",
    }
}

/// Keep URI syntax intact and reject catalog paths that escape their set.
pub(crate) fn image_location(destination: &str, set: &str, member: &str) -> Option<String> {
    if destination.is_empty()
        || !safe_component(set)
        || member.is_empty()
        || !member.split('/').all(safe_component)
        || !member.ends_with(".lrimg")
    {
        return None;
    }
    Some(format!(
        "{}/{set}/{member}",
        destination.trim_end_matches('/')
    ))
}

fn safe_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.contains('/')
        && !component.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::image_location;

    #[test]
    fn missing_or_out_of_range_catalog_dates_are_not_reported_as_epoch() {
        assert_eq!(super::created_at(None), "unknown");
        assert_eq!(super::created_at(Some(u64::MAX)), "unknown");
        assert_eq!(super::created_at(Some(0)), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn uses_the_set_relative_catalog_path_without_duplicating_the_chain() {
        assert_eq!(
            image_location("/backup/", "daily", "chain/000-full.lrimg").as_deref(),
            Some("/backup/daily/chain/000-full.lrimg")
        );
    }

    #[test]
    fn preserves_sftp_and_root_destinations() {
        assert_eq!(
            image_location("sftp://host/backup", "daily", "chain/copy.lrimg").as_deref(),
            Some("sftp://host/backup/daily/chain/copy.lrimg")
        );
        assert_eq!(
            image_location("/", "set", "copy.lrimg").as_deref(),
            Some("/set/copy.lrimg")
        );
    }

    #[test]
    fn rejects_escaping_and_malformed_catalog_names() {
        for member in [
            "../copy.lrimg",
            "/copy.lrimg",
            "chain/../../copy.lrimg",
            "chain//copy.lrimg",
            "copy.lrimg.tmp",
        ] {
            assert!(
                image_location("/backup", "set", member).is_none(),
                "{member}"
            );
        }
        assert!(image_location("/backup", "../set", "copy.lrimg").is_none());
    }
}
