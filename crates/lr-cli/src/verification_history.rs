//! Explicit in-process captured verification and local history inspection.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{anyhow, bail};
use lr_engine::verify::{
    AttemptOutcome, CaptureOptions, RecordingOutcome, VerificationHistoryOptions,
    VerificationObservation, VerificationReceipt, VerifyReport, load_verification_history,
    record_verification_attempt, verify_image_captured,
};
use serde::Deserialize;

const POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalHistoryPolicy {
    schema_version: u16,
    capture: CaptureOptions,
    history: VerificationHistoryOptions,
}

#[derive(serde::Serialize)]
struct VerificationSummary<'a> {
    schema_version: u16,
    report: Option<&'a VerifyReport>,
    observation: &'a VerificationObservation,
    recording: &'a RecordingOutcome,
}

#[derive(serde::Serialize)]
struct HistorySummary<'a> {
    schema_version: u16,
    kind: &'static str,
    current_image_association: &'static str,
    receipts: &'a [VerificationReceipt],
}

/// Verify only from an engine-owned capture, then publish its local receipt.
pub(crate) fn verify_captured(
    json: bool,
    image: &str,
    chain: bool,
    passphrase_file: Option<&Path>,
    destination_options: &lr_store::DestinationOptions,
    policy_path: &Path,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    reject_explicit_socket(socket)?;
    let policy = read_policy(policy_path)?;

    let request = lr_engine::verify::VerifyRequest {
        image: image.to_owned(),
        encryption: lr_engine::options::restore_encryption(passphrase_file)?,
        chain,
        destination_options: destination_options.clone(),
        context: lr_engine::progress::EngineContext::silent(),
    };
    let attempt = verify_image_captured(&request, &policy.capture);
    let recording = record_verification_attempt(&attempt, &policy.history);
    let report = attempt.report();

    if json {
        let summary = VerificationSummary {
            schema_version: 1,
            report,
            observation: attempt.observation(),
            recording: &recording,
        };
        write_json_stdout(&summary)?;
    } else {
        print_verification_summary(report, attempt.observation(), &recording);
    }

    let completed = report.is_some()
        && matches!(
            attempt.observation().outcome(),
            AttemptOutcome::IntegrityVerified | AttemptOutcome::IntegrityVerifiedWithRecordedLoss
        );
    if !completed || !matches!(recording, RecordingOutcome::Recorded { .. }) {
        bail!("captured verification or receipt recording was not confirmed");
    }
    Ok(())
}

/// Inspect stored observations without checking current images or catalogs.
pub(crate) fn inspect_history(
    json: bool,
    policy_path: &Path,
    socket: Option<&Path>,
) -> anyhow::Result<()> {
    reject_explicit_socket(socket)?;
    let policy = read_policy(policy_path)?;
    let history = load_verification_history(&policy.history)
        .map_err(|_| anyhow!("local verification history is unavailable or unknown"))?;

    if json {
        let summary = HistorySummary {
            schema_version: 1,
            kind: "historical_observations",
            current_image_association: "not_checked",
            receipts: history.receipts(),
        };
        write_json_stdout(&summary)?;
    } else {
        println!("historical local verification observations; not current image health");
        println!("current image association: not checked");
        if history.receipts().is_empty() {
            println!("no stored observations");
        }
        for receipt in history.receipts() {
            let observation = receipt.observation();
            println!(
                "receipt {}: recording_started_at={} uid={} outcome={:?} scope={:?} coverage={:?}",
                receipt.receipt_id(),
                receipt.recorded_unix_seconds(),
                receipt.recorded_effective_uid(),
                observation.outcome(),
                observation.requested_scope(),
                observation.content_coverage(),
            );
        }
    }
    Ok(())
}

fn reject_explicit_socket(socket: Option<&Path>) -> anyhow::Result<()> {
    if socket.is_some() {
        bail!("local verification history cannot be combined with --socket");
    }
    Ok(())
}

fn write_json_stdout(value: &impl serde::Serialize) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn read_policy(path: &Path) -> anyhow::Result<LocalHistoryPolicy> {
    let descriptor = lr_unsafe::open_readonly_nofollow(path)
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    let mut file = File::from(descriptor);
    let before = file
        .metadata()
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    if !valid_policy_metadata(&before) || before.len() > MAX_POLICY_BYTES {
        bail!("local verification policy is invalid or unavailable");
    }

    let reserve = usize::try_from(MAX_POLICY_BYTES + 1)
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(reserve)
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    let read_result = (&mut file)
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes);
    let after = file
        .metadata()
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    if read_result.is_err()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_POLICY_BYTES
        || !same_policy_file(&before, &after)
    {
        bail!("local verification policy is invalid or unavailable");
    }

    let policy = serde_json::from_slice::<LocalHistoryPolicy>(&bytes)
        .map_err(|_| anyhow!("local verification policy is invalid or unavailable"))?;
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        bail!("local verification policy is invalid or unavailable");
    }
    Ok(policy)
}

fn valid_policy_metadata(metadata: &Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == lr_unsafe::effective_uid()
        && metadata.mode() & 0o7777 == PRIVATE_FILE_MODE
        && metadata.nlink() == 1
}

fn same_policy_file(before: &Metadata, after: &Metadata) -> bool {
    valid_policy_metadata(after)
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
}

fn print_verification_summary(
    report: Option<&VerifyReport>,
    observation: &VerificationObservation,
    recording: &RecordingOutcome,
) {
    println!("verification outcome: {:?}", observation.outcome());
    println!("requested scope: {:?}", observation.requested_scope());
    println!(
        "actual content coverage: {:?}",
        observation.content_coverage()
    );
    let (complete_members, captured_bytes) =
        observation
            .members()
            .iter()
            .fold((0usize, Some(0u128)), |(count, total), member| {
                if member.capture() != lr_engine::verify::MemberStage::Complete {
                    return (count, total);
                }
                let total = total.and_then(|bytes| {
                    member
                        .raw_length()
                        .and_then(|length| bytes.checked_add(u128::from(length)))
                });
                (count.saturating_add(1), total)
            });
    match captured_bytes {
        Some(bytes) => {
            println!("fully captured raw bytes: {bytes} ({complete_members} complete member(s))")
        }
        None => println!("fully captured raw bytes: unavailable (counter overflow)"),
    }
    if let Some(report) = report {
        println!("report: {}", report.summary());
        for warning in &report.warnings {
            eprintln!("warning: {warning}");
        }
    } else {
        println!("report: incomplete");
    }
    match recording {
        RecordingOutcome::Recorded { receipt_id } => {
            println!("receipt recording: confirmed ({receipt_id})");
        }
        RecordingOutcome::NotRecorded { reason } => {
            println!("receipt recording: not recorded ({reason:?})");
        }
        RecordingOutcome::PublicationUnconfirmed { receipt_id, reason } => {
            println!("receipt recording: publication unconfirmed ({receipt_id}, {reason:?})");
        }
    }
}
