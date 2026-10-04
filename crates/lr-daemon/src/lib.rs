//! The LinuxReflect root daemon.
//!
//! Filled in by **Slice S11** (spec §I): socket activation, gRPC over UDS,
//! `AuthBackend` (polkit / static dev-mode), restore tokens and job management.
#![forbid(unsafe_code)]

pub mod auth;
pub mod client_files;
pub mod jobs;
pub mod notify;
pub mod progress_bridge;
pub mod service;
pub mod shutdown;
pub mod socket;
pub mod status;
pub mod verification;
pub mod verification_policy;
