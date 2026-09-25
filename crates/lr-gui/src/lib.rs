//! LinuxReflect's Slint GUI (spec §K S15).
//!
//! The GUI is a daemon client: the disk map comes from `ListDisks`, the backup
//! wizard shows `ProbeSource`'s plan (including the consistency level) before
//! starting, the restore wizard shows `PrepareRestore`'s plan and token, and
//! progress and history come from the job streams. No device is ever opened
//! here (spec §B).
//!
//! Slint is used under the Royalty-Free 2.0 licence; the attribution it asks
//! for is the footer of the window (see D-090).

mod actions;
mod backup_review;
mod callbacks;
pub mod client;
mod devices;
mod disk_map;
mod geometry;
mod history;
mod job_view;
mod models;
mod prefs;
mod result;
mod review;
pub mod script;
mod script_runner;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use lr_proto::v1::BackupSpec;
use slint::Model as _;

use crate::client::Client;
use crate::script::{ScriptOutcome, Step};

/// The generated UI types; the generated code carries no docs of its own.
#[allow(missing_docs, unreachable_pub)]
mod generated {
    slint::include_modules!();
}

use generated::*;

use actions::*;
use callbacks::*;
use models::*;
use script_runner::*;

/// The generated Slint types, for tooling that renders the window without a
/// display (`examples/gallery.rs`). Not a stable interface.
#[doc(hidden)]
pub mod ui {
    pub use super::generated::*;
}

/// How the GUI should start.
#[derive(Debug, Clone)]
pub struct GuiOptions {
    /// Daemon socket.
    pub socket: PathBuf,
    /// Automation script (tests).
    pub script: Option<PathBuf>,
    /// Quit after this many milliseconds even without `quit` (a smoke run).
    pub exit_after_ms: Option<u64>,
}

impl GuiOptions {
    /// Options for a daemon socket.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            script: None,
            exit_after_ms: None,
        }
    }
}

/// A Slint list of strings.
fn string_model(items: &[String]) -> slint::ModelRc<slint::SharedString> {
    slint::ModelRc::new(slint::VecModel::from(
        items
            .iter()
            .map(|item| slint::SharedString::from(item.as_str()))
            .collect::<Vec<_>>(),
    ))
}

/// Format a byte count for the GUI.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    lr_engine_size(bytes)
}

/// A tiny duplicate of the engine's size formatting, to keep the GUI's
/// dependency list small (the GUI never touches the engine).
fn lr_engine_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// The wired application.
pub struct App {
    ui: MainWindow,
    actions: Arc<Actions>,
    runtime: tokio::runtime::Runtime,
}

impl App {
    /// Wire the UI to a daemon socket.
    ///
    /// # Errors
    /// Returns an error when the Slint component cannot be created or a runtime
    /// cannot be built.
    pub fn new(ui: MainWindow, socket: &Path) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("lr-gui")
            .build()
            .context("building the async runtime")?;
        let actions = Arc::new(Actions {
            runtime: runtime.handle().clone(),
            socket: socket.to_path_buf(),
            shared: Arc::new(Shared {
                busy: AtomicBool::new(false),
                generation: AtomicU64::new(0),
                failure: Mutex::new(None),
                restore_review: Mutex::new(review::Review::default()),
                backup_review: Mutex::new(backup_review::Review::default()),
                prefs: Mutex::new(None),
            }),
        });
        connect_callbacks(&ui, &actions);
        Ok(Self {
            ui,
            actions,
            runtime,
        })
    }

    /// The UI handle.
    #[must_use]
    pub fn ui(&self) -> &MainWindow {
        &self.ui
    }

    /// `true` while an action is running.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.actions.shared.busy.load(Ordering::SeqCst)
    }

    /// The last failure, if any.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.actions
            .shared
            .failure
            .lock()
            .expect("failure lock")
            .clone()
    }

    /// Keep the runtime alive until the end of the value's life.
    #[must_use]
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }
}

/// Run the GUI, optionally executing an automation script.
///
/// # Errors
/// Returns an error when the UI cannot be built, the script cannot be read, or
/// a script step fails.
pub fn run(options: GuiOptions) -> anyhow::Result<ScriptOutcome> {
    let ui = MainWindow::new().context("creating the Slint window")?;
    let app = App::new(ui.clone_strong(), &options.socket)?;
    let steps = match &options.script {
        Some(path) => Some(script::load(path).map_err(|error| anyhow::anyhow!("{error}"))?),
        None => None,
    };
    let outcome_slot: Arc<Mutex<Option<Result<ScriptOutcome, String>>>> =
        Arc::new(Mutex::new(None));

    if steps.is_none() {
        // Remembered folders are for people, not scripted runs: a test must
        // neither depend on nor change the user's preferences.
        if let Some(file) = prefs::location() {
            let recent = prefs::recent_destinations(&file);
            if ui.get_destination().is_empty()
                && let Some(last) = recent.first()
            {
                ui.set_destination(last.clone().into());
            }
            ui.set_recent_destinations(string_model(&recent));
            *app.actions.shared.prefs.lock().expect("prefs lock") = Some(file);
        }
        // Let the desktop choose an initial size within its usable work area,
        // including decorations and display scaling, rather than placing a
        // preferred-size window partly off-screen on small rescue displays.
        // A kiosk compositor (`cage` on the rescue medium) draws no window
        // decorations: fill the output instead of maximising, or the space
        // reserved for client-side decorations stays black.
        if std::env::var("LINUXREFLECT_KIOSK").is_ok_and(|value| value == "1") {
            ui.set_kiosk(true);
            ui.window().set_fullscreen(true);
        } else {
            ui.window().set_maximized(true);
        }
        let weak = ui.as_weak();
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.invoke_refresh_disks();
            }
        })
        .context("queueing initial disk discovery")?;
    }

    if let Some(steps) = steps {
        let weak = ui.as_weak();
        let slot = Arc::clone(&outcome_slot);
        std::thread::spawn(move || {
            // Let the window map first: a mapped window proves the backend.
            std::thread::sleep(Duration::from_millis(800));
            let result = run_script(&weak, &steps);
            *slot.lock().expect("outcome lock") = Some(result);
            let _ = slint::invoke_from_event_loop(|| {
                let _ = slint::quit_event_loop();
            });
        });
    }
    if let Some(millis) = options.exit_after_ms {
        let timer = Box::leak(Box::new(slint::Timer::default()));
        timer.start(
            slint::TimerMode::SingleShot,
            Duration::from_millis(millis),
            || {
                let _ = slint::quit_event_loop();
            },
        );
    }

    ui.run().context("running the Slint event loop")?;
    let _ = app;
    let outcome = outcome_slot
        .lock()
        .expect("outcome lock")
        .take()
        .unwrap_or_else(|| {
            Ok(ScriptOutcome {
                steps: 0,
                log: Vec::new(),
            })
        });
    outcome.map_err(|error| anyhow::anyhow!(error))
}
