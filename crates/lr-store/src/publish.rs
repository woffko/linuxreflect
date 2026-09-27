//! Publication protocol for remote destinations (R18).
//!
//! An image is immutable once published, so publishing one never deletes
//! anything: a retry after a lost reply looks at what the server holds and
//! recognises its own earlier success. The catalog is replaceable and has its
//! own protocol. Both run over [`RemoteOps`] so they can be tested against
//! injected transport failures.

use std::time::Duration;

use lr_core::{Error, Result};

/// The remote operations publication needs.
pub(crate) trait RemoteOps {
    /// Size of `path`, `None` when it does not exist.
    fn size(&self, path: &str) -> Result<Option<u64>>;
    /// One rename attempt that never replaces an existing `to`.
    fn rename(&self, from: &str, to: &str) -> Result<()>;
    /// One rename attempt that atomically replaces `to`; `Ok(false)` when
    /// the server has no such operation.
    fn rename_over(&self, from: &str, to: &str) -> Result<bool>;
    /// Remove `path`.
    fn remove(&self, path: &str) -> Result<()>;
}

/// How often publication is attempted and how long to wait in between.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Retry {
    pub attempts: u32,
    pub delay: Duration,
    pub max_delay: Duration,
}

/// Publish `from` as `to` without ever replacing or deleting `to` (R18).
///
/// A rename whose reply is lost may still have happened. Before retrying,
/// the protocol looks: the temporary file gone and `to` of the expected size
/// is the earlier attempt's success; both present is a name collision, which
/// is refused.
pub(crate) fn publish_new_with(
    ops: &dyn RemoteOps,
    from: &str,
    to: &str,
    retry: Retry,
) -> Result<()> {
    let expected = ops.size(from)?.ok_or_else(|| vanished(from))?;
    renamed_with(ops, from, to, expected, retry, |ops| ops.rename(from, to))
}

/// Replace `to` with `from` (the catalog).
///
/// With `posix-rename@openssh.com` this is one atomic rename. Without it the
/// old copy is first moved aside, so no attempt ever deletes the only copy;
/// the catalog is a cache rebuilt from the images, so a crash in between
/// costs nothing but a rescan.
pub(crate) fn replace_with(ops: &dyn RemoteOps, from: &str, to: &str, retry: Retry) -> Result<()> {
    let expected = ops.size(from)?.ok_or_else(|| vanished(from))?;
    let mut supported = true;
    let atomic = renamed_with(ops, from, to, expected, retry, |ops| {
        if ops.rename_over(from, to)? {
            Ok(())
        } else {
            supported = false;
            Ok(())
        }
    });
    if supported {
        return atomic;
    }
    let aside = match ops.size(to)? {
        Some(size) => {
            let aside = format!("{to}.{}.old", lr_core::Id::generate().map_err(Error::Io)?);
            renamed_with(ops, to, &aside, size, retry, |ops| ops.rename(to, &aside))?;
            Some(aside)
        }
        None => None,
    };
    publish_new_with(ops, from, to, retry)?;
    if let Some(aside) = aside {
        let _ = ops.remove(&aside);
    }
    Ok(())
}

/// Run `attempt` until the rename of `from` to `to` is known to have
/// happened, reconciling after every failure.
fn renamed_with<'a>(
    ops: &'a dyn RemoteOps,
    from: &str,
    to: &str,
    expected: u64,
    retry: Retry,
    mut attempt: impl FnMut(&'a dyn RemoteOps) -> Result<()>,
) -> Result<()> {
    let mut delay = retry.delay;
    for round in 0..retry.attempts {
        let error = match attempt(ops) {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        match (ops.size(from)?, ops.size(to)?) {
            // An earlier attempt reached the server; only its reply was lost.
            (None, Some(size)) if size == expected => return Ok(()),
            (Some(_), Some(_)) if !crate::sftp::is_transient(&error) => {
                return Err(Error::unsupported(format!(
                    "{to} already exists; a published image is never replaced"
                )));
            }
            (None, _) => return Err(vanished(from)),
            _ if crate::sftp::is_transient(&error) && round + 1 < retry.attempts => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(retry.max_delay);
            }
            _ => return Err(error),
        }
    }
    Err(Error::NetworkTimeout(format!("publishing {to}")))
}

fn vanished(path: &str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{path} disappeared before it was published"),
    ))
}

#[cfg(test)]
mod tests {
    use super::{RemoteOps, Retry, publish_new_with, replace_with};
    use lr_core::{Error, Result};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::time::Duration;

    /// A remote directory whose first rename reaches the server but whose
    /// reply is lost, as when the connection drops right after the rename.
    struct LostAck {
        files: RefCell<HashMap<String, Vec<u8>>>,
        renames: Cell<u32>,
        atomic_replace: bool,
    }

    impl LostAck {
        fn with(files: &[(&str, &[u8])]) -> Self {
            Self {
                files: RefCell::new(
                    files
                        .iter()
                        .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
                        .collect(),
                ),
                renames: Cell::new(0),
                atomic_replace: true,
            }
        }
    }

    fn lost() -> Error {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "connection lost",
        ))
    }

    impl RemoteOps for LostAck {
        fn size(&self, path: &str) -> Result<Option<u64>> {
            Ok(self
                .files
                .borrow()
                .get(path)
                .map(|bytes| bytes.len() as u64))
        }

        fn rename(&self, from: &str, to: &str) -> Result<()> {
            let mut files = self.files.borrow_mut();
            if files.contains_key(to) {
                return Err(Error::corrupt("rename: the target exists"));
            }
            let bytes = files
                .remove(from)
                .ok_or_else(|| Error::Io(std::io::ErrorKind::NotFound.into()))?;
            files.insert(to.to_owned(), bytes);
            self.renames.set(self.renames.get() + 1);
            if self.renames.get() == 1 {
                return Err(lost());
            }
            Ok(())
        }

        fn rename_over(&self, from: &str, to: &str) -> Result<bool> {
            if !self.atomic_replace {
                return Ok(false);
            }
            let mut files = self.files.borrow_mut();
            let bytes = files
                .remove(from)
                .ok_or_else(|| Error::Io(std::io::ErrorKind::NotFound.into()))?;
            files.insert(to.to_owned(), bytes);
            self.renames.set(self.renames.get() + 1);
            if self.renames.get() == 1 {
                return Err(lost());
            }
            Ok(true)
        }

        fn remove(&self, path: &str) -> Result<()> {
            self.files
                .borrow_mut()
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| Error::Io(std::io::ErrorKind::NotFound.into()))
        }
    }

    const FAST: Retry = Retry {
        attempts: 5,
        delay: Duration::ZERO,
        max_delay: Duration::ZERO,
    };

    /// The server renamed the image but the reply was lost; the retry must
    /// recognise the earlier success and keep the image (R18).
    #[test]
    fn a_lost_rename_reply_keeps_the_published_image() {
        let ops = LostAck::with(&[("set/c/img.lrimg.x.tmp", b"complete image")]);
        let outcome = publish_new_with(&ops, "set/c/img.lrimg.x.tmp", "set/c/img.lrimg", FAST);
        let files = ops.files.borrow();
        assert_eq!(
            files.get("set/c/img.lrimg").map(Vec::as_slice),
            Some(&b"complete image"[..]),
            "the published image must survive the retry: {files:?}"
        );
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// A name that already exists is refused, and nothing is deleted.
    #[test]
    fn an_existing_image_is_never_replaced() {
        let ops = LostAck::with(&[("tmp", b"new"), ("img", b"published")]);
        let error = publish_new_with(&ops, "tmp", "img", FAST).expect_err("collision");
        assert!(error.to_string().contains("never replaced"), "{error}");
        let files = ops.files.borrow();
        assert_eq!(files.get("img").map(Vec::as_slice), Some(&b"published"[..]));
        assert_eq!(files.get("tmp").map(Vec::as_slice), Some(&b"new"[..]));
    }

    /// The catalog is replaced atomically when the server can, and a lost
    /// reply is recognised there too.
    #[test]
    fn the_catalog_is_replaced_and_a_lost_reply_is_recognised() {
        let ops = LostAck::with(&[
            ("catalog.json.x.tmp", b"new catalog"),
            ("catalog.json", b"old"),
        ]);
        replace_with(&ops, "catalog.json.x.tmp", "catalog.json", FAST).expect("replace");
        let files = ops.files.borrow();
        assert_eq!(
            files.get("catalog.json").map(Vec::as_slice),
            Some(&b"new catalog"[..])
        );
        assert_eq!(files.len(), 1, "{files:?}");
    }

    /// Without an atomic replace the old catalog is moved aside first, so no
    /// step ever deletes the only copy.
    #[test]
    fn without_atomic_replace_the_old_catalog_is_moved_aside_first() {
        let mut ops = LostAck::with(&[
            ("catalog.json.x.tmp", b"new catalog"),
            ("catalog.json", b"old"),
        ]);
        ops.atomic_replace = false;
        replace_with(&ops, "catalog.json.x.tmp", "catalog.json", FAST).expect("replace");
        let files = ops.files.borrow();
        assert_eq!(
            files.get("catalog.json").map(Vec::as_slice),
            Some(&b"new catalog"[..])
        );
        assert_eq!(
            files.len(),
            1,
            "the old copy is removed afterwards: {files:?}"
        );
    }
}
