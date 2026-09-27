//! Fault injection for tests (feature `fault-injection`, never in a release
//! build).
//!
//! A destination URI `fault+<kind>:<uri>` opens `<uri>` and wraps it so that
//! one operation fails the way a disk, a server or a network would:
//!
//! | `<kind>` | What fails |
//! |---|---|
//! | `write=<n>` | writing a temporary file, after `<n>` bytes |
//! | `sync` | flushing to stable storage: a temporary file's own flush, and the flush that publishing and replacing do first |
//! | `publish` | publishing a temporary file under its final name |
//! | `replace` | replacing a file (the catalog) |
//! | `lease` | the set lock's lease, whenever it is checked |
//! | `read=<n>` | reading a published file, after `<n>` bytes |
//!
//! Everything else is passed through, so the tests can check what the
//! failure left behind through the plain URI.

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::Duration;

use lr_core::io::{ReadSeek, WriteSeekSync};
use lr_core::{Error, Result, SetId};

use crate::{Destination, Durability, LockOwner, SetHandle, SetLock, TempFile};

/// The operation that fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Writing a temporary file fails after this many bytes.
    Write(u64),
    /// Flushing a temporary file fails.
    Sync,
    /// Publishing under the final name fails.
    Publish,
    /// Replacing a file fails.
    Replace,
    /// The set lock's lease is reported lost.
    Lease,
    /// Reading a published file fails after this many bytes.
    Read(u64),
}

impl Fault {
    /// Parse the `<kind>` of a `fault+<kind>:` URI.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for an unknown kind.
    pub fn parse(kind: &str) -> Result<Self> {
        let bytes = |value: &str| {
            value
                .parse::<u64>()
                .map_err(|_| Error::unsupported(format!("fault byte count `{value}`")))
        };
        match kind.split_once('=') {
            Some(("write", count)) => Ok(Self::Write(bytes(count)?)),
            Some(("read", count)) => Ok(Self::Read(bytes(count)?)),
            None if kind == "sync" => Ok(Self::Sync),
            None if kind == "publish" => Ok(Self::Publish),
            None if kind == "replace" => Ok(Self::Replace),
            None if kind == "lease" => Ok(Self::Lease),
            _ => Err(Error::unsupported(format!("unknown fault `{kind}`"))),
        }
    }
}

/// Split `fault+<kind>:<uri>` into the fault and the wrapped URI.
///
/// # Errors
/// Returns [`Error::Unsupported`] for an unknown kind.
pub fn split(uri: &str) -> Result<Option<(Fault, &str)>> {
    let Some(rest) = uri.strip_prefix("fault+") else {
        return Ok(None);
    };
    let (kind, inner) = rest
        .split_once(':')
        .ok_or_else(|| Error::unsupported("a fault URI is fault+<kind>:<uri>"))?;
    Ok(Some((Fault::parse(kind)?, inner)))
}

fn injected(what: &str) -> std::io::Error {
    std::io::Error::other(format!("injected fault: {what}"))
}

/// A destination whose one operation fails.
pub struct FaultyDestination {
    inner: Arc<dyn Destination>,
    fault: Fault,
}

impl FaultyDestination {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn Destination>, fault: Fault) -> Self {
        Self { inner, fault }
    }
}

impl Destination for FaultyDestination {
    fn open_set(&self, set: &SetId) -> Result<SetHandle> {
        self.inner.open_set(set)
    }

    fn open_existing_set(&self, set: &SetId) -> Result<SetHandle> {
        self.inner.open_existing_set(set)
    }

    fn lock_set(&self, set: &SetHandle, owner: &LockOwner, ttl: Duration) -> Result<SetLock> {
        let lock = self.inner.lock_set(set, owner, ttl)?;
        Ok(self.wrap_lock(lock))
    }

    fn lock_set_breaking_stale(
        &self,
        set: &SetHandle,
        owner: &LockOwner,
        ttl: Duration,
    ) -> Result<SetLock> {
        let lock = self.inner.lock_set_breaking_stale(set, owner, ttl)?;
        Ok(self.wrap_lock(lock))
    }

    fn create_tmp(&self, set: &SetHandle, final_name: &str) -> Result<TempFile> {
        let tmp = self.inner.create_tmp(set, final_name)?;
        let writer: Box<dyn WriteSeekSync + Send> = match self.fault {
            Fault::Write(limit) => Box::new(FaultyWriter {
                inner: tmp.writer,
                limit: Some(limit),
                fail_sync: false,
                written: 0,
            }),
            Fault::Sync => Box::new(FaultyWriter {
                inner: tmp.writer,
                limit: None,
                fail_sync: true,
                written: 0,
            }),
            _ => tmp.writer,
        };
        Ok(TempFile {
            name: tmp.name,
            writer,
        })
    }

    fn publish_new(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        match self.fault {
            // Publishing flushes first; a failed flush publishes nothing.
            Fault::Sync => return Err(Error::Io(injected("sync"))),
            Fault::Publish => return Err(Error::Io(injected("publish"))),
            _ => {}
        }
        self.inner.publish_new(set, tmp, final_name)
    }

    fn replace(&self, set: &SetHandle, tmp: &str, final_name: &str) -> Result<Durability> {
        match self.fault {
            Fault::Sync => return Err(Error::Io(injected("sync"))),
            Fault::Replace => return Err(Error::Io(injected("replace"))),
            _ => {}
        }
        self.inner.replace(set, tmp, final_name)
    }

    fn open_ro(&self, set: &SetHandle, name: &str) -> Result<Box<dyn ReadSeek + Send>> {
        let reader = self.inner.open_ro(set, name)?;
        match self.fault {
            Fault::Read(limit) => Ok(Box::new(FaultyReader {
                inner: reader,
                limit,
                position: 0,
            })),
            _ => Ok(reader),
        }
    }

    fn list(&self, set: &SetHandle) -> Result<Vec<String>> {
        self.inner.list(set)
    }

    fn list_set_names(&self) -> Result<Vec<String>> {
        self.inner.list_set_names()
    }

    fn delete(&self, set: &SetHandle, name: &str) -> Result<()> {
        self.inner.delete(set, name)
    }
}

impl FaultyDestination {
    fn wrap_lock(&self, lock: SetLock) -> SetLock {
        if self.fault != Fault::Lease {
            return lock;
        }
        let path = lock.path.clone();
        SetLock::with_check(path.clone(), lock, move || {
            Err(crate::lease_lost(&path, "injected fault: lease"))
        })
    }
}

struct FaultyWriter {
    inner: Box<dyn WriteSeekSync + Send>,
    limit: Option<u64>,
    fail_sync: bool,
    written: u64,
}

impl Write for FaultyWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(limit) = self.limit
            && self.written + bytes.len() as u64 > limit
        {
            return Err(injected("write"));
        }
        let written = self.inner.write(bytes)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for FaultyWriter {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(position)
    }
}

impl WriteSeekSync for FaultyWriter {
    fn sync_all(&mut self) -> std::io::Result<()> {
        if self.fail_sync {
            return Err(injected("sync"));
        }
        self.inner.sync_all()
    }
}

struct FaultyReader {
    inner: Box<dyn ReadSeek + Send>,
    limit: u64,
    position: u64,
}

impl Read for FaultyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.position + buffer.len() as u64 > self.limit {
            return Err(injected("read"));
        }
        let read = self.inner.read(buffer)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for FaultyReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.position = self.inner.seek(position)?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::{Fault, split};

    #[test]
    fn fault_uris_parse() {
        assert_eq!(
            split("fault+write=100:/tmp/x").expect("uri"),
            Some((Fault::Write(100), "/tmp/x"))
        );
        assert_eq!(
            split("fault+lease:sftp://h/p").expect("uri"),
            Some((Fault::Lease, "sftp://h/p"))
        );
        assert_eq!(split("/tmp/x").expect("uri"), None);
        assert!(split("fault+melt:/tmp/x").is_err());
    }
}
