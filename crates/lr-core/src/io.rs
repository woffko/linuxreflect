//! Reader/writer traits shared by the storage and format layers (spec §C.1).
//!
//! `Destination::open_ro` and `Destination::create_tmp` hand out boxed readers
//! and writers, and the format codec reads chunk records through a *second*
//! handle while a metadata page stream is open. Both sides therefore need one
//! definition of "a file readable from any offset" and "a writer that can be
//! flushed to stable storage", rather than a trait per crate.

use std::io::{Read, Seek, Write};

/// A file that can be read from any offset.
pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// A file that can be flushed to stable storage.
pub trait WriteSeekSync: Write + Seek {
    /// Flush the file's contents to the storage device.
    ///
    /// # Errors
    /// Propagates `fsync` failures.
    fn sync_all(&mut self) -> std::io::Result<()>;
}

impl WriteSeekSync for std::fs::File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        std::fs::File::sync_all(self)
    }
}
