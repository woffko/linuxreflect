//! Private scratch files for manifest spools (R08, R39).
//!
//! A block or whole-disk backup writes its manifest to scratch space first and
//! copies it into the image once every chunk is stored. The scratch file never
//! has a name another user could reach: it is created with `O_TMPFILE`, or
//! under a random name that is created exclusively with mode 0600 and unlinked
//! at once, and the same descriptor is written, rewound and read. There is
//! nothing to substitute while the job runs and nothing to clean up when it
//! fails.

use std::fs::File;
use std::path::Path;

use lr_core::{Error, Result};

/// An unnamed scratch file in `dir`.
///
/// # Errors
/// Propagates I/O errors creating the file.
pub(crate) fn scratch_file(dir: &Path) -> Result<File> {
    tempfile::tempfile_in(dir).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::scratch_file;
    use std::io::{Read, Seek, Write};

    #[test]
    fn a_scratch_file_has_no_name_and_reads_back_what_was_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut file = scratch_file(dir.path()).expect("scratch");
        file.write_all(b"manifest entries").expect("write");
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("list").count(),
            0,
            "no name exists that could be replaced"
        );
        file.rewind().expect("rewind");
        let mut back = String::new();
        file.read_to_string(&mut back).expect("read");
        assert_eq!(back, "manifest entries");
    }
}
