//! Buffers aligned for `O_DIRECT`.
//!
//! Block devices require the buffer, the file offset and the transfer length to
//! share the device's alignment (spec §B: `AlignedBuf`, `max(4096, lbs)`).
//! Rust's allocator does not guarantee more than word alignment, so the buffer
//! is allocated through `std::alloc` with an explicit alignment.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;
use std::ptr::NonNull;

/// A heap buffer whose base address is aligned to a requested power of two.
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    layout: Layout,
    len: usize,
}

impl AlignedBuf {
    /// Allocate `len` zeroed bytes aligned to `align`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidInput`] when `align` is not a power of
    /// two, and [`io::ErrorKind::OutOfMemory`] when the allocation fails.
    pub fn new(len: usize, align: usize) -> io::Result<Self> {
        if !align.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("alignment {align} is not a power of two"),
            ));
        }
        let len = len.max(1);
        let layout = Layout::from_size_align(len, align)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `layout` has a non-zero size, and a failed allocation is
        // reported as null rather than undefined behaviour.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("{len} bytes aligned to {align}"),
            )
        })?;
        Ok(Self { ptr, layout, len })
    }

    /// Buffer contents.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the pointer owns `len` initialized bytes for `self`'s life.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Mutable buffer contents.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, and `&mut self` guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Buffer length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` when the buffer has no usable bytes (never: at least one byte is
    /// always allocated so the pointer stays valid).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Requested alignment.
    #[must_use]
    pub const fn alignment(&self) -> usize {
        self.layout.align()
    }

    /// Zero the buffer.
    pub fn clear(&mut self) {
        self.as_mut_slice().fill(0);
    }
}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AlignedBuf({} bytes, align {})",
            self.len,
            self.alignment()
        )
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `alloc_zeroed` with exactly this layout and
        // has not been freed, because `AlignedBuf` is not `Copy`.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

// SAFETY: the buffer owns its allocation exclusively, so moving it between
// threads cannot introduce aliasing.
unsafe impl Send for AlignedBuf {}

// SAFETY: the only access through `&AlignedBuf` is `as_slice`, which yields a
// shared byte slice; no interior mutability exists.
unsafe impl Sync for AlignedBuf {}

#[cfg(test)]
mod tests {
    use super::AlignedBuf;

    #[test]
    fn respects_the_requested_alignment() {
        for align in [4096usize, 8192] {
            let buffer = AlignedBuf::new(3 * align, align).expect("allocate");
            assert_eq!(buffer.len(), 3 * align);
            assert_eq!(buffer.alignment(), align);
            assert_eq!(
                buffer.as_slice().as_ptr() as usize % align,
                0,
                "buffer must be {align}-aligned"
            );
        }
    }

    #[test]
    fn starts_zeroed_and_can_be_cleared() {
        let mut buffer = AlignedBuf::new(4096, 4096).expect("allocate");
        assert!(buffer.as_slice().iter().all(|byte| *byte == 0));
        buffer.as_mut_slice()[10] = 0xff;
        buffer.clear();
        assert!(buffer.as_slice().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_a_non_power_of_two_alignment() {
        assert!(AlignedBuf::new(4096, 3000).is_err());
    }

    #[test]
    fn is_movable_between_threads() {
        let buffer = AlignedBuf::new(4096, 4096).expect("allocate");
        let handle = std::thread::spawn(move || {
            assert_eq!(buffer.as_slice().len(), 4096);
            buffer.len()
        });
        assert_eq!(handle.join().expect("thread"), 4096);
    }
}
