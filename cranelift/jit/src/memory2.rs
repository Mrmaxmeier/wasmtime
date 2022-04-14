use std::io;
use std::ptr;

fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

#[derive(Debug)]
struct Segment {
    ptr: *mut u8,
    len: usize,
    position: usize,
    target_prot: region::Protection,
    finalized: bool,
}

impl Segment {
    fn new(ptr: *mut u8, len: usize, target_prot: region::Protection) -> Self {
        let mut segment = Segment {
            ptr,
            len,
            target_prot,
            position: 0,
            finalized: false,
        };
        // set setgment to read-write for initialization
        segment.set_rw();
        segment
    }

    fn set_rw(&mut self) {
        unsafe {
            region::protect(self.ptr, self.len, region::Protection::READ_WRITE)
                .expect("unable to change memory protection for jit memory segment");
        }
    }

    fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        unsafe {
            region::protect(self.ptr, self.len, self.target_prot)
                .expect("unable to change memory protection for jit memory segment");
        }
        self.finalized = true;
    }

    fn allocate(&mut self, size: usize, align: usize) -> *mut u8 {
        assert!(self.has_space_for(size, align));
        self.position = align_up(self.position, align); // FIXME: this is incorrect for align > page size
        let ptr = unsafe { self.ptr.add(self.position) };
        self.position += size;
        ptr
    }

    fn has_space_for(&self, size: usize, align: usize) -> bool {
        align_up(self.position, align) + size <= self.len
    }
}

/// Type of branch protection to apply to executable memory.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BranchProtection {
    /// No protection.
    None,
    /// Use the Branch Target Identification extension of the Arm architecture.
    BTI,
}

/// JIT memory manager. This manages pages of suitably aligned and
/// accessible memory. Memory will be leaked by default to have
/// function pointers remain valid for the remainder of the
/// program's life.
// TODO: docs
// provides a contiguous memory area with properly managed protection flags.
pub(crate) struct Memory {
    ptr: *mut u8,
    size: usize,
    position: usize,
    segments: Vec<Segment>,
}

impl Memory {
    pub(crate) fn new(_branch_protection: BranchProtection, reserve_size: usize) -> Self {
        use nix::sys::mman::*;
        let size = align_up(reserve_size, region::page::size());
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                ProtFlags::PROT_NONE,
                // ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                -1,
                0,
            )
            .unwrap() // TODO?
        };

        Self {
            segments: Vec::new(),
            ptr: ptr as *mut u8,
            size,
            position: 0,
        }
    }

    pub(crate) fn allocate_readonly(&mut self, size: usize, align: u64) -> io::Result<*mut u8> {
        self.allocate(size, align as usize, region::Protection::READ)
    }

    pub(crate) fn allocate_readwrite(&mut self, size: usize, align: u64) -> io::Result<*mut u8> {
        self.allocate(size, align as usize, region::Protection::READ_WRITE)
    }

    pub(crate) fn allocate_readexec(&mut self, size: usize, align: u64) -> io::Result<*mut u8> {
        self.allocate(size, align as usize, region::Protection::READ_EXECUTE)
    }

    fn allocate(
        &mut self,
        size: usize,
        align: usize,
        protection: region::Protection,
    ) -> io::Result<*mut u8> {
        // TODO: fast path without linear scan over segments?

        // can we fit this allocation into an existing segment
        if let Some(segment) = self.segments.iter_mut().find(|seg| {
            seg.target_prot == protection && !seg.finalized && seg.has_space_for(size, align)
        }) {
            return Ok(segment.allocate(size, align));
        }

        // can we resize the last segment?
        if let Some(segment) = self.segments.iter_mut().last() {
            if segment.target_prot == protection && !segment.finalized {
                // resize
                let additional_size = region::page::ceil(align_up(size, align));
                assert!(self.position + additional_size <= self.size);
                segment.len += additional_size;
                segment.set_rw();
                self.position += additional_size;
                return Ok(segment.allocate(size, align));
            }
        }

        // allocate new segment for size&align
        self.allocate_segment(align_up(size, align), protection);
        let i = self.segments.len() - 1;
        Ok(self.segments[i].allocate(size, align))
    }

    fn allocate_segment(&mut self, size: usize, target_prot: region::Protection) {
        let size = region::page::ceil(size);
        let ptr = unsafe { self.ptr.add(self.position) };
        self.position += size;
        assert!(self.position <= self.size);
        self.segments.push(Segment::new(ptr, size, target_prot));
    }

    /// TODO
    pub(crate) fn finalize(&mut self) {
        for segment in &mut self.segments {
            segment.finalize();
        }
    }

    /// Frees the allocated memory region, which would be leaked otherwise.
    /// Likely to invalidate existing function pointers, causing unsafety.
    pub(crate) unsafe fn free(&mut self) {
        if self.ptr == ptr::null_mut() {
            return;
        }
        self.segments.clear();
        use nix::sys::mman::*;
        munmap(self.ptr.cast(), self.size).expect("failed to unmap jit memory region");
        self.ptr = ptr::null_mut();
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        let is_live = self.segments.iter().any(|seg| seg.finalized);
        if !is_live && self.ptr != ptr::null_mut() {
            // memory is unused, we can free this region
            unsafe { self.free() };
            panic!();
        }
    }
}
