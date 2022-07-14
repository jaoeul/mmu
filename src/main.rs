extern crate syscalls;

use core::mem::ManuallyDrop;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use syscalls::{Sysno::mmap, syscall, syscall_args};

const PAGE_SIZE:     usize = 4096;

const HOST_MEM_SIZE: usize = 1024 * 1024 * 1024;

/// Total number of pages that fit in host memory. When a page is allocated by
/// the host, it is reffered to as a "frame".
const NB_FRAMES: usize = HOST_MEM_SIZE / PAGE_SIZE;

const PROT_READ:  usize = 0x01;
const PROT_WRITE: usize = 0x02;
const PROT_EXEC:  usize = 0x04;

const MAP_SHARED:    usize = 0x01;
const MAP_PRIVATE:   usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

const SWAP_FILENAME: &str = "mmu.swap";
const NB_SWAP_PAGES: usize = 2;

/// Ispired by x86 paging design.
const PAGE_TABLE_DEPTH: usize = 4;

/// Number of bits in the virtual addresses which are not used for virtual
/// memory indexing.
const VADR_UNUSED_BITS: usize = 12;

/// Virtual address structure:
///
///   Four levels of 512 (1 << 9) byte entries with 4096 (1 << 12) byte pages.
///   This corresponds to the bits in a virtual address:
///
///       Offsets--+-------+---------+   Byte offset in final page
///       |        |       |         |      |       Unused
///       1        2       3         4      |          |
///   |-------||-------||-------||-------||----------||----------------|
/// 0b0000000000000000000000000000000000000000000000000000000000000000
const PAGE_TABLE_LAYOUT: [usize; PAGE_TABLE_DEPTH] = [16, 16, 16, 16];

type Page = [u8; PAGE_SIZE];

/// Return number of binary `1`s equal to `n`.
fn binary_ones(n: usize) -> usize {
    let mut res = 0;
    for i in 0..n {
        res = res | (1 << i);
    }
    return res;
}

#[derive(Debug)]
struct PageTable {
    // 4096 bytes per page table.
    entries: [u32; 1024],
}

impl PageTable {
    fn new() -> PageTable {
        PageTable {
            entries: [0; 1024],
        }
    }
}

#[derive(Clone, Debug)]
struct FrameMeta {
    is_free: bool,
    is_page_table: bool,
    parent_frame: usize,
    parent_frame_offset: usize,
}

impl FrameMeta {
    fn new() -> FrameMeta {
        FrameMeta {
            is_free: true,
            is_page_table: false,
            parent_frame: usize::MAX,
            parent_frame_offset: usize::MAX,
        }
    }
}

/// Tracks allocated and free frames in memory.
#[derive(Debug)]
struct FrameAllocator {
    busy_frames: Vec<usize>,
    free_frames: Vec<usize>,
    frames: Vec<[u8; PAGE_SIZE]>,
    meta: Vec<FrameMeta>,
}

impl FrameAllocator {
    pub fn new(nb_pages: usize) -> FrameAllocator {

        FrameAllocator {
            busy_frames: Vec::new(),
            free_frames: (0..nb_pages).collect(),
            frames: vec![[0u8; PAGE_SIZE]; nb_pages],
            meta: vec![FrameMeta::new(); NB_FRAMES],
        }
    }
}

#[derive(Debug)]
struct Swap {
    /// The index of free pages in the swapfile.
    free_pages: Vec<usize>,

    /// Vector of pages on disk.
    pages: ManuallyDrop<Vec<[u8; PAGE_SIZE]>>,
}

impl Swap {
    /// Create a swapfile on disk.
    pub fn new(nb_pages: usize) -> Swap {

        let file = File::create(SWAP_FILENAME).unwrap();
        file.set_len((nb_pages * PAGE_SIZE).try_into().unwrap());

        let file = File::options()
            .read(true)
            .write(true)
            .open(SWAP_FILENAME).unwrap();

        let fd: usize = file.as_raw_fd().try_into().unwrap();

        let mmap_args = syscall_args!(0,
                                      nb_pages * PAGE_SIZE,
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED,
                                      fd,
                                      0);

        let swap_adr: usize = unsafe { syscall(mmap, &mmap_args).unwrap() };
        let swap_ptr: *mut [u8; PAGE_SIZE] = swap_adr as *mut [u8; PAGE_SIZE];
        let swap_vec = unsafe { Vec::from_raw_parts(swap_ptr, 0, nb_pages) };

        Swap {
            free_pages: (0..nb_pages).collect(),
            pages: ManuallyDrop::new(swap_vec),
        }
    }
}

impl Drop for Swap {
    fn drop(&mut self) {
        println!("Cleaning up {}", SWAP_FILENAME);
        std::fs::remove_file(SWAP_FILENAME).unwrap();
    }
}

#[derive(Debug)]
struct Mmu {
    frame_allocator: FrameAllocator,
    swap: Swap,
    root_pt: PageTable,
}

impl Mmu {
    pub fn new(nb_frames: usize, nb_swap_pages: usize) -> Mmu {
        Mmu {
            frame_allocator: FrameAllocator::new(nb_frames),
            swap: Swap::new(nb_swap_pages),
            root_pt: PageTable::new(),
        }
    }

    /// Translate the virtual address to host address.
    pub fn lookup(&self, vadr: usize) -> usize {

        // We need to get the correct offset into the page table entry for every
        // level.
        //
        let mut curr_pt = &self.root_pt;

        for i in 0..PAGE_TABLE_DEPTH {

            // Shift for the sum off the number of binary ones according to the
            // virtual address layout.
            let shift: usize = PAGE_TABLE_LAYOUT[i + 1..PAGE_TABLE_DEPTH].iter().sum();
            println!("i: {}, shift: {}", i, shift);

            let off = (vadr >> shift) & binary_ones(PAGE_TABLE_LAYOUT[i]);
            // Range check offset.
            if off > 511 {
                panic!();
            }
            println!("{}", off);

        }

        return vadr;
    }
}

fn main() {
    let mut mmu = Mmu::new(NB_FRAMES, NB_SWAP_PAGES);
    mmu.swap.pages.push([0u8; PAGE_SIZE]);

    let num: usize = 0b0000000000000001_0000000000000010_0000000000000011_0000000000000101;
    let ret = mmu.lookup(num);
    //println!("{:#?}", ret);
}
