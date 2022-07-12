extern crate syscalls;

use core::mem::ManuallyDrop;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use syscalls::{Sysno::mmap, syscall, syscall_args};

const PAGE_SIZE:     usize = 4096;
const NB_FRAMES:     usize = 2;
const NB_SWAP_PAGES: usize = 4;

const PROT_READ:  usize = 0x01;
const PROT_WRITE: usize = 0x02;
const PROT_EXEC:  usize = 0x04;

const MAP_SHARED:    usize = 0x01;
const MAP_PRIVATE:   usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

const SWAP_FILENAME: &str = "mmu.swap";

/// Tracks allocated and free frames in memory.
#[derive(Debug)]
struct FrameAllocator {
    busy_frames: Vec<usize>,
    free_frames: Vec<usize>,
    frames: Vec<[u8; PAGE_SIZE]>,
}

impl FrameAllocator {
    pub fn new(nb_pages: usize) -> FrameAllocator {

        FrameAllocator {
            busy_frames: Vec::new(),
            free_frames: (0..nb_pages).collect(),
            frames: vec![[0u8; PAGE_SIZE]; nb_pages],
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
        println!("{:#?}", fd);

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
}

impl Mmu {
    pub fn new(nb_frames: usize, nb_swap_pages: usize) -> Mmu {
        Mmu {
            frame_allocator: FrameAllocator::new(nb_frames),
            swap: Swap::new(nb_swap_pages),
        }
    }
}

fn main() {
    let mut mmu = Mmu::new(NB_FRAMES, NB_SWAP_PAGES);
    mmu.swap.pages.push({[0u8; PAGE_SIZE]});
    println!("{:#?}", mmu);
}
