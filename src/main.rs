extern crate syscalls;

use core::mem::{ManuallyDrop, transmute, size_of};
use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use syscalls::{Sysno::mmap, syscall, syscall_args};

type Page = [u8; PAGE_SIZE];
type PageTableEntry = u32;

/// Must be a multiple of 4.
const PAGE_SIZE: usize = 4096;

/// Total memory given to the emulator.
const HOST_MEM_SIZE: usize = PAGE_SIZE * 2;

/// Total number of pages that fit in host memory. When a page is allocated by
/// the host, it is reffered to as a "frame".
const NB_FRAMES: usize = HOST_MEM_SIZE / PAGE_SIZE;

/// `mmap` syscall constants.
const PROT_READ:     usize = 0x01;
const PROT_WRITE:    usize = 0x02;
const PROT_EXEC:     usize = 0x04;
const MAP_SHARED:    usize = 0x01;
const MAP_PRIVATE:   usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;

/// Swap constants.
const SWAP_FILENAME: &str = "mmu.swap";
const NB_SWAP_PAGES: usize = 20;

/// Layout of the page table levels. Needs to add up to 64.
const PAGE_TABLE_LAYOUT: [usize; 6] = [19, 9, 9, 9, 9, 9];

/// Indecies in the page table layout which are not used as offsets for page and
/// memory indexing.
const PAGE_TABLE_LAYOUT_UNUSED_INDICIES: [usize; 1] = [0];

/// The index of the page table layout which is used for acutally memory
/// mapping, i.e. does not point to another page table.
const PAGE_TABLE_LAYOUT_FINAL_LEVEL: usize = 5;

/// Ispired by x86 paging design.
const PAGE_TABLE_DEPTH: usize = PAGE_TABLE_LAYOUT.len() - 1;

/// Size in bytes of a single page table entry.
const PAGE_TABLE_ENTRY_SIZE: usize = size_of::<PageTableEntry>();

/// Number of entries in a single page table.
const NB_PAGE_TABLE_ENTRIES: usize = PAGE_SIZE / PAGE_TABLE_ENTRY_SIZE;

/// Indicates that entry is empty. Must be higher than number of entries in a
/// page table. Otherwise it could be mistaken for a valid address.
const PAGE_TABLE_ENTRY_EMPTY: u32 = 0xdeadc0de;

/// Bitmask used to indicates that entry is located on disk (swap). The last bit
/// of the entry is used to indicate this, the lower 22 bits are used to
/// as a page offset into swap, and the last 9 bits are used as a byte offset
/// into the page where the target byte is allocated.
const PAGE_TABLE_ENTRY_ON_DISK: u32 = 1 << (PAGE_TABLE_ENTRY_SIZE * 8 - 1);

/// Return number of binary `1`s equal to `n`. Compile time evaluable.
const fn binary_ones(n: usize) -> usize {
    match n {
        0  => { return 0b0000000000000000000000000000000000000000000000000000000000000000; },
        1  => { return 0b0000000000000000000000000000000000000000000000000000000000000001; },
        2  => { return 0b0000000000000000000000000000000000000000000000000000000000000011; },
        3  => { return 0b0000000000000000000000000000000000000000000000000000000000000111; },
        4  => { return 0b0000000000000000000000000000000000000000000000000000000000001111; },
        5  => { return 0b0000000000000000000000000000000000000000000000000000000000011111; },
        6  => { return 0b0000000000000000000000000000000000000000000000000000000000111111; },
        7  => { return 0b0000000000000000000000000000000000000000000000000000000001111111; },
        8  => { return 0b0000000000000000000000000000000000000000000000000000000011111111; },
        9  => { return 0b0000000000000000000000000000000000000000000000000000000111111111; },
        10 => { return 0b0000000000000000000000000000000000000000000000000000001111111111; },
        11 => { return 0b0000000000000000000000000000000000000000000000000000011111111111; },
        12 => { return 0b0000000000000000000000000000000000000000000000000000111111111111; },
        13 => { return 0b0000000000000000000000000000000000000000000000000001111111111111; },
        14 => { return 0b0000000000000000000000000000000000000000000000000011111111111111; },
        15 => { return 0b0000000000000000000000000000000000000000000000000111111111111111; },
        16 => { return 0b0000000000000000000000000000000000000000000000001111111111111111; },
        17 => { return 0b0000000000000000000000000000000000000000000000011111111111111111; },
        18 => { return 0b0000000000000000000000000000000000000000000000111111111111111111; },
        19 => { return 0b0000000000000000000000000000000000000000000001111111111111111111; },
        20 => { return 0b0000000000000000000000000000000000000000000011111111111111111111; },
        21 => { return 0b0000000000000000000000000000000000000000000111111111111111111111; },
        22 => { return 0b0000000000000000000000000000000000000000001111111111111111111111; },
        23 => { return 0b0000000000000000000000000000000000000000011111111111111111111111; },
        24 => { return 0b0000000000000000000000000000000000000000111111111111111111111111; },
        25 => { return 0b0000000000000000000000000000000000000001111111111111111111111111; },
        26 => { return 0b0000000000000000000000000000000000000011111111111111111111111111; },
        27 => { return 0b0000000000000000000000000000000000000111111111111111111111111111; },
        28 => { return 0b0000000000000000000000000000000000001111111111111111111111111111; },
        29 => { return 0b0000000000000000000000000000000000011111111111111111111111111111; },
        30 => { return 0b0000000000000000000000000000000000111111111111111111111111111111; },
        31 => { return 0b0000000000000000000000000000000001111111111111111111111111111111; },
        32 => { return 0b0000000000000000000000000000000011111111111111111111111111111111; },
        33 => { return 0b0000000000000000000000000000000111111111111111111111111111111111; },
        34 => { return 0b0000000000000000000000000000001111111111111111111111111111111111; },
        35 => { return 0b0000000000000000000000000000011111111111111111111111111111111111; },
        36 => { return 0b0000000000000000000000000000111111111111111111111111111111111111; },
        37 => { return 0b0000000000000000000000000001111111111111111111111111111111111111; },
        38 => { return 0b0000000000000000000000000011111111111111111111111111111111111111; },
        39 => { return 0b0000000000000000000000000111111111111111111111111111111111111111; },
        40 => { return 0b0000000000000000000000001111111111111111111111111111111111111111; },
        41 => { return 0b0000000000000000000000011111111111111111111111111111111111111111; },
        42 => { return 0b0000000000000000000000111111111111111111111111111111111111111111; },
        43 => { return 0b0000000000000000000001111111111111111111111111111111111111111111; },
        44 => { return 0b0000000000000000000011111111111111111111111111111111111111111111; },
        45 => { return 0b0000000000000000000111111111111111111111111111111111111111111111; },
        46 => { return 0b0000000000000000001111111111111111111111111111111111111111111111; },
        47 => { return 0b0000000000000000011111111111111111111111111111111111111111111111; },
        48 => { return 0b0000000000000000111111111111111111111111111111111111111111111111; },
        49 => { return 0b0000000000000001111111111111111111111111111111111111111111111111; },
        50 => { return 0b0000000000000011111111111111111111111111111111111111111111111111; },
        51 => { return 0b0000000000000111111111111111111111111111111111111111111111111111; },
        52 => { return 0b0000000000001111111111111111111111111111111111111111111111111111; },
        53 => { return 0b0000000000011111111111111111111111111111111111111111111111111111; },
        54 => { return 0b0000000000111111111111111111111111111111111111111111111111111111; },
        56 => { return 0b0000000001111111111111111111111111111111111111111111111111111111; },
        57 => { return 0b0000000011111111111111111111111111111111111111111111111111111111; },
        57 => { return 0b0000000111111111111111111111111111111111111111111111111111111111; },
        58 => { return 0b0000001111111111111111111111111111111111111111111111111111111111; },
        59 => { return 0b0000011111111111111111111111111111111111111111111111111111111111; },
        60 => { return 0b0000111111111111111111111111111111111111111111111111111111111111; },
        61 => { return 0b0001111111111111111111111111111111111111111111111111111111111111; },
        62 => { return 0b0011111111111111111111111111111111111111111111111111111111111111; },
        63 => { return 0b0111111111111111111111111111111111111111111111111111111111111111; },
        64 => { return 0b1111111111111111111111111111111111111111111111111111111111111111; },
        _ => { panic!("64 is my limit!"); },
    }
}

#[derive(Debug)]
struct PageTable {
    entries: [PageTableEntry; NB_PAGE_TABLE_ENTRIES],
}

impl PageTable {
    fn new() -> PageTable {
        PageTable {
            entries: [PAGE_TABLE_ENTRY_EMPTY; NB_PAGE_TABLE_ENTRIES],
        }
    }
}

/*
/// Convert between pages and page tables.
impl From<Page> for PageTable {
    fn from(page: Page) -> PageTable {
        return unsafe { transmute::<Page, PageTable>(page) };
    }
}

impl From<PageTable> for Page {
    fn from(pt: PageTable) -> Page {
        return unsafe { transmute::<PageTable, Page>(pt) };
    }
}

impl From<&mut PageTable> for &mut Page {
    fn from(pt: &mut PageTable) -> &mut Page {
        return unsafe { &mut transmute::<PageTable, Page>(pt) };
    }
}
*/

#[derive(Clone, Debug)]
struct FrameMeta {
    is_free: bool,
    is_page_table: bool,
    parent_page: PageTableEntry,
}

impl FrameMeta {
    fn new() -> FrameMeta {
        FrameMeta {
            is_free: true,
            is_page_table: false,
            parent_page: PAGE_TABLE_ENTRY_EMPTY,
        }
    }

    fn clear(&mut self) {
        self.is_free = true;
        self.is_page_table = false;
        self.parent_page = PAGE_TABLE_ENTRY_EMPTY;
    }
}

/// Tracks allocated and free frames in memory.
#[derive(Debug)]
struct FrameAllocator {
    busy_frames: VecDeque<usize>,
    free_frames: Vec<usize>,
    frames: Vec<Page>,
    meta: Vec<FrameMeta>,
    swap: Swap,
}

impl FrameAllocator {
    fn new(nb_pages: usize) -> FrameAllocator {

        // Make sure that the highest page table offset a virtual address can
        // have fits in our page tables.
        for i in 0..PAGE_TABLE_LAYOUT.len() {
            if PAGE_TABLE_LAYOUT_UNUSED_INDICIES.contains(&i) {
                continue;
            }

            let curr_off = binary_ones(PAGE_TABLE_LAYOUT[i]);
            if curr_off > NB_PAGE_TABLE_ENTRIES {
            panic!("Virtual address offset range exceeds the number of entries \
                   a page table can have. Chosen range: 0-{}, Page table fits: \
                   {}. Chose a vadr layout with less bits per page table \
                   offset, i.e. a smaller range.",
                   curr_off, NB_PAGE_TABLE_ENTRIES);
            }
        }

        FrameAllocator {
            busy_frames: VecDeque::new(),
            free_frames: (0..nb_pages).collect(),
            frames: vec![[0u8; PAGE_SIZE]; nb_pages],
            meta: vec![FrameMeta::new(); NB_FRAMES],
            swap: Swap::new(NB_SWAP_PAGES),
        }
    }

    /// Copies the contents of a frame to swap and adds it to the `free_frames`
    /// vector. This is where one can implement different page eviction
    /// algorithms, would one feel like it. Currently use a first-come-first-go
    /// approach to page eviction. Returns the index of the frame which got
    /// freed up by the evicton.
    fn evict_frame(&mut self) -> usize {
        let evictee = self.busy_frames.pop_front().unwrap();
        let mut new_home = self.swap.put_page(self.frames[evictee]);

        // Mark new address with a swap bit, indicating it's location on diska
        // swap.
        new_home |= PAGE_TABLE_ENTRY_ON_DISK as usize;

        println!("Evictee: {:#?}", evictee);
        println!("New home: {:#?}", new_home &
                 !PAGE_TABLE_ENTRY_ON_DISK as usize);

        // Break the tough news...
        let parent = self.meta[evictee].parent_page;

        // No references to the evicted page means that the evictee was located
        // in the root page table. If there is one, we update it with the new
        // page location on swap.
        if parent != PAGE_TABLE_ENTRY_EMPTY {

            let mut parent_page = if parent & PAGE_TABLE_ENTRY_ON_DISK != 0 {
                let parent_off = parent & !PAGE_TABLE_ENTRY_ON_DISK;
                    &self.swap.pages[parent_off as usize]
                }
                else {
                    &self.frames[parent as usize]
                };

            let parent_page_pt: &mut PageTable = unsafe {
                &mut transmute::<Page, PageTable>(*parent_page)
            };

            // Update parent's information.
            parent_page_pt.entries[self.meta[evictee].parent_page as usize] =
                new_home as u32;
        }

        // Clear the evicted frame.
        for byte in self.frames[evictee].iter_mut() {
            *byte = 0;
        }

        self.free_frames.push(evictee);
        return evictee;
    }

    /// Returns the index off the allocated frame in the `frames` vector.
    fn alloc(&mut self) -> usize {
        let allocated = if self.free_frames.len() == 0 {
            self.evict_frame()
        }
        else {
            self.free_frames.pop().unwrap()
        };
        return allocated;
    }
}

#[derive(Debug)]
struct Swap {
    /// The index of free pages in the swapfile.
    free_pages: Vec<usize>,

    /// Vector of pages on disk.
    pages: ManuallyDrop<Vec<Page>>,
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
        let swap_vec = unsafe {
            Vec::from_raw_parts(swap_ptr, nb_pages, nb_pages)
        };

        Swap {
            free_pages: (0..nb_pages).collect(),
            pages: ManuallyDrop::new(swap_vec),
        }
    }

    /// Writes the contents of `page` to next free page slot on disk and returns
    /// the page offset.
    fn put_page(&mut self, page: Page) -> usize {
        if self.free_pages.len() == 0 {
            panic!("Out of swap memory!");
        }
        let free_slot = self.free_pages.pop().unwrap();
        self.pages[free_slot] = page;
        return free_slot;
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
    root_pt: PageTable,
}

impl Mmu {
    pub fn new(nb_frames: usize, nb_swap_pages: usize) -> Mmu {
        Mmu {
            frame_allocator: FrameAllocator::new(nb_frames),
            root_pt: PageTable::new(),
        }
    }

    /// Return byte of the virtual address. Could be at disk, or in host memory.
    /// We don't know.
    pub fn lookup(&mut self, vadr: usize) -> u8 {

        // We need to get the correct offset into the page table entry for every
        // level.
        let mut curr_pt = &mut self.root_pt;
        let mut prev_entry = PAGE_TABLE_ENTRY_EMPTY;
        let mut prev_offset = PAGE_TABLE_ENTRY_EMPTY;

        // Traverse all page tables, until we reach the final level of acutal
        // memory mapped pages.
        for i in 0..PAGE_TABLE_DEPTH {

            // Ignore current level?
            if PAGE_TABLE_LAYOUT_UNUSED_INDICIES.contains(&i) {
                continue;
            }

            // Get the page table entry offset according to the page table
            // layout.
            let shift: usize = PAGE_TABLE_LAYOUT[i..PAGE_TABLE_DEPTH].iter()
                .sum();
            let off = (vadr >> shift) & binary_ones(PAGE_TABLE_LAYOUT[i]);
            println!("i: {}, shift: {}, offset: {}", i, shift, off);

            // Empty page table entry?
            if curr_pt.entries[off] == PAGE_TABLE_ENTRY_EMPTY {

                let new_frame = self.frame_allocator.alloc();

                self.frame_allocator.busy_frames.push_back(new_frame);
                self.frame_allocator.meta[new_frame].parent_page = prev_entry;

                // Create a new page table at the new frame.
                self.frame_allocator.frames[new_frame] =
                    unsafe { transmute::<PageTable, Page>(PageTable::new()) };

                // Note the address of the new page table.
                curr_pt.entries[off] = new_frame as u32;
                println!("Created new page table at frame: {}, level: {}",
                         new_frame, i);
            }

            // Continue the traversal.
            let pt_entry = curr_pt.entries[off];

            // Get the next page table either swap disk or from host memory.
            let next_pt_frame = if pt_entry & PAGE_TABLE_ENTRY_ON_DISK != 0 {
                let pt_entry_swap = pt_entry & !PAGE_TABLE_ENTRY_ON_DISK;
                    &self.frame_allocator.swap.pages[pt_entry_swap as usize]
                }
                else {
                    &self.frame_allocator.frames[pt_entry as usize]
                };

            let next_pt = unsafe {
                transmute::<Page, PageTable>(*next_pt_frame)
            };

            *curr_pt = next_pt;
            prev_entry = pt_entry;
            prev_offset = off as u32;
        }

        // Final level reached. Time to find the actual byte.
        let byte_offset = vadr & binary_ones(
            PAGE_TABLE_LAYOUT[PAGE_TABLE_DEPTH]);
        println!("Last offset: {}", byte_offset);

        // Convert the the last level is not a page table, but a table of actual
        // page.
        let target_page: Page = unsafe {
            *transmute::<&mut PageTable, &mut Page>(curr_pt) };
        let target_byte: u8 = target_page[byte_offset];

        //return self.frame_allocator.frames[last_off] as usize;
        return target_byte.into();
    }
}

fn main() {
    let mut mmu = Mmu::new(NB_FRAMES, NB_SWAP_PAGES);
    //mmu.frame_allocator.swap.pages.push([0u8; PAGE_SIZE]);
    //
    //const PAGE_TABLE_LAYOUT: [usize; 6] = [19, 9, 9, 9, 9, 9];

    let num: usize = 0b1111111111111111111_000000001_000000001_000000001_000000001_000000001;
    let ret = mmu.lookup(num);
    let num: usize = 0b1111111111111111111_000000011_000000001_000000001_000000001_000000001;
    let ret = mmu.lookup(num);

    println!("{:#x}", NB_FRAMES);
    println!("{:#x}", ret);
}
