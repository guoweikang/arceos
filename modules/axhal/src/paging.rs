//! Page table manipulation.

use core::cell::OnceCell;
use axalloc::global_allocator;
use page_table::PagingIf;

use crate::arch::{write_page_table_root, sync_kernel_mappings};
use crate::mem::{phys_to_virt, virt_to_phys, MemRegionFlags, PhysAddr, VirtAddr, PAGE_SIZE_4K};

#[doc(no_inline)]
pub use page_table::{MappingFlags, PageSize, PagingError, PagingResult};

impl From<MemRegionFlags> for MappingFlags {
    fn from(f: MemRegionFlags) -> Self {
        let mut ret = Self::empty();
        if f.contains(MemRegionFlags::READ) {
            ret |= Self::READ;
        }
        if f.contains(MemRegionFlags::WRITE) {
            ret |= Self::WRITE;
        }
        if f.contains(MemRegionFlags::EXECUTE) {
            ret |= Self::EXECUTE;
        }
        if f.contains(MemRegionFlags::DEVICE) {
            ret |= Self::DEVICE;
        }
        if f.contains(MemRegionFlags::UNCACHED) {
            ret |= Self::UNCACHED;
        }
        ret
    }
}

/// Implementation of [`PagingIf`], to provide physical memory manipulation to
/// the [page_table] crate.
pub struct PagingIfImpl;

impl PagingIf for PagingIfImpl {
    fn alloc_frame() -> Option<PhysAddr> {
        global_allocator()
            .alloc_pages(1, PAGE_SIZE_4K)
            .map(|vaddr| virt_to_phys(vaddr.into()))
            .ok()
    }

    fn dealloc_frame(paddr: PhysAddr) {
        global_allocator().dealloc_pages(phys_to_virt(paddr).as_usize(), 1)
    }

    #[inline]
    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        /// The architecture-specific page table.
        pub type PageTable = page_table::x86_64::X64PageTable<PagingIfImpl>;
    } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
        /// The architecture-specific page table.
        pub type PageTable = page_table::riscv::Sv39PageTable<PagingIfImpl>;
    } else if #[cfg(target_arch = "aarch64")]{
        /// The architecture-specific page table.
        pub type PageTable = page_table::aarch64::A64PageTable<PagingIfImpl>;
    }
}

static mut KERNEL_PAGE_TABLE: OnceCell<PageTable> = OnceCell::new();

fn kernel_pg_root_paddr() -> PhysAddr {
    unsafe { KERNEL_PAGE_TABLE.get().unwrap().root_paddr() }
}

pub fn setup_page_table_root(pt: PageTable) {
    unsafe {
        let _ = KERNEL_PAGE_TABLE.set(pt);
        write_page_table_root(kernel_pg_root_paddr());
    }
}

pub fn reuse_page_table_root() {
    unsafe {
        assert!(KERNEL_PAGE_TABLE.get().is_some());
        write_page_table_root(kernel_pg_root_paddr());
    }
}

pub fn pgd_alloc() -> PageTable {
    let pgtable = unsafe { KERNEL_PAGE_TABLE.get().unwrap().clone() };
    /* Copy kernel mappings */
    sync_kernel_mappings(kernel_pg_root_paddr(), pgtable.root_paddr());
    pgtable
}
