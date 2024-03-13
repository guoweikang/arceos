#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use mm::VmAreaStruct;
use memory_addr::{is_aligned_4k, align_down_4k, align_up_4k, PAGE_SIZE_4K, PAGE_SHIFT};
use core::ops::Bound;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axfile::fops::File;
use spinlock::SpinNoIrq;
pub use mm::FileRef;

pub fn mmap(
    va: usize, len: usize, prot: usize, flags: usize,
    file: Option<FileRef>, offset: usize
) -> LinuxResult {
    assert!(is_aligned_4k(len));
    error!("mmap va {:#X} offset {:#X}", va, offset);

    let mm = task::current().mm();
    let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, file, flags);
    mm.lock().vmas.insert(va, vma);

    Ok(())
}

pub fn faultin_page(va: usize) -> usize {
    debug!("faultin_page... va {:#X}", va);
    let mm = task::current().mm();
    let locked_mm = mm.lock();

    let vma = locked_mm.vmas.upper_bound(Bound::Included(&va)).value().unwrap();
    assert!(
        va >= vma.vm_start && va < vma.vm_end,
        "va {:#X} in {:#X} - {:#X}",
        va,
        vma.vm_start,
        vma.vm_end
    );
    let va = align_down_4k(va);
    let delta = va - vma.vm_start;
    let flags = vma.vm_flags;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    let pa = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .map(|va| virt_to_phys(va.into()))
        .ok()
        .unwrap()
        .into();
    if vma.vm_file.get().is_some() {
        let f = vma.vm_file.get().unwrap().clone();
        locked_mm.fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
    }
    let _ = locked_mm.map_region(va, pa, PAGE_SIZE_4K, 1);
    phys_to_virt(pa.into()).into()
}