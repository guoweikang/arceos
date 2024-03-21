#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;
use axerrno::LinuxResult;
use mm::VmAreaStruct;
use memory_addr::{is_aligned_4k, align_down_4k, PAGE_SIZE_4K, PAGE_SHIFT};
use memory_addr::align_up_4k;
use core::ops::Bound;
use axhal::mem::{phys_to_virt, virt_to_phys};
pub use mm::FileRef;

/// Interpret addr exactly.
pub const MAP_FIXED: usize = 0x10;
/// Don't use a file.
pub const MAP_ANONYMOUS: usize = 0x20;

pub fn mmap(
    mut va: usize, mut len: usize, _prot: usize, flags: usize,
    file: Option<FileRef>, offset: usize
) -> LinuxResult<usize> {
    assert!(is_aligned_4k(va));
    len = align_up_4k(len);
    error!("mmap va {:#X} offset {:#X}", va, offset);

    if (flags & MAP_FIXED) == 0 {
        va = get_unmapped_vma(va, len);
        error!("Get unmapped vma {:#X}", va);
    }

    error!("mmap region: {:#X} - {:#X}", va, va + len);
    let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, file, flags);
    let mm = task::current().mm();
    mm.lock().vmas.insert(va, vma);

    Ok(va)
}

pub fn get_unmapped_vma(va: usize, len: usize) -> usize {
    let mm = task::current().mm();
    let locked_mm = mm.lock();
    let mut gap_start = 0;
    for (_, vma) in &locked_mm.vmas {
        error!("{:#X} {:#X}", vma.vm_start, vma.vm_end);
        if gap_start == 0 {
            gap_start = vma.vm_end;
            continue;
        }

        if vma.vm_start - gap_start >= len {
            return gap_start;
        }
    }
    unimplemented!("NO available unmapped vma!");
}

pub fn faultin_page(va: usize) -> usize {
    error!("faultin_page... va {:#X}", va);
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
    //let flags = vma.vm_flags;
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    let direct_va: usize = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K).unwrap();

    // Todo: check whether we need to zero it.
    let buf = unsafe {
        core::slice::from_raw_parts_mut(direct_va as *mut u8, PAGE_SIZE_4K)
    };
    buf.fill(0);

    let pa = virt_to_phys(direct_va.into()).into();

    if vma.vm_file.get().is_some() {
        let f = vma.vm_file.get().unwrap().clone();
        locked_mm.fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
    }
    let _ = locked_mm.map_region(va, pa, PAGE_SIZE_4K, 1);
    phys_to_virt(pa.into()).into()
}
