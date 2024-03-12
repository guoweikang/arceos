#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
use axerrno::{LinuxError, LinuxResult};
use mm::VmAreaStruct;
use memory_addr::{is_aligned_4k, align_down_4k, align_up_4k, PAGE_SIZE_4K, PAGE_SHIFT};
use core::ops::Bound;
use axhal::mem::{phys_to_virt, virt_to_phys};

pub fn mmap(
    va: usize, len: usize, prot: usize, flags: usize,
    fd: usize, offset: usize
) -> LinuxResult {
    assert!(is_aligned_4k(len));

    let mm = task::current().mm();
    //mm.lock().mmap(va, len, prot, flags, None, offset);

    let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, None, flags);
    mm.lock().vmas.insert(va, vma);

    /*
        let ft = self.filetable.lock();
        let file = if flags != 0 {
            ft.get_file(fd)
        } else {
            None
        };

        match self.mm {
            Some(ref mm) => {
            },
            None => {
                panic!("NOT user process");
            }
        }
    */
    error!("mmap!");
    Ok(())
}

pub fn faultin_page(va: usize) -> usize {
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
    let file = vma.vm_file.clone();
    let offset = (vma.vm_pgoff << PAGE_SHIFT) + delta;

    let pa = axalloc::global_allocator()
        .alloc_pages(1, PAGE_SIZE_4K)
        .map(|va| virt_to_phys(va.into()))
        .ok()
        .unwrap()
        .into();
    if flags != 0 {
        if let Some(f) = file {
            locked_mm.fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
        }
    }
    let _ = locked_mm.map_region(va, pa, PAGE_SIZE_4K, 1);
    error!("faultin_page...");
    phys_to_virt(pa.into()).into()
}
