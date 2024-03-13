#![no_std]
#![feature(btree_cursors)]

#[macro_use]
extern crate log;
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::OnceCell;
use axfile::fops::File;
use axhal::arch::dup_kernel_pg_dir;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::MappingFlags;
use axhal::paging::PageTable;
use axhal::paging::PagingResult;
use axio::SeekFrom;
use core::cell::RefCell;
use core::ops::Bound;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use memory_addr::align_down_4k;
use memory_addr::is_aligned_4k;
use memory_addr::PAGE_SHIFT;
use memory_addr::PAGE_SIZE_4K;
use spinlock::SpinNoIrq;

pub type FileRef = Arc<SpinNoIrq<File>>;

static MM_UNIQUE_ID: AtomicUsize = AtomicUsize::new(1);

pub struct VmAreaStruct {
    pub vm_start: usize,
    pub vm_end: usize,
    pub vm_pgoff: usize,
    pub vm_file: OnceCell<Arc<SpinNoIrq<File>>>,
    pub vm_flags: usize,
}

impl VmAreaStruct {
    pub fn new(
        vm_start: usize,
        vm_end: usize,
        vm_pgoff: usize,
        vm_file: Option<FileRef>,
        vm_flags: usize,
    ) -> Self {
        let vma = Self {
            vm_start,
            vm_end,
            vm_pgoff,
            vm_file: OnceCell::new(),
            vm_flags,
        };
        if let Some(f) = vm_file {
            vma.vm_file.set(f);
        }
        vma
    }
}

pub struct MmStruct {
    id: usize,
    pub vmas: BTreeMap<usize, VmAreaStruct>,
    pgd: RefCell<PageTable>,
    brk: usize,
}

impl MmStruct {
    pub fn new() -> Self {
        Self {
            id: MM_UNIQUE_ID.fetch_add(1, Ordering::SeqCst),
            vmas: BTreeMap::new(),
            pgd: RefCell::new(dup_kernel_pg_dir()),
            brk: 0,
        }
    }

    fn root_paddr(&self) -> usize {
        self.pgd.borrow().root_paddr().into()
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn brk(&self) -> usize {
        self.brk
    }

    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    pub fn map_region(&self, va: usize, pa: usize, len: usize, _uflags: usize) -> PagingResult {
        let flags =
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER;
        self.pgd
            .borrow_mut()
            .map_region(va.into(), pa.into(), len, flags, true)
    }

    /*
    pub fn mmap(
        &mut self,
        va: usize,
        len: usize,
        _prot: usize,
        flags: usize,
        file: Option<Arc<SpinNoIrq<File>>>,
        offset: usize,
    ) {
        assert!(is_aligned_4k(len));
        let vma = VmAreaStruct::new(va, va + len, offset >> PAGE_SHIFT, file.clone(), flags);
        self.vmas.insert(va, vma);
    }

    pub fn faultin_page(&self, va: usize) -> usize {
        let vma = self.vmas.upper_bound(Bound::Included(&va)).value().unwrap();
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
                self.fill_cache(pa, PAGE_SIZE_4K, &mut f.lock(), offset);
            }
        }
        let _ = self.map_region(va, pa, PAGE_SIZE_4K, 1);
        phys_to_virt(pa.into()).into()
    }
    */

    pub fn fill_cache(&self, pa: usize, len: usize, file: &mut File, offset: usize) {
        let offset = align_down_4k(offset);
        let va = phys_to_virt(pa.into()).as_usize();

        let buf = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };

        info!("offset {:#X} len {:#X}", offset, len);
        let _ = file.seek(SeekFrom::Start(offset as u64));

        let mut pos = 0;
        while pos < len {
            let ret = file.read(&mut buf[pos..]).unwrap();
            if ret == 0 {
                break;
            }
            pos += ret;
        }
        buf[pos..].fill(0);
        info!("OK");
    }
}
