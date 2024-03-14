#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;

use axerrno::LinuxResult;
use memory_addr::{align_down_4k, align_up_4k, PAGE_SIZE_4K};
use axfile::fops::File;
use axfile::fops::OpenOptions;
use elf::segment::ProgramHeader;
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use elf::segment::SegmentTable;
use elf::parse::ParseAt;
use axio::SeekFrom;
use spinlock::SpinNoIrq;
//use mm::MmStruct;
use mmap::FileRef;
use axhal::arch::TrapFrame;
use axhal::arch::{SR_SPIE, SR_FS_INITIAL, SR_UXL_64};

const ELF_HEAD_BUF_SIZE: usize = 256;
const TASK_SIZE: usize = 0x40_0000_0000;

pub fn kernel_execve(filename: &str) -> LinuxResult {
    error!("kernel_execve... {}", filename);

    let task = task::current();
    task.alloc_mm();

    // TODO: Move it into kernel_init().
    setup_zero_page()?;

    let sp = get_arg_page()?;
    bprm_execve(filename, 0, sp)
}

fn setup_zero_page() -> LinuxResult {
    error!("setup_zero_page ...");
    mmap::mmap(0x0, PAGE_SIZE_4K, 0, 0, None, 0)
}

fn get_arg_page() -> LinuxResult<usize> {
    let va = TASK_SIZE - PAGE_SIZE_4K;
    mmap::mmap(va, PAGE_SIZE_4K, 0, 0, None, 0)?;
    let direct_va = mmap::faultin_page(va);
    let stack = unsafe {
        core::slice::from_raw_parts_mut(
            direct_va as *mut usize, 4
        )
    };
    stack[0] = 0;
    stack[1] = TASK_SIZE - 16;
    stack[2] = 0;
    stack[3] = 0;
    error!("get_arg_page!");
    Ok(TASK_SIZE - 32)
}

/// sys_execve() executes a new program.
fn bprm_execve(filename: &str, flags: usize, sp: usize) -> LinuxResult {
    let file = do_open_execat(filename, flags)?;
    exec_binprm(file, sp)
}

fn do_open_execat(filename: &str, _flags: usize) -> LinuxResult<FileRef> {
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let file = File::open(filename, &opts, &fs)?;
    Ok(Arc::new(SpinNoIrq::new(file)))
}

fn exec_binprm(file: FileRef, sp: usize) -> LinuxResult {
    load_elf_binary(file, sp)
}

fn load_elf_binary(file: FileRef, sp: usize) -> LinuxResult {
    let (phdrs, entry) = load_elf_phdrs(file.clone())?;

    let mut elf_bss: usize = 0;
    let mut elf_brk: usize = 0;

    error!("There are {} PT_LOAD segments", phdrs.len());
    for phdr in phdrs {
        error!("phdr: offset: {:#X}=>{:#X} size: {:#X}=>{:#X}",
            phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz);

        let va = align_down_4k(phdr.p_vaddr as usize);
        let va_end = align_up_4k((phdr.p_vaddr + phdr.p_filesz) as usize);
        mmap::mmap(va, va_end - va, 0, 1, Some(file.clone()), phdr.p_offset as usize)?;

        let pos = (phdr.p_vaddr + phdr.p_filesz) as usize;
        if elf_bss < pos {
            elf_bss = pos;
        }
        let pos = (phdr.p_vaddr + phdr.p_memsz) as usize;
        if elf_brk < pos {
            elf_brk = pos;
        }
    }

    error!("set brk...");
    set_brk(elf_bss, elf_brk);

    error!("start thread...");
    start_thread(entry, sp);
    Ok(())
}

fn set_brk(elf_bss: usize, elf_brk: usize) {
    let elf_bss = align_up_4k(elf_bss);
    let elf_brk = align_up_4k(elf_brk);
    if elf_bss < elf_brk {
        error!("{:#X} < {:#X}", elf_bss, elf_brk);
        mmap::mmap(elf_bss, elf_brk - elf_bss, 0, 0, None, 0).unwrap();
    }

    task::current().mm().lock().set_brk(elf_brk as usize)
}

fn load_elf_phdrs(file: FileRef) -> LinuxResult<(Vec<ProgramHeader>, usize)> {
    let mut file = file.lock();
    let mut buf: [u8; ELF_HEAD_BUF_SIZE] = [0; ELF_HEAD_BUF_SIZE];
    file.read(&mut buf)?;

    let ehdr = ElfBytes::<AnyEndian>::parse_elf_header(&buf[..]).unwrap();
    error!("e_entry: {:#X}", ehdr.e_entry);

    let phnum = ehdr.e_phnum as usize;
    // Validate phentsize before trying to read the table so that we can error early for corrupted files
    let entsize = ProgramHeader::validate_entsize(ehdr.class, ehdr.e_phentsize as usize).unwrap();
    let size = entsize.checked_mul(phnum).unwrap();
    assert!(size > 0 && size <= PAGE_SIZE_4K);
    let phoff = ehdr.e_phoff;
    //let mut buf: [u8; PAGE_SIZE_4K] = [0; PAGE_SIZE_4K];
    let mut buf: [u8; 2*1024] = [0; 2*1024];
    error!("phoff: {:#X}", ehdr.e_phoff);
    let _ = file.seek(SeekFrom::Start(phoff));
    file.read(&mut buf)?;
    let phdrs = SegmentTable::new(ehdr.endianness, ehdr.class, &buf[..]);

    let phdrs: Vec<ProgramHeader> = phdrs
        .iter()
        .filter(|phdr|{phdr.p_type == PT_LOAD})
        .collect();
    Ok((phdrs, ehdr.e_entry as usize))
}

fn start_thread(pc: usize, sp: usize) {
    let tf = unsafe {
        core::slice::from_raw_parts_mut(
            task::current().pt_regs() as *mut TrapFrame, 1
        )
    };
    tf[0].sepc = pc;
    tf[0].sstatus = SR_SPIE | SR_FS_INITIAL | SR_UXL_64;
    tf[0].regs.sp = sp;
}
