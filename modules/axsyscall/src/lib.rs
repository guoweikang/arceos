#![cfg_attr(not(test), no_std)]

extern crate alloc;
use alloc::string::String;

use axhal::trap::SyscallHandler;
use axhal::arch::TrapFrame;
//use axhal::mem::virt_to_phys;
use core::arch::asm;
use memory_addr::{align_up_4k, is_aligned_4k};
use mmap::{MAP_FIXED, MAP_ANONYMOUS};
use axfile::fops::File;
use axfile::fops::OpenOptions;
use alloc::sync::Arc;
use spinlock::SpinNoIrq;
use axerrno::LinuxError;
use axhal::trap::SyscallArgs;

#[macro_use]
extern crate log;

pub const AT_FDCWD: isize = -100;
pub const AT_EMPTY_PATH: isize = 0x1000;

struct LinuxSyscallHandler;

fn do_syscall(args: SyscallArgs, sysno: usize) -> usize {
    match sysno {
        LINUX_SYSCALL_OPENAT => {
            linux_syscall_openat(args)
        },
        LINUX_SYSCALL_CLOSE => {
            linux_syscall_close(args)
        },
        LINUX_SYSCALL_READ => {
            linux_syscall_read(args)
        },
        LINUX_SYSCALL_WRITE => {
            linux_syscall_write(args)
        },
        LINUX_SYSCALL_WRITEV => {
            linux_syscall_writev(args)
        },
        LINUX_SYSCALL_READLINKAT => {
            usize::MAX
        },
        LINUX_SYSCALL_FSTATAT => {
            linux_syscall_fstatat(args)
        },
        LINUX_SYSCALL_UNAME => {
            linux_syscall_uname(args)
        },
        LINUX_SYSCALL_BRK => {
            linux_syscall_brk(args)
        },
        LINUX_SYSCALL_MUNMAP => {
            linux_syscall_munmap(args)
        },
        LINUX_SYSCALL_MMAP => {
            linux_syscall_mmap(args)
        },
        LINUX_SYSCALL_EXIT => {
            linux_syscall_exit(args)
        },
        LINUX_SYSCALL_EXIT_GROUP => {
            linux_syscall_exit_group(args)
        },
        _ => {
            0
        }
    }
}

#[crate_interface::impl_interface]
impl SyscallHandler for LinuxSyscallHandler {
    fn handle_syscall(tf: &mut TrapFrame) {
        axhal::arch::syscall(tf, do_syscall);
    }
}

//
// Linux syscall
//
const LINUX_SYSCALL_OPENAT:     usize = 0x38;
const LINUX_SYSCALL_CLOSE:      usize = 0x39;
const LINUX_SYSCALL_READ:       usize = 0x3f;
const LINUX_SYSCALL_WRITE:      usize = 0x40;
const LINUX_SYSCALL_WRITEV:     usize = 0x42;
const LINUX_SYSCALL_READLINKAT: usize = 0x4e;
const LINUX_SYSCALL_FSTATAT:    usize = 0x4f;
const LINUX_SYSCALL_EXIT:       usize = 0x5d;
const LINUX_SYSCALL_EXIT_GROUP: usize = 0x53;
const LINUX_SYSCALL_UNAME:      usize = 0xa0;
const LINUX_SYSCALL_BRK:        usize = 0xd6;
const LINUX_SYSCALL_MUNMAP:     usize = 0xd7;
const LINUX_SYSCALL_MMAP:       usize = 0xde;


#[derive(Debug)]
#[repr(C)]
struct iovec {
    iov_base: usize,
    iov_len: usize,
}

/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
/// The string must be null-terminated.
pub unsafe fn get_str_len(ptr: *const u8) -> usize {
    let mut cur = ptr as usize;
    while *(cur as *const u8) != 0 {
        cur += 1;
    }
    cur - ptr as usize
}

/// # Safety
///
/// The caller must ensure that the pointer is valid and
/// points to a valid C string.
pub fn raw_ptr_to_ref_str(ptr: *const u8) -> &'static str {
    let len = unsafe { get_str_len(ptr) };
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(slice) {
        s
    } else {
        panic!("not utf8 slice");
    }
}

pub fn get_user_str(ptr: usize) -> String {
    let ptr = ptr as *const u8;
    axhal::arch::enable_sum();
    let ptr = raw_ptr_to_ref_str(ptr);
    let s = String::from(ptr);
    axhal::arch::disable_sum();
    s
}

fn linux_syscall_openat(args: SyscallArgs) -> usize {
    let [dtd, filename, flags, mode, ..] = args;

    let filename = get_user_str(filename);
    error!("filename: {}\n", filename);
    //////////////////////////
    let mut opts = OpenOptions::new();
    opts.read(true);

    let current = task::current();
    let fs = current.fs.lock();
    let file = match File::open(&filename, &opts, &fs) {
        Ok(f) => f,
        Err(e) => {
            return (-LinuxError::from(e).code()) as usize;
        },
    };
    let fd = current.filetable.lock().insert(Arc::new(SpinNoIrq::new(file)));
    //////////////////////////
    error!("linux_syscall_openat fd {}", fd);
    fd
}

fn linux_syscall_close(args: SyscallArgs) -> usize {
    error!("linux_syscall_close");
    0
}

fn linux_syscall_read(args: SyscallArgs) -> usize {
    let [fd, buf, count, ..] = args;

    let user_buf = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, count)
    };

    let current = task::current();
    let filetable = current.filetable.lock();
    let file = filetable.get_file(fd).unwrap();
    let mut pos = 0;
    assert!(count < 1024);
    let mut buf: [u8; 1024] = [0; 1024];
    while pos < count {
        let ret = file.lock().read(&mut buf[pos..]).unwrap();
        if ret == 0 {
            break;
        }
        pos += ret;
    }
    axhal::arch::enable_sum();
    user_buf.copy_from_slice(&buf[..count]);
    axhal::arch::disable_sum();
    //error!("linux_syscall_read: fd {}, buf {:#X}, count {}, ret {}", fd, buf, count, pos);
    pos
}

fn linux_syscall_write(args: SyscallArgs) -> usize {
    let [fd, buf, size, ..] = args;
    debug!("write: {:#x}, {:#x}, {:#x}", fd, buf, size);

    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, size) };
    /*
    let s = String::from_utf8(bytes.into());
    debug!("{}", s.unwrap());
    */

    axhal::arch::enable_sum();
    axhal::console::write_bytes(bytes);
    axhal::arch::disable_sum();

    return size;
}

fn linux_syscall_writev(args: SyscallArgs) -> usize {
    let [fd, array, size, ..] = args;
    debug!("writev: {:#x}, {:#x}, {:#x}", fd, array, size);

    axhal::arch::enable_sum();
    let iov_array = unsafe { core::slice::from_raw_parts(array as *const iovec, size) };
    for iov in iov_array {
        debug!("iov: {:#X} {:#X}", iov.iov_base, iov.iov_len);
        let bytes = unsafe { core::slice::from_raw_parts(iov.iov_base as *const _, iov.iov_len) };
        let s = String::from_utf8(bytes.into());
        error!("{}", s.unwrap());
    }
    axhal::arch::disable_sum();

    return size;
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KernelStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub _pad0: u64,
    pub st_size: u64,
    pub st_blksize: u32,
    pub _pad1: u32,
    pub st_blocks: u64,
    pub st_atime_sec: isize,
    pub st_atime_nsec: isize,
    pub st_mtime_sec: isize,
    pub st_mtime_nsec: isize,
    pub st_ctime_sec: isize,
    pub st_ctime_nsec: isize,
}

fn linux_syscall_fstatat(args: SyscallArgs) -> usize {
    let [dirfd, pathname, statbuf, flags, ..] = args;

    if (flags as isize & AT_EMPTY_PATH) == 0 {
        let pathname = get_user_str(pathname);
        warn!("!!! implement NONE AT_EMPTY_PATH for pathname: {}\n", pathname);
        return 0;
    }

    error!("###### fstatat!!! {:#x} {:#x} {:#x}", dirfd, statbuf, flags);
    let current = task::current();
    let filetable = current.filetable.lock();
    let file = match filetable.get_file(dirfd) {
        Some(f) => f,
        None => {
            return (-2isize) as usize;
        },
    };
    let metadata = file.lock().get_attr().unwrap();
    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    let st_size = metadata.size();
    error!("st_size: {}", st_size);

    let statbuf = statbuf as *mut KernelStat;
    axhal::arch::enable_sum();
    unsafe {
        *statbuf = KernelStat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            st_uid: 1000,
            st_gid: 1000,
            st_size: st_size,
            st_blocks: metadata.blocks() as _,
            st_blksize: 512,
            ..Default::default()
        };
    }
    axhal::arch::disable_sum();
    0
}

fn linux_syscall_mmap(args: SyscallArgs) -> usize {
    let [va, len, prot, flags, fd, offset] = args;
    assert!(is_aligned_4k(va));
    error!("###### mmap!!! {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}", va, len, prot, flags, fd, offset);

    mmap::mmap(va, len, prot, flags, fd, offset).unwrap()
}

const UTS_LEN: usize = 64;

#[repr(C)]
struct utsname {
    sysname: [u8; UTS_LEN + 1],
    nodename: [u8; UTS_LEN + 1],
    release: [u8; UTS_LEN + 1],
    version: [u8; UTS_LEN + 1],
    machine: [u8; UTS_LEN + 1],
    domainname: [u8; UTS_LEN + 1],
}

fn linux_syscall_uname(args: SyscallArgs) -> usize {
    let ptr = args[0];
    info!("uname: {:#x}", ptr);

    let uname = unsafe { (ptr as *mut utsname).as_mut().unwrap() };

    init_bytes_from_str(&mut uname.sysname[..], "Linux");
    init_bytes_from_str(&mut uname.nodename[..], "host");
    init_bytes_from_str(&mut uname.domainname[..], "(none)");
    init_bytes_from_str(&mut uname.release[..], "5.9.0-rc4+");
    init_bytes_from_str(&mut uname.version[..], "#1337 SMP Fri Mar 4 09:36:42 CST 2022");
    init_bytes_from_str(&mut uname.machine[..], "riscv64");

    return 0;
}

fn init_bytes_from_str(dst: &mut [u8], src: &str) {
    let src = src.as_bytes();
    let (left, right) = dst.split_at_mut(src.len());
    axhal::arch::enable_sum();
    left.copy_from_slice(src);
    right.fill(0);
    axhal::arch::disable_sum();
}

fn linux_syscall_brk(args: SyscallArgs) -> usize {
    let va = align_up_4k(args[0]);
    mmap::set_brk(va)
}

fn linux_syscall_munmap(args: SyscallArgs) -> usize {
    let [va, len, ..] = args;
    debug!("munmap!!! {:#x} {:#x}", va, len);
    unimplemented!();
    //return 0;
}

fn linux_syscall_exit(args: SyscallArgs) -> usize {
    let ret = args[0] as i32;
    debug!("exit ...{}", ret);
    task::exit(ret);
}

fn linux_syscall_exit_group(_tf: SyscallArgs) -> usize {
    debug!("exit_group!");
    return 0;
}

pub fn init() {
}
