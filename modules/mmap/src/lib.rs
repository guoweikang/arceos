#![no_std]

use axerrno::{LinuxError, LinuxResult};

pub fn mmap(
    va: usize, len: usize, prot: usize, flags: usize,
    fd: usize, offset: usize
) -> LinuxResult {
    /*
        let ft = self.filetable.lock();
        let file = if flags != 0 {
            ft.get_file(fd)
        } else {
            None
        };

        match self.mm {
            Some(ref mm) => {
                mm.lock().mmap(va, len, prot, flags, file, offset);
            },
            None => {
                panic!("NOT user process");
            }
        }
    */
    unimplemented!("mmap!");
}
