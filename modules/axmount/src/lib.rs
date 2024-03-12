#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod dev;
mod fs;
mod mounts;

use axdriver::{prelude::*, AxDeviceContainer};
use alloc::{string::String, sync::Arc, vec::Vec};
pub use spinlock::{SpinNoIrq as Mutex};
use lazy_init::LazyInit;

/// Initializes filesystems by block devices.
pub fn init_filesystems(mut blk_devs: AxDeviceContainer<AxBlockDevice>) {
    error!("Initialize filesystems...");

    let dev = blk_devs.take_one().expect("No block device found!");
    info!("  use block device 0: {:?}", dev.device_name());
    let disk = self::dev::Disk::new(dev);

    cfg_if::cfg_if! {
        if #[cfg(feature = "myfs")] { // override the default filesystem
            let main_fs = fs::myfs::new_myfs(disk);
        } else if #[cfg(feature = "fatfs")] {
            static FAT_FS: LazyInit<Arc<fs::fatfs::FatFileSystem>> = LazyInit::new();
            FAT_FS.init_by(Arc::new(fs::fatfs::FatFileSystem::new(disk)));
            FAT_FS.init();
            let main_fs = FAT_FS.clone();
        }
    }

    task::current().fs.lock().init_rootfs(main_fs);
}
