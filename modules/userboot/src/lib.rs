#![no_std]
#![feature(result_option_inspect)]

#[macro_use]
extern crate log;
extern crate alloc;
use axerrno::{LinuxError, LinuxResult};
use fork::{user_mode_thread, CloneFlags};

pub fn start() {
    error!("userboot::start ...");

    task::init();
    run_queue::init();

    let all_devices = axdriver::init_drivers();
    let main_fs = axmount::init_filesystems(all_devices.block);
    let root_dir = axmount::init_rootfs(main_fs);
    task::current().fs.lock().init(root_dir);
    rest_init();
}

fn rest_init() {
    error!("rest_init ...");
    let pid = user_mode_thread(
        || {
            kernel_init();
        },
        CloneFlags::CLONE_FS,
    );
    assert_eq!(pid, 1);

    /*
     * The boot idle thread must execute schedule()
     * at least once to get things moving:
     */
    schedule_preempt_disabled();
    /* Call into cpu_idle with preempt disabled */
    cpu_startup_entry(/* CPUHP_ONLINE */);
}

fn schedule_preempt_disabled() {
    let task = task::current();
    let rq = run_queue::task_rq(&task);
    rq.lock().resched(false);
    unimplemented!("schedule_preempt_disabled()");
}

fn cpu_startup_entry() {
    unimplemented!("do idle()");
}

/// Prepare for entering first user app.
fn kernel_init() {
    try_to_run_init_process("/sbin/init").expect("No working init found.");
}

fn try_to_run_init_process(init_filename: &str) -> LinuxResult {
    run_init_process(init_filename).inspect_err(|e| {
        if e != &LinuxError::ENOENT {
            error!(
                "Starting init: {} exists but couldn't execute it (error {})",
                init_filename, e
            );
        }
    })
}

fn run_init_process(init_filename: &str) -> LinuxResult {
    error!("run_init_process...");
    exec::kernel_execve(init_filename)
}
