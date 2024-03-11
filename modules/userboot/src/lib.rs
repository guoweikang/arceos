#![no_std]
#![feature(result_option_inspect)]

#[macro_use]
extern crate log;
extern crate alloc;
use fork::{user_mode_thread, CloneFlags};
use axerrno::{LinuxResult, LinuxError};

pub fn start() {
    error!("userboot::start ...");

    task::init();
    run_queue::init();
    rest_init();
}

fn rest_init() {
    error!("rest_init ...");
    let pid = user_mode_thread(|| {
        kernel_init();
    }, CloneFlags::CLONE_FS);
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
    try_to_run_init_process("/sbin/init")
        .expect("No working init found.");
}

fn try_to_run_init_process(init_filename: &str) -> LinuxResult {
    run_init_process(init_filename)
        .inspect_err(|e| if e == &LinuxError::ENOENT {
            error!("Starting init: {} exists but couldn't execute it (error {})",
                   init_filename, e);
        })
}

fn run_init_process(init_filename: &str) -> LinuxResult {
    /*
    const char *const *p;

    argv_init[0] = init_filename;
    pr_info("Run %s as init process\n", init_filename);
    pr_debug("  with arguments:\n");
    for (p = argv_init; *p; p++)
        pr_debug("    %s\n", *p);
    pr_debug("  with environment:\n");
    for (p = envp_init; *p; p++)
        pr_debug("    %s\n", *p);
    return kernel_execve(init_filename, argv_init, envp_init);
    */
    unimplemented!("run_init_process!");
}
