#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use fork::{user_mode_thread, CloneFlags};

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
        ret_from_fork();
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
    unimplemented!("userboot::kernel_init");
}

/// Return to userland from kernel.
fn ret_from_fork() {
    unimplemented!("ret_from_fork");
}
