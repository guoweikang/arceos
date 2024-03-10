#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::string::String;

use task::{current, TaskRef, Pid};

bitflags::bitflags! {
    /// clone flags
    pub struct CloneFlags: usize {
        /// signal mask to be sent at exit
        const CSIGNAL       = 0x000000ff;
        /// set if VM shared between processes
        const CLONE_VM      = 0x00000100;
        /// set if fs info shared between processes
        const CLONE_FS      = 0x00000200;
        /// set if open files shared between processes
        const CLONE_FILES   = 0x00000400;
        /// set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = 0x00000800;
        /// set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED= 0x00800000;
    }
}

struct KernelCloneArgs {
    flags: CloneFlags,
    name: String,
    exit_signal: u32,
    func: Option<*mut dyn FnOnce()>,
}

impl KernelCloneArgs {
    fn new(
        flags: CloneFlags, name: String, exit_signal: u32,
        func: Option<*mut dyn FnOnce()>
    ) -> Self {
        Self {
            flags,
            name,
            exit_signal,
            func,
        }
    }

    /// Do kernel_clone to clone a new kernel thread.
    fn perform(&self) -> Pid {
        error!("kernel_clone ...");
        let trace = !self.flags.contains(CloneFlags::CLONE_UNTRACED);
        assert!(!trace);

        let task = self.copy_process(None, trace);
        self.wake_up_new_task(&task);
        task.get_task_pid()
    }

    fn wake_up_new_task(&self, task: &TaskRef) {
        error!("wake_up_new_task");
    }

    fn copy_process(&self, _pid: Option<Pid>, trace: bool) -> TaskRef {
        error!("copy_process...");
        assert!(!trace);
        let mut task = current().dup_task_struct();
        self.copy_thread(&mut task);
        task
    }

    fn copy_thread(&self, task: &mut TaskRef) {
        error!("copy_thread ...");
        let task = Arc::get_mut(task);
        assert!(!task.is_none());
        error!("copy_thread!");
    }
}

/// Create a user thread
///
/// Invoke `f` to do some preparations before entering userland.
pub fn user_mode_thread<F>(f: F, flags: CloneFlags) -> Pid
where
    F: FnOnce() + 'static,
{
    error!("user_mode_thread ...");
    assert!((flags.bits() & CloneFlags::CSIGNAL.bits()) == 0);
    let f = Box::into_raw(Box::new(f));
    let args = KernelCloneArgs::new(flags | CloneFlags::CLONE_VM | CloneFlags::CLONE_UNTRACED, "".into(), 0, Some(f));
    args.perform()
}
