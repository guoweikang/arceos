#![no_std]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

pub type Pid = usize;

static NEXT_PID: AtomicUsize = AtomicUsize::new(0);

pub struct TaskStruct {
    pid:    Pid,
    tgid:   Pid,
}

impl TaskStruct {
    pub fn new() -> Self {
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        error!("pid {}", pid);
        Self {
            pid: pid,
            tgid: pid,
        }
    }

    pub fn dup_task_struct(&self) -> Arc<Self> {
        error!("dup_task_struct ...");
        Arc::new(Self::new())
    }

    pub fn get_task_pid(&self) -> Pid {
        self.pid
    }
}

/// The reference type of a task.
pub type TaskRef = Arc<TaskStruct>;

/// A wrapper of [`TaskRef`] as the current task.
pub struct CurrentTask(ManuallyDrop<TaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const TaskStruct = axhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(TaskRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        error!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task);
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskStruct;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    unimplemented!("yield_now");
}

pub fn init() {
    error!("task::start ...");
    let init_task = Arc::new(TaskStruct::new());
    //init_task.set_state(TaskState::Running);
    unsafe { CurrentTask::init_current(init_task) }
}
