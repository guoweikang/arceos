#![no_std]

use core::ops::Deref;
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{alloc::Layout, cell::UnsafeCell, fmt, ptr::NonNull};

#[macro_use]
extern crate log;
extern crate alloc;
use alloc::sync::Arc;

use axhal::arch::TaskContext as ThreadStruct;

pub type Pid = usize;

static NEXT_PID: AtomicUsize = AtomicUsize::new(0);

pub struct TaskStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl TaskStack {
    pub fn alloc(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 16).unwrap();
        Self {
            ptr: NonNull::new(unsafe { alloc::alloc::alloc(layout) }).unwrap(),
            layout,
        }
    }

    pub const fn top(&self) -> usize {
        unsafe { core::mem::transmute(self.ptr.as_ptr().add(self.layout.size())) }
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

pub struct TaskStruct {
    pid:    Pid,
    tgid:   Pid,

    pub entry: Option<*mut dyn FnOnce()>,

    /* CPU-specific state of this task: */
    pub thread: UnsafeCell<ThreadStruct>,
}

unsafe impl Send for TaskStruct {}
unsafe impl Sync for TaskStruct {}

impl TaskStruct {
    pub fn new() -> Self {
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        error!("pid {}", pid);
        Self {
            pid: pid,
            tgid: pid,

            entry: None,

            thread: UnsafeCell::new(ThreadStruct::new()),
        }
    }

    pub fn pid(&self) -> usize {
        self.pid
    }

    pub fn dup_task_struct(&self) -> Arc<Self> {
        error!("dup_task_struct ...");
        Arc::new(Self::new())
    }

    pub fn get_task_pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    pub const unsafe fn ctx_mut_ptr(&self) -> *mut ThreadStruct {
        self.thread.get()
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

    pub fn ptr_eq(&self, other: &TaskRef) -> bool {
        Arc::ptr_eq(&self, other)
    }

    pub(crate) unsafe fn init_current(init_task: TaskRef) {
        error!("CurrentTask::init_current...");
        let ptr = Arc::into_raw(init_task);
        axhal::cpu::set_current_task_ptr(ptr);
    }

    pub unsafe fn set_current(prev: Self, next: TaskRef) {
        error!("CurrentTask::set_current...");
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next);
        axhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskRef;
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
