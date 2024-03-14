use lazy_init::LazyInit;
use scheduler::BaseScheduler;
use alloc::sync::Arc;
use task::CurrentTask;
//use task::{CurrentTask, TaskState};
/*
use alloc::collections::VecDeque;

use crate::{AxTaskRef, Scheduler, TaskInner, WaitQueue};
*/
use spinlock::SpinNoIrq;
use task::TaskRef;
use core::sync::atomic::Ordering;
use mm::switch_mm;

cfg_if::cfg_if! {
    if #[cfg(feature = "sched_rr")] {
        const MAX_TIME_SLICE: usize = 5;
        type Scheduler = scheduler::RRScheduler<TaskRef, MAX_TIME_SLICE>;
    } else if #[cfg(feature = "sched_cfs")] {
        type SchedItem = scheduler::CFSTask<TaskRef>;
        type Scheduler = scheduler::CFScheduler<TaskRef>;
    } else {
        // If no scheduler features are set, use FIFO as the default.
        type Scheduler = scheduler::FifoScheduler<TaskRef>;
    }
}

// TODO: per-CPU
pub(crate) static RUN_QUEUE: LazyInit<SpinNoIrq<AxRunQueue>> = LazyInit::new();

/*
// TODO: per-CPU
static EXITED_TASKS: SpinNoIrq<VecDeque<AxTaskRef>> = SpinNoIrq::new(VecDeque::new());

static WAIT_FOR_EXIT: WaitQueue = WaitQueue::new();

#[percpu::def_percpu]
static IDLE_TASK: LazyInit<AxTaskRef> = LazyInit::new();
*/

pub struct AxRunQueue {
    scheduler: Scheduler,
}

impl AxRunQueue {
    pub fn new() -> SpinNoIrq<Self> {
        let scheduler = Scheduler::new();
        SpinNoIrq::new(Self { scheduler })
    }

    pub fn activate_task(&mut self, task: TaskRef) {
        self.add_task(task)
    }

    pub fn add_task(&mut self, task: TaskRef) {
        debug!("task spawn: {}", task.pid());
        //assert!(task.is_ready());
        let item = Arc::new(SchedItem::new(task));
        self.scheduler.add_task(item);
    }

    pub fn scheduler_timer_tick(&mut self) {
        let curr = task::current();
        if self.scheduler.task_tick(
            &Arc::new(SchedItem::new(curr.as_task_ref().clone()))
        ) {
            #[cfg(feature = "preempt")]
            curr.set_preempt_pending(true);
        }
    }

/*
    pub fn yield_current(&mut self) {
        let curr = crate::current();
        trace!("task yield: {}", curr.id_name());
        assert!(curr.is_running());
        self.resched(false);
    }

    pub fn set_current_priority(&mut self, prio: isize) -> bool {
        self.scheduler
            .set_priority(crate::current().as_task_ref(), prio)
    }

    #[cfg(feature = "preempt")]
    pub fn preempt_resched(&mut self) {
        let curr = crate::current();
        assert!(curr.is_running());

        // When we get the mutable reference of the run queue, we must
        // have held the `SpinNoIrq` lock with both IRQs and preemption
        // disabled. So we need to set `current_disable_count` to 1 in
        // `can_preempt()` to obtain the preemption permission before
        //  locking the run queue.
        let can_preempt = curr.can_preempt(1);

        debug!(
            "current task is to be preempted: {}, allow={}",
            curr.id_name(),
            can_preempt
        );
        if can_preempt {
            self.resched(true);
        } else {
            curr.set_preempt_pending(true);
        }
    }

    pub fn exit_current(&mut self, exit_code: i32) -> ! {
        let curr = crate::current();
        debug!("task exit: {}, exit_code={}", curr.id_name(), exit_code);
        assert!(curr.is_running());
        assert!(!curr.is_idle());
        if curr.is_init() {
            EXITED_TASKS.lock().clear();
            axhal::misc::terminate();
        } else {
            curr.set_state(TaskState::Exited);
            curr.notify_exit(exit_code, self);
            EXITED_TASKS.lock().push_back(curr.clone());
            WAIT_FOR_EXIT.notify_one_locked(false, self);
            self.resched(false);
        }
        unreachable!("task exited!");
    }

    pub fn block_current<F>(&mut self, wait_queue_push: F)
    where
        F: FnOnce(AxTaskRef),
    {
        let curr = crate::current();
        debug!("task block: {}", curr.id_name());
        assert!(curr.is_running());
        assert!(!curr.is_idle());

        // we must not block current task with preemption disabled.
        #[cfg(feature = "preempt")]
        assert!(curr.can_preempt(1));

        curr.set_state(TaskState::Blocked);
        wait_queue_push(curr.clone());
        self.resched(false);
    }

    pub fn unblock_task(&mut self, task: AxTaskRef, resched: bool) {
        debug!("task unblock: {}", task.id_name());
        if task.is_blocked() {
            task.set_state(TaskState::Ready);
            self.scheduler.add_task(task); // TODO: priority
            if resched {
                #[cfg(feature = "preempt")]
                crate::current().set_preempt_pending(true);
            }
        }
    }

    #[cfg(feature = "irq")]
    pub fn sleep_until(&mut self, deadline: axhal::time::TimeValue) {
        let curr = crate::current();
        debug!("task sleep: {}, deadline={:?}", curr.id_name(), deadline);
        assert!(curr.is_running());
        assert!(!curr.is_idle());

        let now = axhal::time::current_time();
        if now < deadline {
            crate::timers::set_alarm_wakeup(deadline, curr.clone());
            curr.set_state(TaskState::Blocked);
            self.resched(false);
        }
    }
    */
}

impl AxRunQueue {
    /// Common reschedule subroutine. If `preempt`, keep current task's time
    /// slice, otherwise reset it.
    pub fn resched(&mut self, preempt: bool) {
        let prev = crate::current();
        self.scheduler.put_prev_task(Arc::new(SchedItem::new(prev.clone())), preempt);
        let next = self.scheduler.pick_next_task().unwrap();
        self.switch_to(prev, next.inner().clone());
    }

    fn switch_to(&mut self, prev_task: CurrentTask, next_task: TaskRef) {
        trace!(
            "context switch: {} -> {}",
            prev_task.pid(),
            next_task.pid()
        );
        #[cfg(feature = "preempt")]
        next_task.set_preempt_pending(false);
        //next_task.set_state(TaskState::Running);
        if prev_task.ptr_eq(&next_task) {
            return;
        }

        // Switch mm from prev to next
        // kernel ->   user   switch + mmdrop_lazy_tlb() active
        //   user ->   user   switch
        // kernel -> kernel   lazy + transfer active
        //   user -> kernel   lazy + mmgrab_lazy_tlb() active
        match next_task.try_mm() {
            Some(ref next_mm) => {
                switch_mm(
                    prev_task.active_mm_id.load(Ordering::SeqCst),
                    next_mm.clone()
                );
            },
            None => {
                error!("###### {} {};",
                   prev_task.active_mm_id.load(Ordering::SeqCst),
                   next_task.active_mm_id.load(Ordering::SeqCst));

                next_task.active_mm_id.store(
                    prev_task.active_mm_id.load(Ordering::SeqCst),
                    Ordering::SeqCst
                );
            }
        }
        if prev_task.try_mm().is_none() {
            prev_task.active_mm_id.store(0, Ordering::SeqCst);
        }

        unsafe {
            let prev_ctx_ptr = prev_task.ctx_mut_ptr();
            let next_ctx_ptr = next_task.ctx_mut_ptr();

            // The strong reference count of `prev_task` will be decremented by 1,
            // but won't be dropped until `gc_entry()` is called.
            assert!(Arc::strong_count(&prev_task) > 1);
            assert!(Arc::strong_count(&next_task) >= 1);

            CurrentTask::set_current(prev_task, next_task);
            (*prev_ctx_ptr).switch_to(&*next_ctx_ptr);
        }
    }
}

/*

fn gc_entry() {
    loop {
        // Drop all exited tasks and recycle resources.
        let n = EXITED_TASKS.lock().len();
        for _ in 0..n {
            // Do not do the slow drops in the critical section.
            let task = EXITED_TASKS.lock().pop_front();
            if let Some(task) = task {
                if Arc::strong_count(&task) == 1 {
                    // If I'm the last holder of the task, drop it immediately.
                    drop(task);
                } else {
                    // Otherwise (e.g, `switch_to` is not compeleted, held by the
                    // joiner, etc), push it back and wait for them to drop first.
                    EXITED_TASKS.lock().push_back(task);
                }
            }
        }
        WAIT_FOR_EXIT.wait();
    }
}
*/

/*
pub(crate) fn init_secondary() {
    let idle_task = TaskInner::new_init("idle".into());
    idle_task.set_state(TaskState::Running);
    IDLE_TASK.with_current(|i| i.init_by(idle_task.clone()));
    unsafe { CurrentTask::init_current(idle_task) }
}
*/
