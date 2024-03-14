struct TrapHandlerImpl;

#[crate_interface::impl_interface]
impl axhal::trap::TrapHandler for TrapHandlerImpl {
    fn handle_irq(_irq_num: usize) {
        let guard = kernel_guard::NoPreempt::new();
        axhal::irq::dispatch_irq(_irq_num);
        drop(guard); // rescheduling may occur when preemption is re-enabled.
    }
    fn handle_page_fault(badaddr: usize, _cause: usize) {
        mmap::faultin_page(badaddr);
    }
}
