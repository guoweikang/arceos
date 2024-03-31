//! Trap handling.

use crate_interface::{call_interface, def_interface};
use crate::arch::TrapFrame;

pub const TRAPFRAME_SIZE: usize = core::mem::size_of::<TrapFrame>();
pub const STACK_ALIGN: usize = 16;

/// Trap handler interface.
///
/// This trait is defined with the [`#[def_interface]`][1] attribute. Users
/// should implement it with [`#[impl_interface]`][2] in any other crate.
///
/// [1]: crate_interface::def_interface
/// [2]: crate_interface::impl_interface
#[def_interface]
pub trait TrapHandler {
    /// Handles interrupt requests for the given IRQ number.
    fn handle_irq(irq_num: usize);
    fn handle_page_fault(badaddr: usize, cause: usize);
}

/// Call the external IRQ handler.
#[allow(dead_code)]
pub fn handle_irq_extern(irq_num: usize) {
    call_interface!(TrapHandler::handle_irq, irq_num);
}

/// Call page fault handler.
pub fn handle_page_fault(badaddr: usize, cause: usize) {
    call_interface!(TrapHandler::handle_page_fault, badaddr, cause);
}

#[def_interface]
pub trait SyscallHandler {
    fn handle_syscall(tf: &mut TrapFrame);
}

/// Call the syscall handler.
#[allow(dead_code)]
pub fn handle_linux_syscall(tf: &mut TrapFrame) {
    call_interface!(SyscallHandler::handle_syscall, tf);
}
