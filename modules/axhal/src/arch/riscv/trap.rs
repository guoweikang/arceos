use riscv::register::scause::{self, Exception as E, Trap};
use riscv::register::stval;

use crate::trap::TRAPFRAME_SIZE;
use super::TrapFrame;

include_asm_marcos!();

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const TRAPFRAME_SIZE,
);

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}
