use riscv::register::scause::{self, Exception as E, Trap};
use riscv::register::stval;

use crate::trap::TRAPFRAME_SIZE;
use super::TrapFrame;
use crate::trap::SyscallArgs;

include_asm_marcos!();

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const TRAPFRAME_SIZE,
);

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

#[no_mangle]
fn riscv_trap_handler(tf: &mut TrapFrame, _from_user: bool) {
    let scause = scause::read();
    match scause.cause() {
        Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
        #[cfg(feature = "monolithic")]
        Trap::Exception(E::UserEnvCall) => crate::trap::handle_linux_syscall(tf),
        Trap::Exception(E::InstructionPageFault) => {
            crate::trap::handle_page_fault(stval::read(), 0);
        },
        Trap::Exception(E::LoadPageFault) => {
            crate::trap::handle_page_fault(stval::read(), 1);
        },
        Trap::Exception(E::StorePageFault) => {
            crate::trap::handle_page_fault(stval::read(), 2);
        },
        Trap::Interrupt(_) => crate::trap::handle_irq_extern(scause.bits()),
        _ => {
            panic!(
                "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                scause.cause(),
                tf.sepc,
                tf
            );
        }
    }
}

pub fn syscall_args(tf: &TrapFrame) -> SyscallArgs {
    [
        tf.regs.a0, tf.regs.a1, tf.regs.a2,
        tf.regs.a3, tf.regs.a4, tf.regs.a5,
    ]
}

pub fn syscall<F>(tf: &mut TrapFrame, do_syscall: F)
where
    F: FnOnce(SyscallArgs, usize) -> usize
{
    error!("Syscall: {:#x}", tf.regs.a7);
    let args = syscall_args(tf);
    tf.regs.a0 = do_syscall(args, tf.regs.a7);
}
