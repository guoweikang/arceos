use core::arch::global_asm;

use aarch64_cpu::registers::{ESR_EL1, FAR_EL1};
use tock_registers::interfaces::Readable;
use crate::trap::SyscallArgs;

use super::TrapFrame;

global_asm!(include_str!("trap.S"));

#[repr(u8)]
#[derive(Debug)]
#[allow(dead_code)]
enum TrapKind {
    Synchronous = 0,
    Irq = 1,
    Fiq = 2,
    SError = 3,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(dead_code)]
enum TrapSource {
    CurrentSpEl0 = 0,
    CurrentSpElx = 1,
    LowerAArch64 = 2,
    LowerAArch32 = 3,
}

#[no_mangle]
fn invalid_exception(tf: &TrapFrame, kind: TrapKind, source: TrapSource) {
    panic!(
        "Invalid exception {:?} from {:?}:\n{:#x?}",
        kind, source, tf
    );
}

#[no_mangle]
fn handle_sync_exception(tf: &mut TrapFrame) {
    let esr = ESR_EL1.extract();
    match esr.read_as_enum(ESR_EL1::EC) {
        Some(ESR_EL1::EC::Value::Brk64) => {
            let iss = esr.read(ESR_EL1::ISS);
            debug!("BRK #{:#x} @ {:#x} ", iss, tf.elr);
            tf.elr += 4;
        }
        Some(ESR_EL1::EC::Value::SVC64) => {
            warn!("No supervisor call is supported currently!");
        }
        Some(ESR_EL1::EC::Value::DataAbortLowerEL)
        | Some(ESR_EL1::EC::Value::InstrAbortLowerEL) => {
            let iss = esr.read(ESR_EL1::ISS);
            warn!(
                "EL0 Page Fault @ {:#x}, FAR={:#x}, ISS={:#x}",
                tf.elr,
                FAR_EL1.get(),
                iss
            );
        }
        Some(ESR_EL1::EC::Value::DataAbortCurrentEL)
        | Some(ESR_EL1::EC::Value::InstrAbortCurrentEL) => {
            let iss = esr.read(ESR_EL1::ISS);
            info!(
                "EL1 Page Fault @ {:#x}, FAR={:#x}, ISS={:#x}:\n{:#x?}",
                tf.elr,
                FAR_EL1.get(),
                iss,
                tf,
            );
            crate::trap::handle_page_fault(FAR_EL1.get() as usize, 0);
        }
        _ => {
            panic!(
                "Unhandled synchronous exception @ {:#x}: ESR={:#x} (EC {:#08b}, ISS {:#x})",
                tf.elr,
                esr.get(),
                esr.read(ESR_EL1::EC),
                esr.read(ESR_EL1::ISS),
            );
        }
    }
}

#[no_mangle]
fn handle_irq_exception(_tf: &TrapFrame) {
    crate::trap::handle_irq_extern(0)
}

pub fn syscall_args(tf: &TrapFrame) -> SyscallArgs {
    [
        tf.r[0], tf.r[1], tf.r[2],
        tf.r[3], tf.r[4], tf.r[5],
    ].map(|x| x as usize)
}

pub fn syscall<F>(tf: &mut TrapFrame, do_syscall: F)
where
    F: FnOnce(SyscallArgs, usize) -> usize
{
    error!("Syscall: {:#x}", tf.r[8]);
    let args = syscall_args(tf);
    tf.r[0] = do_syscall(args, tf.r[8] as usize) as u64;
    //tf.sepc += 4;
}
