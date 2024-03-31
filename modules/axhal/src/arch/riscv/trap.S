.section .text
.balign 4
.global ret_from_fork
ret_from_fork:
    mv sp, a0
    addi    t0, sp, {trapframe_size}    // put supervisor sp to scratch
    csrw    sscratch, t0
    RESTORE_REGS 1
    sret
