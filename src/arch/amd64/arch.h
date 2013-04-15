#define TRACY_REGS_NAME user_regs_struct
/* pt_regs doesn't work - user_regs_struct has more fields */

#define TRACY_SYSCALL_OPSIZE 2

#define TRACY_SYSCALL_REGISTER orig_rax
#define TRACY_SYSCALL_N rax

#define TRACY_RETURN_CODE rax
#define TRACY_IP_REG rip

#define TRACY_STACK_POINTER rsp

#define TRACY_NR_MMAP __NR_mmap

/* Register used to pass trampy code the tracer PID */
#define TRAMPY_PID_REG r8
#define TRAMPY_PID_ARG a4

/*
 * TODO:
 * - Implement x32 in arch/amd64/arch.c
 */
#define TRACY_ABI_COUNT 3

#define TRACY_ABI_AMD64 0
#define TRACY_ABI_X86 1

#define TRACY_ABI_NATIVE TRACY_ABI_AMD64


struct tracy_event;

int get_abi(struct tracy_event *s);
long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi);
long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val);
