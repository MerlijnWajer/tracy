#define TRACY_REGS_NAME user_regs_struct /* pt_regs doesn't work */

#define TRACY_SYSCALL_OPSIZE 2

#define TRACY_SYSCALL_REGISTER orig_eax
#define TRACY_SYSCALL_N eax

#define TRACY_RETURN_CODE eax
#define TRACY_IP_REG eip

#define TRACY_STACK_POINTER esp

#define TRACY_ARG_0 ebx
#define TRACY_ARG_1 ecx
#define TRACY_ARG_2 edx
#define TRACY_ARG_3 esi
#define TRACY_ARG_4 edi
#define TRACY_ARG_5 ebp

#define TRACY_NR_MMAP __NR_mmap2

/* Register used to pass trampy code the tracer PID */
#define TRAMPY_PID_REG ebp
#define TRAMPY_PID_ARG a5

#define TRACY_ABI_COUNT 1

#define TRACY_ABI_X86 0

#define TRACY_ABI_NATIVE TRACY_ABI_X86

struct tracy_event;

int get_abi(struct tracy_event *s);

long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi);
long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val);
