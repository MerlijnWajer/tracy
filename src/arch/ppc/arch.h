#define TRACY_REGS_NAME pt_regs

#define TRACY_SYSCALL_OPSIZE 4

#define TRACY_SYSCALL_REGISTER gpr[0]
#define TRACY_SYSCALL_N orig_gpr3 

#define TRACY_RETURN_CODE result

#define TRACY_IP_REG link 

#define TRACY_STACK_POINTER gpr[1]

#define TRACY_NR_MMAP __NR_mmap2

/* Register used to pass trampy code the tracer PID */
#define TRAMPY_PID_REG gpr[9] /*TODO :fix this*/
#define TRAMPY_PID_ARG a4


#define TRACY_ABI_COUNT 1

#define TRACY_ABI_PPC 0

#define TRACY_ABI_NATIVE TRACY_ABI_PPC

struct tracy_event;

int get_abi(struct tracy_event *s);
long get_reg(struct TRACY_REGS_NAME *r, int reg, int abi);
long set_reg(struct TRACY_REGS_NAME *r, int reg, int abi, long val);
