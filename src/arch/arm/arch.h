/*
 * See this for more info on ARM:
 * http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/ch09s02s02.html
 */
#define TRACY_REGS_NAME pt_regs

/* Unsure about some of the registers */
#define TRACY_SYSCALL_OPSIZE 8

/* ARM EABI puts System call number in r7 */
#define TRACY_SYSCALL_REGISTER ARM_r7
#define TRACY_SYSCALL_N ARM_r8

#define TRACY_RETURN_CODE ARM_r0

#define TRACY_IP_REG ARM_pc

#define TRACY_STACK_POINTER ARM_sp

/*
 * ARM does nasty stuff
 * http://www.arm.linux.org.uk/developer/patches/viewpatch.php?id=3105/4
 */
#define TRACY_ARG_0 ARM_r0
#define TRACY_ARG_1 ARM_r1
#define TRACY_ARG_2 ARM_r2
#define TRACY_ARG_3 ARM_r3
#define TRACY_ARG_4 ARM_r4
#define TRACY_ARG_5 ARM_r5

#define TRACY_NR_MMAP __NR_mmap2

/* Register used to pass trampy code the tracer PID */
#define TRAMPY_PID_REG ARM_r4
#define TRAMPY_PID_ARG a4


/* TODO: OABI */
#define TRACY_ABI_COUNT 2

#define TRACY_ABI_EABI 0
#define TRACY_ABI_OABI 1

#define TRACY_ABI_NATIVE TRACY_ABI_EABI

struct tracy_event;

int get_abi(struct tracy_event *s);
