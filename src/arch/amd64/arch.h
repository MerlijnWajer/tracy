/*
 * TODO:
 * - Implement x32
 */

#define ARCH_ABI_COUNT 3

#define TRACY_ABI_AMD64 0
#define TRACY_ABI_X86 1
#define TRACY_ABI_X32 2

#define TRACY_ABI_NATIVE TRACY_ABI_AMD64


struct tracy_event;

int get_abi(struct tracy_event *s);
