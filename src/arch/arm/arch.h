#define ARCH_ABI_COUNT 2

#define TRACY_ABI_EABI 0
#define TRACY_ABI_OABI 1

#define TRACY_ABI_NATIVE TRACY_ABI_EABI

struct tracy_event;

int get_abi(struct tracy_event *s);
