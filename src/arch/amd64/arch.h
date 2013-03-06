/*
 * Aantal ABIs; naam van abi + include...
 *
 */

#define ARCH_ABI_COUNT 2

#define TRACY_ABI_AMD64 0
#define TRACY_ABI_x86 1

#if 0
#define TRACY_ABI_x32 2
#endif

struct tracy_abi_syscall abi[ARCH_ABI_COUNT][] =
{
{
#include "syscall_amd64.h"
},
{
#include "syscall_x86.h"
}
};
