#define PRINT_PATHS 1
#define SKIP_IF_PROC_IS_UNAVAILABLE skip_if_unavailable("/proc/self/fd/")
#include "ioctl_seccomp.c"
