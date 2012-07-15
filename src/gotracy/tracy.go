package main

// #cgo CFLAGS: -D_GNU_SOURCE -D_POSIX_SOURCE -ggdb -pthread
// #cgo LDFLAGS: -rdynamic -pthread -L../tracy/ -ltracy
// #include "../tracy/tracy.h"
// #include <sched.h>
// #include <stdlib.h>
import "C"

import (
    "unsafe"
    "fmt"
    "os"
)

func main() {
    slice := os.Args[1:]
    fmt.Println(slice)
    chpp := make([]*C.char, len(slice)+1);
    for i, v := range slice {
        chpp[i] = C.CString(v)
        defer C.free(unsafe.Pointer(chpp[i]))
    }
    chpp[1] = (*C.char)(nil)

    var tracy = C.tracy_init(0)
    fmt.Println(tracy)
    C.fork_trace_exec(tracy, 1, &(chpp[0]))
    C.tracy_main(tracy)
    fmt.Println(tracy)
    C.tracy_free(tracy)
}
