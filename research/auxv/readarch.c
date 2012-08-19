#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    char* file = malloc(sizeof(char)*1024);
    sprintf(file, "/proc/%s/auxv", argv[1]);
    printf("Filename: %s\n", file);
    FILE *f = fopen(file, "r");
    long *buf = malloc(1024*sizeof(char));
    printf("Read: %ld bytes\n", fread(buf, 4, 1000, f));

    while (!(buf[0] ==0 && buf[1] == 0)) {
        printf("%ld\n", buf[0]);
        printf("%ld\n", (long)buf);
        if (buf[0] == 15)
            printf("Arch: %s\n", (char*)buf[1]);
        buf+=2;
    }
    fclose(f);
    return 0;
}
