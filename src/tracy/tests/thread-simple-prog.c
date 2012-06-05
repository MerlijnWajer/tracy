#include <stdlib.h>
#include <stdio.h>

#include <pthread.h>

void* thread_start() {
    printf("Hello\n");
    return EXIT_SUCCESS;
}

int main() {
    pthread_t t;
    int ret;

    ret = 0;

    pthread_create(&t, NULL, &thread_start, NULL);

    pthread_join(t, (void*)&ret);

    printf("Thread return value: %d\n", ret);

    return EXIT_SUCCESS;
}
