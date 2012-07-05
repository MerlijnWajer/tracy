#include <unistd.h>
#include <stdio.h>

int main()
{
    int ticktock = 1;

    while (1) {
        if (ticktock) {
            puts("Tick");
        } else {
            puts("Tock");
        }
        sleep(1);
        ticktock = !ticktock;
    }

    return 0;
}

