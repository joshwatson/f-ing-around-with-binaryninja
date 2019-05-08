#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void simple_for_loop()
{
    for (int i = 0; i < 80; i++)
    {
        printf("*");
        fflush(stdout);
        sleep(1);
    }
}

void for_with_break()
{
    for (int i = 0; i < 35; i++)
    {
        if (i == 24)
        {
            printf("i is %d\n", i);
            break;
        }
    }

    printf("After the for loop");
}

int main(int argc, char** argv)
{
    simple_for_loop();
    for_with_break();

    return 0;
}