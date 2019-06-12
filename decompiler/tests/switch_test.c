#include <stdio.h>

int main(int argc, char** argv)
{
    switch(argc)
    {
    case 0:
        printf("No args?!\n");
        break;
    case 1:
        printf("1 arg\n");
    case 20:
        printf("fallthrough to 20\n");
        break;
    case 2:
        printf("2 args\n");
    default:
        printf("lots of args");
    }

    puts("Outside the switch statement");
    return 0;
}