#include <stdio.h>
#include <stdint.h>

// TODO: figure out why this isn't rendering correctly
int main(int argc, char** argv)
{
    int64_t a, b, c;

    printf("Enter a: ");
    scanf("%lld", &a);

    printf("Enter b: ");
    scanf("%lld", &b);

    printf("Enter c: ");
    scanf("%lld", &c);

    if (a > 0)
    {
        printf("a > 0\n");
    }
    else
    {
        printf("a <= 0\n");
    }

    if (b > 0 && c != 2)
    {
        printf("b > 0 and c != 2\n");
    }
    else 
    {
        if (b <= 0 && c != 2)
        {
            printf("b <= 0 and c != 2\n");
        }
        else
        {
            printf("c == 2, b is....whatever\n");
        }
    }


    return 0;
}