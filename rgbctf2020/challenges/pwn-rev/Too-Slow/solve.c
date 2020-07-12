#include <stdio.h>

int main()
{
    unsigned long flag = 0x12297e12426e6f53;
    unsigned int counter = 0;
    unsigned long param_1 = 0x265d1d23;

    while (counter < 9) {
        *(unsigned int *)((long)&flag + (unsigned long)counter * 4) =
            *(unsigned int *)((long)&flag + (unsigned long)counter * 4) ^ param_1;
        counter = counter + 1;
    }

    printf("Your flag: rgbCTF{%36s}\n",&flag);

    return 0;
}

