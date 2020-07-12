#include <stdio.h>

void win(unsigned long param_1)
{
    unsigned long flag = 0x12297e12426e6f53;
    unsigned long junk0 = 0x79242e48796e7141;
    unsigned long junk1 = 0x49334216426e2e4d;
    unsigned long junk2 = 0x473e425717696a7c;
    unsigned long junk3 = 0x42642a41;
    unsigned long junk4 = 0;
    unsigned int counter = 0;

    while (counter < 9) {
        *(unsigned int *)((long)&flag + (unsigned long)counter * 4) =
            *(unsigned int *)((long)&flag + (unsigned long)counter * 4) ^ param_1;
        counter = counter + 1;
    }

    printf("Your flag: rgbCTF{%36s}\n",&flag);

    return;
}

unsigned long getKey()
{
    unsigned int a;

    a = 0;
    while (a < 0x265d1d23) {
        a = a + 1;
    }
    return (unsigned long)a;
}

int main()
{
    win(getKey());
    return 0;
}

