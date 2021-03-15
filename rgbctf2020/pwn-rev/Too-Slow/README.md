# Too Slow

## Description

I've made this flag decryptor! It's super secure, but it runs a little slow.

~ungato#3536

## Solution

We're given a binary executable file, [a.out](./a.out).
The challenge description suggests that the program is designed to reveal the flag, but is too slow to be used practically.
When attempting to run the program, we are greeted with the following:

```
Flag Decryptor v1.0
Generating key...

```

At which point the program hangs.

By disassembling the program in Ghidra, we get the following `main` function:

```c
undefined8 main(void)

{
    uint uVar1;

    puts("Flag Decryptor v1.0");
    puts("Generating key...");
    uVar1 = getKey();
    win((ulong)uVar1);
    return 0;
}
```

By following these function calls, we find a `getKey` function and a `win` function.

I've renamed the local variables within Ghidra to improve readability.

Let's first analyse the `getKey` function:

```c
ulong getKey(void)

{
    uint a;
    uint b;

    a = 0;
    while (a < 0x265d1d23) {
        b = a;
        while (b != 1) {
            if ((b & 1) == 0) {
                b = (int)b / 2;
            }
            else {
                b = b * 3 + 1;
            }
        }
        a = a + 1;
    }
    return (ulong)a;
}
```

The function involves 2 local unsigned integers, which I have labeled `a` and `b`.
No arguments are taken, and the function typecasts `a` to an unsigned long integer and returns this value.

The value of `a` is set to `0` at the start of the function, and is incremented by `1` until `a` is equal to or greater than `0x265d1d23`.
Using this information, we know that the value of `a` when it is returned will be `0x265d1d23`.
The other variable, `b`, is used only to increase the runtime of the program, and can be safely ignored for the purpose of reversing this binary.

Now let's look at the `win` function:

```c
void win(uint param_1)

{
    long in_FS_OFFSET;
    uint counter;
    undefined8 flag;
    undefined8 junk0;
    undefined8 junk1;
    undefined8 junk2;
    undefined4 junk3;
    undefined junk4;
    long canary;

    canary = *(long *)(in_FS_OFFSET + 0x28);
    flag = 0x12297e12426e6f53;
    junk0 = 0x79242e48796e7141;
    junk1 = 0x49334216426e2e4d;
    junk2 = 0x473e425717696a7c;
    junk3 = 0x42642a41;
    junk4 = 0;
    counter = 0;
    while (counter < 9) {
        *(uint *)((long)&flag + (ulong)counter * 4) =
            *(uint *)((long)&flag + (ulong)counter * 4) ^ param_1;
        counter = counter + 1;
    }
    printf("Your flag: rgbCTF{%36s}\n",&flag);
    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    return;
}
```

The function takes the key as a parameter and uses it to decode the flag.

When first reading through the decompiled code, the variables labeled `junk0` through `junk4` seemed to exist to obfuscate the code.
However, this is not the case, as the values stored in these variables are part of the encoded flag.

Each part of the `while` loop handles a 32-bit (4-byte long) section of memory, starting at the address of `flag` and incrementing 4 bytes each iteration a total of 9 times.

The key, which is labeled here as `param_1` is typecasted to an unsigned integer to have an equal length compared to the section of memory being manipulated with each iteration.
This key is XORed with the memory stored in the stack, 4 bytes at a time.

At the end of the function, a string is printed from the stack with a length of 36 bytes, exactly equal to the length of memory manipulated in the `while` loop, and at the same location, as it uses the address of `flag` as the start of this string.

When writing the solve script, it is important that the "junk" variables are placed in the same location in the stack relative to the `flag` variable.

## Script

```c
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
```

The above script has been written to be identical to the original binary when in how the flag is produced, except that the useless second variable in `getKey` has been removed to allow the program to terminate in a reasonable amount of time.
This is by far NOT the most efficient way this program could have been written.

Running the above script will produce the flag in a relatively short amount of time.

## Alternative Solution

Alternatively, once the program is understood, the flag can be reverse engineered without recreating its functions.

It is worth noting that simply combining the hexadecimal values of the encoded flag as they appear in the decompiled code will result in a jumbled string due to the values being stored in little endian.
Instead, the values should be concatonated as follows:

```[flag][junk0][junk1][junk2][junk3]```

Likewise, the key should be repeated to match the length of the encoded flag.

```[key][key][key][key][key][key][key][key][key]```

This should result in the following two hexadecimal values:

```
flag: 0x42642a41473e425717696a7c49334216426e2e4d79242e48796e714112297e12426e6f53
 key: 0x265d1d23265d1d23265d1d23265d1d23265d1d23265d1d23265d1d23265d1d23265d1d23
```

XORing these values will result in a backwards flag due to endianness.
To fix this, the string can be reversed after being XORed, or the endianness of both the key and flag can be reversed prior to XORing.
Either operation will result in the same flag as that produced by the solve script.

## Flag

```rgbCTF{pr3d1ct4bl3_k3y_n33d5_no_w41t_cab79d}```

