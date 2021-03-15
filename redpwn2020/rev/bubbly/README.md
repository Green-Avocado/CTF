# bubbly

## Description

dns

It never ends

nc 2020.redpwnc.tf 31039

## Solution

We're given a binary which, when decompiled with Ghidra, produces the following functions:

```c
int main(void)

{
    uint32_t i;
    int unused;
    _Bool pass;

    setbuf(stdout,(char *)0x0);
    setbuf(stdin,(char *)0x0);
    setbuf(stderr,(char *)0x0);
    puts("I hate my data structures class! Why can\'t I just sort by hand?");
    pass = false;
    while( true ) {
        __isoc99_scanf(&DAT_00102058);
        if (8 < i) break;
        nums[i] = nums[i] ^ nums[i + 1];
        nums[i + 1] = nums[i + 1] ^ nums[i];
        nums[i] = nums[i] ^ nums[i + 1];
        pass = check();
    }
    if (pass == false) {
        puts("Try again!");
    }
    else {
        puts("Well done!");
        print_flag();
    }
    return 0;
}
```

```c
_Bool check(void)

    {
    uint32_t i;
    _Bool pass;
    
    i = 0;
    while( true ) {
        if (8 < i) {
            return true;
        }
        if (nums[i + 1] < nums[i]) break;
        i = i + 1;
    }
    return false;
}
```

```c
void print_flag(void)

{
    int unused;

    system("cat flag.txt");
    return;
}
```

The program contains an array of 10 integers which need to be sorted by the user in order to have the flag printed.
The values of these integers can be easily determined by printing them while debugging using GDB.
They are as follows:

```[1, 10, 3, 2, 5, 9, 8, 7, 4, 6]```

As we can see from the `main` function, the program takes the lesser index of a pair as user input and swaps the element at that index with the element with an index of 1 greater than that indicated by the user.

If the user enters an index greater than 8, the sorting phase finishes and the program attempts to verify that the list is in ascending order, in which case, it prints the flag.

The solution to this is quite simple, as the user can sort the array by hand and manually input the numbers, or a generic bubble sort script can be used, where the required numbers are recorded and piped into the program.

## Script

This python script is a generic bubbly sort algorithm with the original array hard-coded in.
A slight modification has been made where the lesser index of the pair is being recorded during each swap so it can be printed at the end.

```py
#!/usr/bin/python

def notSorted(arr):
    for n in range(len(arr)-1):
        if arr[n] > arr[n+1]:
            return True

    return False

nums = [1, 10, 3, 2, 5, 9, 8, 7, 4, 6]
sequence = ''

while notSorted(nums):
    for n in range(len(nums)-1):
        if nums[n] > nums[n+1]:
            sequence += str(n) + ' '
            temp = nums[n]
            nums[n] = nums[n+1]
            nums[n+1] = temp

print(sequence + '9')
```

The above script will print the following sequence:

```
1 2 3 4 5 6 7 8 1 4 5 6 7 4 5 6 4 5 3 9
```

This shell script simply runs the python script and pipes the output into the challenge program through netcat.

```sh
#!/bin/bash

python solver.py | nc 2020.redpwnc.tf 31039
```

## Flag

```flag{4ft3r_y0u_put_u54c0_0n_y0ur_c011ege_4pp5_y0u_5t1ll_h4ve_t0_d0_th15_57uff}```

