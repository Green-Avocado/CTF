# two-sum

## Challenge

The challenge description is as follows:

> Can you solve this?
> What two positive numbers can make this possible: n1 > n1 + n2 OR n2 > n1 + n2
> Enter them here nc saturn.picoctf.net 60993.

We are also provided with a C source code file.

The program reads two integers from stdin.
If both numbers are positive, but their addition results in an integer overflow, the program will print the flag.

## Solution

The program checks for an overflow by adding the two numbers and checking the sign of the result.
If both integers were positive and their sum is negative, it returns a code indicating an overflow.
Likewise if both integerse were negative and their sum is positive.

The greatest value that can be stored in a 32-bit `int` is 2147483647.
If we send this value as one number, and 1 as our second number, the result will be negative due to an integer overflow.

## Exploit

```sh
#/usr/bin/bash

echo "2147483647 1" | nc saturn.picoctf.net 50591
```

## Flag

```
picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_fe14e9e9}
```
