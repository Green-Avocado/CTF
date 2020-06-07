# stacking

Strings can live in different sections of the memory.

## Solution

We're given a binary and the description suggests that we'll have to look at the stack to find the flag.

We can analyse the program using Radare2.

As this is not a binary exploitation challenge, I don't list functions right away as it's more likely to be a hidden password, given the category.
Instead, let's go straight to disassembling ```main```.

```asm
[greenavocado@greenavocado-pc stacking]$ r2 stacking
 -- Your endian swaps
[0x00000600]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000600]> pdf @ main
            ; DATA XREF from entry0 @ 0x61d
┌ 32: int main (int argc, char **argv);
│           ; var char **var_10h @ rbp-0x10
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x0000070a      55             push rbp
│           0x0000070b      4889e5         mov rbp, rsp
│           0x0000070e      4883ec10       sub rsp, 0x10
│           0x00000712      897dfc         mov dword [var_4h], edi     ; argc
│           0x00000715      488975f0       mov qword [var_10h], rsi    ; argv
│           0x00000719      b800000000     mov eax, 0
│           0x0000071e      e807000000     call sym.func
│           0x00000723      b800000000     mov eax, 0
│           0x00000728      c9             leave
└           0x00000729      c3             ret
[0x00000600]>
```

We can see that the ```main``` function doesn't really do much, but it does call another function at ```sym.func```.
Let's disassemble that as well.

```asm
[0x00000600]> pdf @ sym.func
            ; CALL XREF from main @ 0x71e
┌ 305: sym.func ();
│           ; var int64_t var_48h @ rbp-0x48
│           ; var int64_t var_4ch @ rbp-0x4c
│           ; var signed int64_t var_44h @ rbp-0x44
│           ; var int64_t var_17h @ rbp-0x17
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_19h @ rbp-0x19
│           ; var int64_t var_1ah @ rbp-0x1a
│           ; var int64_t var_1bh @ rbp-0x1b
│           ; var int64_t var_1ch @ rbp-0x1c
│           ; var int64_t var_1dh @ rbp-0x1d
│           ; var int64_t var_1eh @ rbp-0x1e
│           ; var int64_t var_1fh @ rbp-0x1f
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_21h @ rbp-0x21
│           ; var int64_t var_22h @ rbp-0x22
│           ; var int64_t var_23h @ rbp-0x23
│           ; var int64_t var_24h @ rbp-0x24
│           ; var int64_t var_25h @ rbp-0x25
│           ; var int64_t var_26h @ rbp-0x26
│           ; var int64_t var_27h @ rbp-0x27
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_29h @ rbp-0x29
│           ; var int64_t var_2ah @ rbp-0x2a
│           ; var int64_t var_2bh @ rbp-0x2b
│           ; var int64_t var_2ch @ rbp-0x2c
│           ; var int64_t var_2dh @ rbp-0x2d
│           ; var int64_t var_2eh @ rbp-0x2e
│           ; var int64_t var_2fh @ rbp-0x2f
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_31h @ rbp-0x31
│           ; var int64_t var_32h @ rbp-0x32
│           ; var int64_t var_33h @ rbp-0x33
│           ; var int64_t var_34h @ rbp-0x34
│           ; var int64_t var_35h @ rbp-0x35
│           ; var int64_t var_36h @ rbp-0x36
│           ; var int64_t var_37h @ rbp-0x37
│           ; var int64_t var_38h @ rbp-0x38
│           ; var int64_t var_39h @ rbp-0x39
│           ; var int64_t var_3ah @ rbp-0x3a
│           ; var int64_t var_3bh @ rbp-0x3b
│           ; var int64_t var_3ch @ rbp-0x3c
│           ; var int64_t var_3dh @ rbp-0x3d
│           ; var int64_t var_3eh @ rbp-0x3e
│           ; var int64_t var_3fh @ rbp-0x3f
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t canary @ rbp-0x8
│           0x0000072a      55             push rbp
│           0x0000072b      4889e5         mov rbp, rsp
│           0x0000072e      4883ec50       sub rsp, 0x50
│           0x00000732      64488b042528.  mov rax, qword fs:[0x28]
│           0x0000073b      488945f8       mov qword [canary], rax
│           0x0000073f      31c0           xor eax, eax
│           0x00000741      c645c063       mov byte [var_40h], 0x63    ; 'c'
│           0x00000745      c645c161       mov byte [var_3fh], 0x61    ; 'a'
│           0x00000749      c645c273       mov byte [var_3eh], 0x73    ; 's'
│           0x0000074d      c645c374       mov byte [var_3dh], 0x74    ; 't'
│           0x00000751      c645c46f       mov byte [var_3ch], 0x6f    ; 'o'
│           0x00000755      c645c572       mov byte [var_3bh], 0x72    ; 'r'
│           0x00000759      c645c673       mov byte [var_3ah], 0x73    ; 's'
│           0x0000075d      c645c743       mov byte [var_39h], 0x43    ; 'C'
│           0x00000761      c645c854       mov byte [var_38h], 0x54    ; 'T'
│           0x00000765      c645c946       mov byte [var_37h], 0x46    ; 'F'
│           0x00000769      c645ca7b       mov byte [var_36h], 0x7b    ; '{'
│           0x0000076d      c645cb77       mov byte [var_35h], 0x77    ; 'w'
│           0x00000771      c645cc33       mov byte [var_34h], 0x33    ; '3'
│           0x00000775      c645cd6c       mov byte [var_33h], 0x6c    ; 'l'
│           0x00000779      c645ce63       mov byte [var_32h], 0x63    ; 'c'
│           0x0000077d      c645cf30       mov byte [var_31h], 0x30    ; '0'
│           0x00000781      c645d06d       mov byte [var_30h], 0x6d    ; 'm'
│           0x00000785      c645d133       mov byte [var_2fh], 0x33    ; '3'
│           0x00000789      c645d25f       mov byte [var_2eh], 0x5f    ; '_'
│           0x0000078d      c645d337       mov byte [var_2dh], 0x37    ; '7'
│           0x00000791      c645d430       mov byte [var_2ch], 0x30    ; '0'
│           0x00000795      c645d55f       mov byte [var_2bh], 0x5f    ; '_'
│           0x00000799      c645d672       mov byte [var_2ah], 0x72    ; 'r'
│           0x0000079d      c645d733       mov byte [var_29h], 0x33    ; '3'
│           0x000007a1      c645d876       mov byte [var_28h], 0x76    ; 'v'
│           0x000007a5      c645d933       mov byte [var_27h], 0x33    ; '3'
│           0x000007a9      c645da72       mov byte [var_26h], 0x72    ; 'r'
│           0x000007ad      c645db35       mov byte [var_25h], 0x35    ; '5'
│           0x000007b1      c645dc33       mov byte [var_24h], 0x33    ; '3'
│           0x000007b5      c645dd5f       mov byte [var_23h], 0x5f    ; '_'
│           0x000007b9      c645de33       mov byte [var_22h], 0x33    ; '3'
│           0x000007bd      c645df6e       mov byte [var_21h], 0x6e    ; 'n'
│           0x000007c1      c645e036       mov byte [var_20h], 0x36    ; '6'
│           0x000007c5      c645e131       mov byte [var_1fh], 0x31    ; '1'
│           0x000007c9      c645e26e       mov byte [var_1eh], 0x6e    ; 'n'
│           0x000007cd      c645e333       mov byte [var_1dh], 0x33    ; '3'
│           0x000007d1      c645e433       mov byte [var_1ch], 0x33    ; '3'
│           0x000007d5      c645e572       mov byte [var_1bh], 0x72    ; 'r'
│           0x000007d9      c645e631       mov byte [var_1ah], 0x31    ; '1'
│           0x000007dd      c645e76e       mov byte [var_19h], 0x6e    ; 'n'
│           0x000007e1      c645e836       mov byte [var_18h], 0x36    ; '6'
│           0x000007e5      c645e97d       mov byte [var_17h], 0x7d    ; '}'
│           0x000007e9      c745bc140000.  mov dword [var_44h], 0x14
│           0x000007f0      c745b4000000.  mov dword [var_4ch], 0
│       ┌─< 0x000007f7      eb0e           jmp 0x807
│       │   ; CODE XREF from sym.func @ 0x80d
│      ┌──> 0x000007f9      bf3d000000     mov edi, 0x3d               ; '=' ; int c
│      ╎│   0x000007fe      e8bdfdffff     call sym.imp.putchar        ; int putchar(int c)
│      ╎│   0x00000803      8345b401       add dword [var_4ch], 1
│      ╎│   ; CODE XREF from sym.func @ 0x7f7
│      ╎└─> 0x00000807      8b45b4         mov eax, dword [var_4ch]
│      ╎    0x0000080a      3b45bc         cmp eax, dword [var_44h]
│      └──< 0x0000080d      7cea           jl 0x7f9
│           0x0000080f      488d3de40000.  lea rdi, str.Where_s_the_flag ; 0x8fa ; "\nWhere's the flag?" ; const char *s
│           0x00000816      e8b5fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000081b      c745b8000000.  mov dword [var_48h], 0
│       ┌─< 0x00000822      eb0e           jmp 0x832
│       │   ; CODE XREF from sym.func @ 0x838
│      ┌──> 0x00000824      bf3d000000     mov edi, 0x3d               ; '=' ; int c
│      ╎│   0x00000829      e892fdffff     call sym.imp.putchar        ; int putchar(int c)
│      ╎│   0x0000082e      8345b801       add dword [var_48h], 1
│      ╎│   ; CODE XREF from sym.func @ 0x822
│      ╎└─> 0x00000832      8b45b8         mov eax, dword [var_48h]
│      ╎    0x00000835      3b45bc         cmp eax, dword [var_44h]
│      └──< 0x00000838      7cea           jl 0x824
│           0x0000083a      bf0a000000     mov edi, 0xa                ; int c
│           0x0000083f      e87cfdffff     call sym.imp.putchar        ; int putchar(int c)
│           0x00000844      90             nop
│           0x00000845      488b45f8       mov rax, qword [canary]
│           0x00000849      644833042528.  xor rax, qword fs:[0x28]
│       ┌─< 0x00000852      7405           je 0x859
│       │   0x00000854      e887fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from sym.func @ 0x852
│       └─> 0x00000859      c9             leave
└           0x0000085a      c3             ret
[0x00000600]>
```

One part in particular sticks out.

```asm
│           0x00000741      c645c063       mov byte [var_40h], 0x63    ; 'c'
│           0x00000745      c645c161       mov byte [var_3fh], 0x61    ; 'a'
│           0x00000749      c645c273       mov byte [var_3eh], 0x73    ; 's'
│           0x0000074d      c645c374       mov byte [var_3dh], 0x74    ; 't'
│           0x00000751      c645c46f       mov byte [var_3ch], 0x6f    ; 'o'
│           0x00000755      c645c572       mov byte [var_3bh], 0x72    ; 'r'
│           0x00000759      c645c673       mov byte [var_3ah], 0x73    ; 's'
│           0x0000075d      c645c743       mov byte [var_39h], 0x43    ; 'C'
│           0x00000761      c645c854       mov byte [var_38h], 0x54    ; 'T'
│           0x00000765      c645c946       mov byte [var_37h], 0x46    ; 'F'
│           0x00000769      c645ca7b       mov byte [var_36h], 0x7b    ; '{'
│           0x0000076d      c645cb77       mov byte [var_35h], 0x77    ; 'w'
│           0x00000771      c645cc33       mov byte [var_34h], 0x33    ; '3'
│           0x00000775      c645cd6c       mov byte [var_33h], 0x6c    ; 'l'
│           0x00000779      c645ce63       mov byte [var_32h], 0x63    ; 'c'
│           0x0000077d      c645cf30       mov byte [var_31h], 0x30    ; '0'
│           0x00000781      c645d06d       mov byte [var_30h], 0x6d    ; 'm'
│           0x00000785      c645d133       mov byte [var_2fh], 0x33    ; '3'
│           0x00000789      c645d25f       mov byte [var_2eh], 0x5f    ; '_'
│           0x0000078d      c645d337       mov byte [var_2dh], 0x37    ; '7'
│           0x00000791      c645d430       mov byte [var_2ch], 0x30    ; '0'
│           0x00000795      c645d55f       mov byte [var_2bh], 0x5f    ; '_'
│           0x00000799      c645d672       mov byte [var_2ah], 0x72    ; 'r'
│           0x0000079d      c645d733       mov byte [var_29h], 0x33    ; '3'
│           0x000007a1      c645d876       mov byte [var_28h], 0x76    ; 'v'
│           0x000007a5      c645d933       mov byte [var_27h], 0x33    ; '3'
│           0x000007a9      c645da72       mov byte [var_26h], 0x72    ; 'r'
│           0x000007ad      c645db35       mov byte [var_25h], 0x35    ; '5'
│           0x000007b1      c645dc33       mov byte [var_24h], 0x33    ; '3'
│           0x000007b5      c645dd5f       mov byte [var_23h], 0x5f    ; '_'
│           0x000007b9      c645de33       mov byte [var_22h], 0x33    ; '3'
│           0x000007bd      c645df6e       mov byte [var_21h], 0x6e    ; 'n'
│           0x000007c1      c645e036       mov byte [var_20h], 0x36    ; '6'
│           0x000007c5      c645e131       mov byte [var_1fh], 0x31    ; '1'
│           0x000007c9      c645e26e       mov byte [var_1eh], 0x6e    ; 'n'
│           0x000007cd      c645e333       mov byte [var_1dh], 0x33    ; '3'
│           0x000007d1      c645e433       mov byte [var_1ch], 0x33    ; '3'
│           0x000007d5      c645e572       mov byte [var_1bh], 0x72    ; 'r'
│           0x000007d9      c645e631       mov byte [var_1ah], 0x31    ; '1'
│           0x000007dd      c645e76e       mov byte [var_19h], 0x6e    ; 'n'
│           0x000007e1      c645e836       mov byte [var_18h], 0x36    ; '6'
│           0x000007e5      c645e97d       mov byte [var_17h], 0x7d    ; '}'
```

And there's our flag.

## Flag

```castorsCTF{w3lc0m3_70_r3v3r53_3n61n33r1n6}```

