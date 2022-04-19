# Unboxing

## Challenge

Connecting to the challenge gives us a binary encoded as a hexadecimal string.

We must then send an input, also encoded as a hexadecimal string, which will cause the binary to output `"correct :)"`.

The `main` function looks like this:

```c
void main(void) {
    code *pcVar1;
    ulong extraout_RDX;
    int64_t iVar2;
    ulong uVar3;
    uint64_t uVar4;
    ulong s1;
    
    pcVar1 = sym.imp.mmap(0, 0x11001, 7, 0x22, 0xffffffff, 0);
    sym.imp.memcpy(pcVar1, obj.check, 0x11001);
    sym.imp.read(0, obj.input, 0x40);
    uVar3 = 0;
    sym.imp.memset(obj.output, 0, 0x100);
    (*pcVar1)();
    if (((((((*0x15113 == '\0') && (*0x1511b == '\0')) && (*0x15141 == '\0')) &&
          ((*0x1514c == '\0' && (*0x15157 == '\0')))) &&
         ((*0x15178 == '\0' && ((*0x1518d == '\0' && (*0x15190 == '\0')))))) &&
        ((*0x1519e == '\0' && (((*0x151ba == '\0' && (*0x151d6 == '\0')) && (*0x151f6 == '\0')))))) &&
       ((((((*0x15203 == '\0' && (*0x15217 == '\0')) &&
           ((*0x1521e == '\0' && ((*0x15233 == '\0' && (*0x15240 == '\0')))))) &&
          ((*0x15248 == '\0' &&
           (((((*0x1524c == '\0' && (*0x15279 == '\0')) && (*0x15285 == '\0')) &&
             ((*0x15286 == '\0' && (*0x152fa == '\0')))) &&
            (((*0x152fe == '\0' && ((*0x1530b == '\0' && (*0x15313 == '\0')))) &&
             ((*0x1532a == '\0' &&
              ((((*0x15348 == '\0' && (*0x15349 == '\0')) && (*0x1534b == '\0')) &&
               ((*0x15362 == '\0' && (*0x15374 == '\0')))))))))))))) &&
         (((((*0x153b5 == '\0' && ((*0x153bb == '\0' && (*0x153c0 == '\0')))) && (*0x153e7 == '\0')) &&
           (((*0x153ea == '\0' && (*0x153ff == '\0')) && (*0x15400 == '\0')))) &&
          (((((*0x15401 == '\0' && (*0x1540e == '\0')) &&
             ((*0x15413 == '\0' && ((*0x15417 == '\0' && (*0x15418 == '\0')))))) && (*0x15423 == '\0')) &&
           (((*0x1542b == '\0' && (*0x15432 == '\0')) && (*0x15435 == '\0')))))))) &&
        (((((*0x1543b == '\0' && (*0x1544a == '\0')) &&
           ((*0x15479 == '\0' && ((*0x1547b == '\0' && (*0x1548c == '\0')))))) && (*0x1548d == '\0')) &&
         ((((((*0x1548e == '\0' && (*0x15492 == '\0')) && (*0x1549b == '\0')) &&
            ((*0x1549c == '\0' && (*0x154a1 == '\0')))) && (*0x154a9 == '\0')) &&
          (((*0x154c4 == '\0' && (*0x154d8 == '\0')) && ((*0x154db == '\0' && (*0x154e6 == '\0')))))))))))) {
        sym.imp.puts("correct :)");
        sym.imp.exit(0);
    }
    sym.imp.puts("wrong :(");
    uVar4 = 1;
    sym.imp.exit(1);
    sym._init();
    iVar2 = 0;
    do {
        (**(segment.LOAD3 + iVar2 * 8))(uVar4 & 0xffffffff, uVar3, extraout_RDX);
        iVar2 = iVar2 + 1;
    } while (iVar2 != 1);
    return;
}
```

The addresses checked by the `if` condition change, as well as the contents of `obj.check`.
Everything else seems consistent between binaries.

`obj.check` contains 0x11001 bytes of self-modifying assembly.
The assembly is loaded into an RWX page and executed.
The assembly is different between runs.

At the beginning of a run, the assembly may look something like this:

```asm
            0x00004080      488d05120000.  lea rax, [0x00004099]
            0x00004087      48c7c1e70f01.  mov rcx, 0x10fe7
            0x0000408e      8030f7         xor byte [rax], 0xf7        ; [0xf7:1]=0
            0x00004091      48ffc0         inc rax
            0x00004094      48ffc9         dec rcx
            0x00004097      75f5           jne 0x408e
            0x00004099      be7aafe27d     mov esi, 0x7de2af7a
            0x0000409e      ec             in al, dx
            0x0000409f      7704           ja 0x40a5
            0x000040a1      f7be7a7e08f4   idiv dword [rsi - 0xbf78186]
            0x000040a7      f7f7           div edi
            0x000040a9      7fee           jg 0x4099
            0x000040ab      bf7af21008     mov edi, 0x810f27a
            0x000040b0      0808           or byte [rax], cl
            0x000040b2      bf3036faf7     mov edi, 0xf7fa3630
            0x000040b7      f7f7           div edi
            0x000040b9      31f7           xor edi, esi
            0x000040bb      f7bf0837bf08   idiv dword [rdi + 0x8bf3708]
            0x000040c1      3e             invalid
            0x000040c2      82             invalid
            0x000040c3      02bf7af2e5f7   add bh, byte [rdi - 0x81a0d86]
            0x000040c9      f7f7           div edi
            0x000040cb      bf303654f8     mov edi, 0xf8543630
            0x000040d0      f6f7           div bh
            0x000040d2      77c7           ja 0x409b
            0x000040d4      86bf0837bf08   xchg byte [rdi + 0x8bf3708], bh
            0x000040da      3e             invalid
            0x000040db      82             invalid
            0x000040dc      02cf           add cl, bh
            0x000040de      0bde           or ebx, esi
            0x000040e0      880c9d067586.  mov byte [rbx*4 - 0x30798afa], cl
            0x000040e7      0b0f           or ecx, dword [rdi]
            0x000040e9      7885           js 0x4070
            0x000040eb      86860e9fce0b   xchg byte [rsi + 0xbce9f0e], al
            0x000040f1      83617979       and dword [rcx + 0x79], 0x79 ; [0x79:4]=0x4000000
            0x000040f5     .string "ayyy" ; len=5
            0x000040f7      41478b868686.  mov r8d, dword [r14 - 0x79bf797a]
            0x000040ff      86ce           xchg dh, cl
```

As this shell code is executed, it will modify code ahead of it to create valid instructions.

## Solution

The self-modifying assembly was almost impossible to debug or otherwise dynamically analyze.
It begins with a long loop that is not feasible to step through, as it iterates 0x10fe7 times.
Automated tools, such as angr, have difficulty analysing this assembly, probably because the large number of branches.
Unicorn also has difficulty emulating the instructions.

### Understanding the self-modifying assembly

It is also not possible to view most of the completed code by running through it and reading the memory after,
as the code deletes previous segments as it runs.
This is the code near the end after it has been fully executed:

```asm
   0x7ffff7fbefbc    lea    rax, [rip + 0x12]
   0x7ffff7fbefc3    mov    rcx, 0x2b
   0x7ffff7fbefca    xor    byte ptr [rax], 0x1b
   0x7ffff7fbefcd    inc    rax
   0x7ffff7fbefd0    dec    rcx
   0x7ffff7fbefd3    jne    0x7ffff7fbefca                <0x7ffff7fbefca>
 
   0x7ffff7fbefd5    add    byte ptr [rax], al
   0x7ffff7fbefd7    add    byte ptr [rax], al
   0x7ffff7fbefd9    add    byte ptr [rax], al
   0x7ffff7fbefdb    add    byte ptr [rax], al
   0x7ffff7fbefdd    add    byte ptr [rax], al
   0x7ffff7fbefdf    add    byte ptr [rax], al
   0x7ffff7fbefe1    add    byte ptr [rcx], bl
   0x7ffff7fbefe3    lea    rax, [rip - 0x15]
   0x7ffff7fbefea    mov    rcx, 0xd
   0x7ffff7fbeff1    mov    byte ptr [rax], 0
   0x7ffff7fbeff4    inc    rax
   0x7ffff7fbeff7    dec    rcx
   0x7ffff7fbeffa    jne    0x7ffff7fbeff1                <0x7ffff7fbeff1>
 
   0x7ffff7fbeffc    nop    
   0x7ffff7fbeffd    nop    
   0x7ffff7fbeffe    nop    
   0x7ffff7fbefff    nop    
   0x7ffff7fbf000    ret                                  <0x100001224; main+159>
```

There are two loops here.
The first loop xors every byte after it with 0x1b.
The second loop overwrites some instructions before it with zeros.
We can see that the loops remain, but the part of code between those loops has been overwritten.

If we look through the rest of the code after execution, we can see that this is a pattern which repeats throughout the assembly.
Everywhere, there is a loop which xors everything after it, followed by some assembly which is overwritten by zeros and the loop that overwrote it.
The blocks are all 0x44 bytes long, and the loops are the same every time except for how many bytes are xored and the value they are xored with.

If we did manage to see the bit of assembly between the loops, we would find something like this:

```asm
            0x00004099      498d581b       lea rbx, [r8 + 0x1b]
            0x0000409d      8a1b           mov bl, byte [rbx]
            0x0000409f      80f300         xor bl, 0
            0x000040a2      498d89ff0300.  lea rcx, [r9 + 0x3ff]
            0x000040a9      8819           mov byte [rcx], bl
```

Note that `r8` is `obj.input` and `r9` is `obj.output`, as set by `main` before the call:

```asm
            0x00001205      488d05b43e01.  lea rax, obj.input          ; 0x150c0
            0x0000120c      4989c0         mov r8, rax
            0x0000120f      488d05ea3e01.  lea rax, obj.output         ; 0x15100
            0x00001216      4989c1         mov r9, rax
```

We can see that each segment deals with a character from our input and modifies the `obj.output` accordingly.
To learn what the program is doing to our input and reverse the process, we must have a reliable way of extracting these sections.

### Patching out loops

To extract the sections of code we were concerned with, we could essentially simulate what the leading loops did by computing the xor ourselves.
We could then replace both the leading and trailing loops with NOP instructions, leaving us with only the decoded useful parts of code.

#### Using radare2 to patch

Radare2 is incredibly useful here as it can disassemble assembly and has a decent scripting API.
Using this, we parsed the instructions to extract the number of bytes to xor and the value to xor them with.
We then read the raw bytes to xor and calculated the result in Python.

We tried to use the built-in write functions in radare2 to patch the binary.
Unfortunately, the write functions in radare2 have a limit on the size of the write that is too small for us to do the first write in one command.
We also want to minimize the number of radare2 commands, as the r2pipe library sometimes has problems returning the correct output.
For example, one command might fail to generate any output, and the response will instead be sent to the next command.

We were able to resolve this problem by restarting r2pipe every iteration and using a while loop to ensure that the output made it through.
However, this made the process far too slow and still was not reliable enough to solve even one binary.

#### Using Python to patch

Instead of using radare2 for the patching part, we tried opening the file in Python to edit.
When trying to patch for the first time, we ran into the issue that the patch seemed to not work for anything in `obj.check`.
We eventually realized that radare2 shows addresses as they would be when loaded into memory during program execution,
rather than offsets within the executable file itself.
To solve this, radare2 comes with the `?p` command to calculate the offset within the file.

We saw much more success when patching with Python.
Unfortunately, the process still look rather long as we would have to open and close the file many times,
and radare2 would still have to reopen the file between writes.
We tried using the built-in `oo` command to reopen the file, but this was highly error prone and we were forced to reinitialize r2pipe instead.

Even then, we had some problems with either radare2 not updating after a write, or a write seeming to be slightly offset from what we expected.
Because of these problems and the time that this method was taking, we decided to change our approach to patching.

#### Computing all patches in memory

Due to the difficulties with radare2 and disk writes, we decided to compute all xor operations in memory and only write once at the end.

We extracted the entire `obj.check` using radare2 as an array of bytes, just as we had before.
The difference was that now, instead of writing our intermediate results and reading them back from the file,
we would simply keep the intermediate array and operate on that.

Our previous method of disassembling the instructions wouldn't work the same.
However, radare2 does include the `pad` command for disassembling from a hexadecimal input, so we could have used that if we still wanted disassembly.
In the end, this wasn't necessary as we decided to directly read the bytes we were interested in.
Importantly, this would remove our dependence on radare2 as we iterated over the assembly, as we seemed to have problems when it was called often.

The instructions in each leading loop were the same except for the size and xor operand.
The size however, was always just the remaining length of code after the loop.
To extract the xor operand, we identified the byte responsible at each loop and read it from our memory array.

All the loops are placed consistently as well, so to remove them, we could simply overwrite all of their instructions with NOP instructions.

Now we could reliably write a single time to the binary and it will be completely patched.

We ran into problems initially that the binary would not include a return statement.
It seemed to end in NOPs until it reached the end.
While we could just add a return at the end manually, we were concerned that this meant we had missed something.

Looking back at the normal behaviour without patching, we realized that the return was in one of the addresses we had xored.
We had erroneously assumed that the xor was applied up to an offset of 0x11001, when in reality it should have been 1 byte shorter,
as the return was there from the start and did not have to be decoded.
When we corrected for this, we had fully functional code with the loops removed.

### Using angr to solve the patched code

Once the loops had been removed, angr had a fairly easy time solving the rest of the challenge.

We set it to find the address that loads the `"correct :)"` string and avoid the one that loads `"wrong :("`.
We also hooked the `read` function so that it would place our symbolic string in memory instead of reading from stdin.

Now, without any further guidance, angr was able to solve the constraints on the symbolic string necessary to reach the correct output.

## Script

```py
#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import r2pipe

io = remote("tamuctf.com", 443, ssl=True, sni="unboxing")

for binary in range(5):
    with open("elf", "wb") as file:
        file.write(bytes.fromhex(io.recvline().rstrip().decode()))
        file.close()

    exe = context.binary = ELF('elf')

    r = r2pipe.open(exe.path)
    r.cmd('aaa')
    correct = int(r.cmd('pdfs @ main ~ str.correct_:_').split()[0], 0)
    wrong = int(r.cmd('pdfs @ main ~ str.wrong_:_').split()[0], 0)

    mem = r.cmdj(f'pxj 0x11001 @ 0x4080')

    offset = 0;
    while offset + 0x44 < 0x11001:
        start = offset + 0x19
        xor = mem[offset + 0x10]

        # print(f"XOR to {hex(start)}")
        mem[start:-1] = [byte ^ xor for byte in mem[start:-1]]

        offset += 0x44

    print(hex(len(mem)))
    offset = 0;
    while offset + 0x44 < 0x11001:
        # print(f"NOP to {hex(offset)}")
        mem[offset + 0x00 : offset + 0x19] = [0x90] * 0x19
        mem[offset + 0x2b : offset + 0x44] = [0x90] * 0x19

        offset += 0x44

    print(hex(len(mem)))
    with open(exe.path, 'r+b') as file:
        file.seek(int(r.cmd('?p @ obj.check'), 0))
        file.write(bytes(mem))

    info("CORRECT = " + hex(correct))
    info("WRONG = " + hex(wrong))

    p = angr.Project(exe.path, main_opts={'base_addr': 0})

    password_chars = [claripy.BVS("byte_%d" % i, 8) for i in range(0x40)]
    password = claripy.Concat(*password_chars)

    class ReplacementRead(angr.SimProcedure):
        def run(self, fd, ptr, length):
            self.state.memory.store(ptr, password)

    p.hook_symbol('read', ReplacementRead(), replace=True)

    s = p.factory.full_init_state(
            add_options={
                    angr.options.LAZY_SOLVES,
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )

    sim = p.factory.simgr(s)

    sim.explore(find=correct, avoid=wrong)

    if sim.found:
        print("solution found")
        solution = sim.found[0].solver.eval(password, cast_to=bytes)
    else:
        print("no solution")

    io.sendline(solution.hex().encode())

io.interactive()
```

## Flag

```
gigem{unb0x1n6_74muc7f5_m057_3xclu51v3_fl46_ch3ck3r}
```
