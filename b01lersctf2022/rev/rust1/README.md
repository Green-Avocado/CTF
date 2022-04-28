# rust1

## Challenge

We're given a rust binary and a remote to connect to.

Running the binary or connecting to the remote presents the following welcome message:

```
To get the flag, you have to beat the monster the correct way
Think you can handle it?....
Prepare to lose
```

We then get a prompt:

```
I have 120 health, prepare to lose
1) Flame
2) Ice
3) Wind
Enter your attack
```

We can enter one of the options to attack the monster.
It will then ask for any powerups.
If we answer `N` to powerups, we get a response such as the following:

```
Enter your attack
1
Any powerups?
Y/N
N
You rolled: 22
Monster rolled: 16
Ouch! That's gonna leave a mark
You now have 70 health
 and the monster has 98 health
```

OR

```
Enter your attack
1
Any powerups?
Y/N
N
You rolled: 14
Monster rolled: 28
Nice try ;)
You now have 42 health
 and the monster has 120 health
```

Both the player and the monster roll for a random number.
Whoever has the higher number does that amount of damage to the other.

From trial and error, the type of attack does not seem to have any noticeable affect on the probability.
The monster has more health and seems more likely to roll a higher number.
In most runs, we will lose the battle if we continue to attack like this.

```
Enter your attack
3
Any powerups?
Y/N
N
You rolled: 6
Monster rolled: 21
Nice try ;)
You now have 0 health
 and the monster has 71 health
HAHAHAHA YOU LOSE!!!!
```

However, it is possible to win by chance.

```
Enter your attack
1
Any powerups?
Y/N
N
You rolled: 25
Monster rolled: 13
Ouch! That's gonna leave a mark
You now have 18 health
 and the monster has 0 health
I CAN'T BELIEVE IT!!!!
 You beat me
BUT WHERE'S THE FLAG???
```

Even after winning, we are not presented with a flag.

## Solution

At some point, the program would have to read and print the flag.
If we look at the binary symbols, we can see that it uses `std::sys::unix::process` and `std::process::Command::output`.
These symbols are interesting as they are likely involved in printing the flag.

Using cross references, we can see the symbol is called in the basic block at 0xaf92.
The disassembly for this block looks like this:

```asm
0000af92  488d354d090400     lea     rsi, [rel str.0[0x186]]  {"catUh oh, flag file is missing, …"}
0000af99  488d5c2410         lea     rbx, [rsp+0x10 {var_1d8}]
0000af9e  ba03000000         mov     edx, 0x3
0000afa3  4889df             mov     rdi, rbx {var_1d8}
0000afa6  ff15fc3d0500       call    qword [rel data_5eda8]  {std::sys::unix::process::process_common::Command::new}
0000afac  488d3506070400     lea     rsi, [rel data_4b080[0x639]]  {"flag.txtEnter your attack\nsrc/m…"}
0000afb3  ba08000000         mov     edx, 0x8
0000afb8  4889df             mov     rdi, rbx {var_1d8}
0000afbb  ff1547380500       call    qword [rel data_5e808]  {std::sys::unix::process::process_common::Command::arg}
0000afc1  488dbc24e0000000   lea     rdi, [rsp+0xe0 {var_108}]
0000afc9  488d742410         lea     rsi, [rsp+0x10 {var_1d8}]
0000afce  ff154c3d0500       call    qword [rel data_5ed20]  {std::process::Command::output}
0000afd4  83bc24e000000001   cmp     dword [rsp+0xe0 {var_108}], 0x1
0000afdc  0f84e8040000       je      0xb4ca
```

Note that the string annotations do not terminate where they should because rust strings are not null terminated.

We can see from this block that the program is running `cat flag.txt` as a subprocess and storing the output of the command.
We need to find an input that reaches this block.

Looking at the CFG of `rust1::main`, we can see that there is a path from the block which reads our powerup, to the `cat flag.txt` block.

This is what happens when we try entering an random powerup:

```
I have 120 health, prepare to lose
1) Flame
2) Ice
3) Wind
Enter your attack
1
Any powerups?
Y/N
Y
Enter your powerup
aaa
thread 'main' panicked at 'Illegal length', src/main.rs:101:17
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

We can find the block which reads our powerup by following cross references to the string `"Enter your powerup"`.
Looking at this block, we find that, if the read is successful, it will branch into a block which runs `trim_matches` on the input and compares a register to 0x16.
If we try entering a powerup of length 16, we get a different error:

```
I have 120 health, prepare to lose
1) Flame
2) Ice
3) Wind
Enter your attack
1
Any powerups?
Y/N
Y
Enter your powerup
aaaaaaaaaaaaaaaaaaaaaa
Check1 failed
```

If we look for the block which references `"Check1 failed"`, then follow the edge preceeding it, we find the following block:

```asm
0000a832  488bbc24e0000000   mov     rdi, qword [rsp+0xe0 {var_108}]
0000a83a  0fb607             movzx   eax, byte [rdi]
0000a83d  0fb64f01           movzx   ecx, byte [rdi+0x1]
0000a841  01c1               add     ecx, eax
0000a843  0fb64702           movzx   eax, byte [rdi+0x2]
0000a847  01c8               add     eax, ecx
0000a849  0fb64f03           movzx   ecx, byte [rdi+0x3]
0000a84d  01c1               add     ecx, eax
0000a84f  81f915010000       cmp     ecx, 0x115
0000a855  0f855d060000       jne     0xaeb8
```

We can see that it adds the first 4 characters in our string as bytes, then checks that their sum equals 0x115.

If we continue to follow the path from this block to the `cat flag.txt` block, we find a number of other checks.

We can extract all these conditions and use a solver such as Z3 to find a solution which satisfies all constraints.
Running this through Z3, we get a solution such as `B"3~-hzuC!|>yd"!U+#!}T`
If we enter this as our powerup, we are given the flag.

## Script

```
#!/usr/bin/env python3

from z3 import *
from pwn import *

powerup = b'B"3~-hzuC!|>yd"!U+#!}T'

if len(powerup) == 0:

    s = Solver()

    nums = []

    for i in range(0x16):
        x = Int('num_%d' % i)
        s.add(x > 0x20)
        s.add(x < 0x7f)
        nums.append(x)

    s.add(nums[0] + nums[1] + nums[2] + nums[3] == 0x115)

    s.add(nums[4] * nums[5] + nums[6] + nums[7] == 0x1337)

    s.add(nums[8] + nums[9] > 0x63)

    s.add(nums[10] / nums[0xb] == 0x2)
    s.add(nums[10] % nums[0xb] == 0x0)

    s.add(nums[0xd] * nums[0xc] >= 0x3e9)

    s.add(nums[0xf] + nums[0xe] * 5 >= 0xc9)

    s.add(nums[0x10] - nums[0x11] == 0x2a)

    s.add(nums[0x12] - nums[0x13] == 0x2)

    s.add(nums[0x15] * nums[0x14] >= 0x384)

    s.check()
    m = s.model()

    for i in nums:
        powerup += p8(m.eval(i).as_long())

print(powerup)

io = remote("ctf.b01lers.com", 9303)

io.sendlineafter(b"Enter your attack\n", b"1")

io.sendlineafter(b"Y/N\n", b"Y")

io.sendlineafter(b"Enter your powerup\n", powerup)

io.interactive()
```

## Flag

```
bctf{5l4y1ng_m0ns73r5_&_gr4bb1ng_fl4g5}
```
