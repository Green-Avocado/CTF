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
