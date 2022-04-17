#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import r2pipe

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
    print(solution)
else:
    print("no solution")
