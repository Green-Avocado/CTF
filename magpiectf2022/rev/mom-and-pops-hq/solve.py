#!/usr/bin/env python3

import angr
import claripy

p = angr.Project('./CONFIDENTIAL_BLUEPRINTS', main_opts={'base_addr': 0}, auto_load_libs=True)

password_chars = [claripy.BVS("byte_%d" % i, 8) for i in range(8)]
password = claripy.Concat(*password_chars + [claripy.BVV(b'\n')])

s = p.factory.entry_state(
        stdin=angr.SimFileStream(name='stdin', content=password, has_end=True),
        add_options=set.union(
            angr.options.unicorn,
            {
                angr.options.LAZY_SOLVES,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }))

for c in password_chars:
    s.solver.add(c < 0x7f)
    s.solver.add(c > 0x20)

sim = p.factory.simgr(s)
sim.explore(find=0x000021c9, avoid=0x0000244f)

if sim.found:
    print(sim.found[0].posix.dumps(1).decode())
else:
    print("no solution")
