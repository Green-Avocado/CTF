#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import r2pipe
import networkx

io = remote("tamuctf.com", 443, ssl=True, sni="labyrinth")

for binary in range(5):
    with open("elf", "wb") as file:
        file.write(bytes.fromhex(io.recvline().rstrip().decode()))

    exe = context.binary = ELF('elf')

    r = r2pipe.open(exe.path)
    r.cmd('aaa')
    r.cmd('e search.in=bin.section.[x]')
    target = r.cmdj('pdfj @ ' + r.cmd('/a mov edi, 0; call sym.imp.exit;').split()[0])
    all_func_offsets = [func['offset'] for func in r.cmdj('aflj') if 'function_' in func['name']]

    p = angr.Project(exe.path, main_opts={'base_addr': 0}, load_options={'auto_load_libs': False})

    cfg = p.analyses.CFGFast()

    complete = False

    while not complete:
        complete = True

        for node in cfg.graph.nodes:
            if node.function_address not in all_func_offsets and node.name and 'main' not in node.name:
                cfg.graph.remove_node(node)
                complete = False
                break

    mainNode = cfg.model.get_node(exe.sym['main'])
    targetNode = cfg.model.get_node(target['addr'])

    path = networkx.algorithms.shortest_path(
            cfg.graph,
            source=mainNode,
            target=targetNode
        )

    nums = []

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, ptr):
            u = claripy.BVS('num_%d' % len(nums), 4*8)
            nums.append(u)
            self.state.mem[ptr].dword = u

    p.hook_symbol('__isoc99_scanf', ReplacementScanf(), replace=True)

    s = p.factory.full_init_state(
            add_options=set.union(
                angr.options.unicorn,
                {
                    angr.options.LAZY_SOLVES,
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                }
            )
        )

    sim = p.factory.simgr(s)

    print("PATH: " + str([node.name for node in path]) + " (" + str(len(path)) + ")")

    for node in path:
        sim.explore(find=node.addr)

        if sim.found:
            print(node.name + " solution found")
            sim = p.factory.simgr(sim.found[0])
        else:
            print("no solution")

    solution = [sim.active[0].solver.eval(num) for num in nums]

    print(solution)

    io.sendline(b"".join([str(num).encode() + b'\n' for num in solution]).hex().encode())

io.interactive()
