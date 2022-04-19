# Labyrinth

## Challenge

Connecting to the challenge gives us a binary encoded as a hexadecimal string.

We must then send an input, also encoded as a hexadecimal string, which will cause the binary to exit with a status code of 0.

The binary consists of around 1000 functions, many of which call one of several functions each, depending on user input.
A portion of these functions include an `exit(1)` call, and only one includes `exit(0)`.

At each function, we enter an unsigned integer followed by a newline.
This is used to determine the next call made by the function.

## Solution

There are too many branches for angr to handle on its own, so we have to guide it quite a bit through the exploration process.

First, we can use radare2 to find the call to `exit(0)`.

If we generate a control-flow graph, we can then identify paths from the start of `main` to the desired `exit` call.
A problem arises, however, when we try generating the shortest path.
The path includes calls to the other functions, but it also includes calls to library functions.
The first time we tried generating a path, it used `__isoc99_scanf` to jump from one function to another in a way that should not have been possible.

To fix this, we removed all nodes from the graph except for `main` and the named functions included in the binary.

We tried having angr solve this, ignoring any nodes not in path, and searching for the target node.
Unfortunately, this still proved too complex for angr to solve, we would have to provide more guidance.

Instead, we had angr start at each node and explore to reach the next node.
We did this for every node in the path until it reached the end.
This method was much more successful and took very little time to complete.

We added replaced `__isoc99_scanf` with a hook which would record the numbers in a list.
As the path was straightforward, without complicated branching that might require backtracking, each stage called `__isoc99_scanf` once.
This allowed us to use a simple list and append the symbolic variables to it, without having to keep track of depth.

## Script

```py
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
```

## Flag

```
gigem{w0w_y0ur3_r34lly_600d_w17h_m4z35}
```
