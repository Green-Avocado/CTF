# Flatland

Using BinaryNinja to extract control flow.

## Challenge

![Original CFG](./resources/original_cfg.png)

## Solution

```py
def getPossibleRange(block):
    possible = set()
    if block.start == 13:
        return possible
    if len(block.outgoing_edges) == 0:
        possible.add(exit_node)
        return possible
    if 13 in [edge.target.start for edge in block.outgoing_edges]:
        for i in range(block.end - 1, block.start - 1, -1):
            if 'rax' in [x.name for x in ssa[i].vars_written]:
                possible_rax = ssa[i].get_ssa_var_possible_values(ssa[i].vars_written[0])
                if hasattr(possible_rax, 'ranges'):
                    for rax_range in possible_rax.ranges:
                        bounded_start = max(rax_range.start, possible_rcx.start)
                        bounded_end = min(rax_range.end, possible_rcx.end)
                        possible.update([cases[ii]['node'] for ii in range(bounded_start, bounded_end + 1, rax_range.step)])
                elif hasattr(possible_rax, 'values'):
                    possible.update([cases[ii]['node'] for ii in possible_rax.values])
                else:
                    possible.add(cases[possible_rax.value]['node'])
                break
    for edge in block.outgoing_edges:
        possible.update(getPossibleRange(edge.target))
    return possible
```

```py
if bounded_start <= 0 and bounded_end >= 0xf:
    continue
```

![Over approximated CFG](./resources/over_approximation_cases.png) ![Under approximated CFG](./resources/under_approximation_cases.png)

```py
if len(ssa[i].non_ssa_form.vars_read) == 1 and ssa[i].non_ssa_form.vars_read[0].name == 'r15':
    possible.add(cases[0xf]['node'])
    break
```

![Better approximation CFG](./resources/better_approximation.png)

```py
for i in [1, 3, 5]:
    cases[0xf]['node'].add_outgoing_edge(BranchType.UserDefinedBranch, cases[i]['node'])
```

![Fixed CFG](./resources/fixed_cfg.png)

## Fix CFG Script

```py
def generateFixedCFG(showInstructions=True):
    main = bv.get_functions_by_name('main')[0]

    ssa = main.mmlil.ssa_form

    jump_table = bv.get_data_var_at(0x402010).value

    graph = FlowGraph()

    cases = {}

    possible_rcx = ssa[49].get_ssa_var_possible_values(ssa[49].vars_read[0]).ranges[0]

    entry_node = FlowGraphNode(graph)
    entry_node.lines = [f"ENTRY"]
    graph.append(entry_node)

    exit_node = FlowGraphNode(graph)
    exit_node.lines = [f"EXIT"]
    graph.append(exit_node)

    for i in range(len(jump_table)):
        for block in ssa.basic_blocks:
            if block.start == ssa.get_instruction_start(jump_table[i]):
                node = FlowGraphNode(graph)
                graph.append(node)
                cases[i] = {
                        'block': block,
                        'node': node,
                        }

    for x in main.hlil.instructions:
        if x.operation == HighLevelILOperation.HLIL_CASE:
            node = cases[x.operands[0][0].constant]['node']
            node.lines = list(x.lines)
            if showInstructions:
                node.lines += ['='*16] + list(x.body.lines)

    entry_node.add_outgoing_edge(BranchType.UserDefinedBranch, cases[0]['node'])

    def getPossibleRange(block):
        possible = set()
        if block.start == 13:
            return possible
        if len(block.outgoing_edges) == 0:
            possible.add(exit_node)
            return possible
        if 13 in [edge.target.start for edge in block.outgoing_edges]:
            for i in range(block.end - 1, block.start - 1, -1):
                if 'rax' in [x.name for x in ssa[i].vars_written]:
                    if len(ssa[i].non_ssa_form.vars_read) == 1 and ssa[i].non_ssa_form.vars_read[0].name == 'r15':
                        possible.add(cases[0xf]['node'])
                        break
                    possible_rax = ssa[i].get_ssa_var_possible_values(ssa[i].vars_written[0])
                    if hasattr(possible_rax, 'ranges'):
                        for rax_range in possible_rax.ranges:
                            bounded_start = max(rax_range.start, possible_rcx.start)
                            bounded_end = min(rax_range.end, possible_rcx.end)
                            if bounded_start <= 0 and bounded_end >= 0xf:
                                continue
                            possible.update([cases[ii]['node'] for ii in range(bounded_start, bounded_end + 1, rax_range.step)])
                    elif hasattr(possible_rax, 'values'):
                        possible.update([cases[ii]['node'] for ii in possible_rax.values])
                    else:
                        possible.add(cases[possible_rax.value]['node'])
                    break
        for edge in block.outgoing_edges:
            possible.update(getPossibleRange(edge.target))
        return possible

    for c in cases.values():
        if c['block'].immediate_post_dominator is None:
            c['node'].add_outgoing_edge(BranchType.UserDefinedBranch, exit_node)
            continue
        possible_branches = getPossibleRange(c['block'])
        for node in possible_branches:
            c['node'].add_outgoing_edge(BranchType.UserDefinedBranch, node)

    for i in [1, 3, 5]:
        cases[0xf]['node'].add_outgoing_edge(BranchType.UserDefinedBranch, cases[i]['node'])

    bv.show_graph_report("Fixed CFG", graph)
```

## Solve Script

```py
#!/usr/bin/env python3

from binaryninja import *

bview = BinaryViewType.get_view_of_file('flatland')

key = bview.get_ascii_string_at(0x402150).value
maps = bview.define_user_data_var(0x402090, Type.array(Type.array(Type.int(0x4), 0x18), 0x2), 'maps').value

def solveFlag(known):
    if len(known) == 0x18:
        print(known)
        return
    if known[-1] == '}':
        return
    candidates = set()
    for m in maps:
        for pair in enumerate(m):
            for i in range(2):
                if pair[i] == key.index(known[-1]) and key[pair[1-i]] not in known:
                    candidates.add(key[pair[1-i]])
    for c in candidates:
        solveFlag(known + c)

solveFlag('actf{')
```

## Flag

```
actf{Fl4TmAn_rouNdw0R1D}
```
