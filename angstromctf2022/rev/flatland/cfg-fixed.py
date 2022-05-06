def generateFixedCFG(showInstructions=True, showSummary=True):
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

    summary = {
            0: [
                '- zeros stack variables',
                '- sets r15 to 1',
                ],
            0xd: [
                '- reads a character to [c]',
                '- if [c] is -1 (i.e. getc fails) : go to 3',
                '- else (i.e. getc succeeds) : go to 0xe',
                ],
            0xe: [
                '- store r15 to [saved_r15]',
                '- sets r15 to 0xf',
                ],
            7: [
                '- sets [offset] to 0',
                ],
            8: [
                '- if [offset] == 0x18 : go to 9',
                '- else : go to 0xb',
                ],
            9: [
                '- set [offset] to -1',
                '- go to r15 (known to be 0xf)',
                ],
            0xb: [
                '- check that [c] == key at offset [offset]',
                '- if true : go to 0xc',
                '- if false : go to 0xa',
                ],
            0xa: [
                '- increment [offset] by 1',
                '- go to 8',
                ],
            0xc: [
                '- go to 0xf',
                ],
            0xf: [
                '- if [offset] == -1 : go to 3',
                '- else : go to [saved_r15] (can be 1 or 5)',
                ],
            3: [
                '- exit failure',
                ],
            1: [
                '- set [prev_offset] to [offset]',
                '- set [used_chars] at [offset] to 1',
                '- set [chars_read] to 1',
                ],
            5: [
                '- if [map0] at [prev_offset] == [offset]',
                '  or [map0] at [offset] == [prev_offset]',
                '  or [map1] at [prev_offset] == [offset]',
                '  or [map1] at [offset] == [prev_offset] :',
                '  - if [used_chars] at [offset] == 0 : go to 2',
                '  - else : go to 3',
                '- else : go to 3',
                ],
            2: [
                '- set [prev_offset] to [offset]',
                '- set [used_chars] at [offset] to 1',
                '- increment [chars_read] by 1',
                '- if [chars_read] == 0x18 : go to 6',
                '- else : go to 4',
                ],
            4: [
                '- set r15 to 5',
                '- go to 0xd',
                ],
            6: [
                '- exit success',
                ],
            }

    if showSummary:
        for i in cases:
            if showInstructions:
                cases[i]['node'].lines += ['='*16]
            cases[i]['node'].lines += summary[i]

    bv.show_graph_report("Fixed CFG", graph)
