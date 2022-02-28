# Mom & Pops HQ

## Challenge

We're given a .iso file, which we are told contains secret blueprints.

Mounting the file allows us to extract the `CONFIDENTIAL_BLUEPRINTS` executable.
Running this executable prompts us for a keycode.

## Solution

Let's start by disassembling the binary in radare2.

```c
void main(void)

{
    char *s;
    int32_t var_8h;
    undefined8 var_4h;
    
    var_4h._0_4_ = 0;
    sym.imp.puts("          ***CONFIDENTIAL***          \n");
    sym.imp.puts("Please enter your unique key code:");
    sym.imp.fgets(&s, 2000, _reloc.stdin);
    for (var_8h = 0; (var_8h < 2000 && (*(char *)((int64_t)&s + (int64_t)var_8h) != '\n')); var_8h = var_8h + 1) {
        var_4h._0_4_ = (int32_t)var_4h + 1;
    }
    if (((int32_t)var_4h < 8) || (8 < (int32_t)var_4h)) {
        sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
    }
    else {
        fcn.00002222((char *)&s);
    }
    return;
}
```

The `main` function checks that the length of our input, excluding the newline, is 8 characters.
If it is, we call `fcn.00002222`.

```c
void fcn.00002222(char *arg1)

{
    char cVar1;
    char *var_18h;
    int64_t var_5h;
    
    cVar1 = fcn.000021ca();
    if (arg1[3] == cVar1) {
        cVar1 = fcn.000021e0();
        if (*arg1 == cVar1) {
            cVar1 = fcn.00002217();
            if (arg1[2] == cVar1) {
                cVar1 = fcn.000021f6();
                if (arg1[1] == cVar1) {
                    cVar1 = fcn.0000220c();
                    if (arg1[7] == cVar1) {
                        cVar1 = fcn.000021d5();
                        if (arg1[4] == cVar1) {
                            cVar1 = fcn.000021eb();
                            if (arg1[6] == cVar1) {
                                cVar1 = fcn.00002201();
                                if (arg1[5] == cVar1) {
                                    sym.imp.puts("Key validated...\nTOP SECRET BLUEPRINTS BELOW\n");
                                    fcn.00001155();
                                }
                                else {
                                    sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
                                }
                            }
                            else {
                                sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
                            }
                        }
                        else {
                            sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
                        }
                    }
                    else {
                        sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
                    }
                }
                else {
                    sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
                }
            }
            else {
                sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
            }
        }
        else {
            sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
        }
    }
    else {
        sym.imp.puts("Invalid Key!\nAre you sure you should have this...?");
    }
    return;
}
```

The function checks each character against the result of a different function.
Each of these other functions return a single character.
For example, the first one decompiles as follows:

```c
undefined8 fcn.000021ca(void)

{
    return 0x49;
}
```

Note that these comparisons are not done in order.

If all these tests succeed, we call `fcn.00001155`, an obfuscated function that prints ASCII art.

### Manually read the key

There are only 8 characters and it is trivial to read the expected characters from a decompiler.

If we read these in the correct order, we get the following:

0x4f
0x4d
0x4e
0x49
0x43
0x4f
0x52
0x50

If we convert these to an ASCII string, we get "OMNICORP".

Using this password gives us the flag:

```
$ ./CONFIDENTIAL_BLUEPRINTS 
          ***CONFIDENTIAL***          

Please enter your unique key code:
OMNICORP
Key validated...
TOP SECRET BLUEPRINTS BELOW

	     _________________________________________________________________________________________________________________________________________________
            /                                                                                                                                                 \
           /                     __  __                                             _     ____                    _           _   _    ___                     \
          /                     |  \/  |   ___    _ __ ___       __ _   _ __     __| |   |  _ \    ___    _ __   ( )  ___    | | | |  / _ \                     \
         /                      | |\/| |  / _ \  | '_ ` _ \     / _` | | '_ \   / _` |   | |_) |  / _ \  | '_ \  |/  / __|   | |_| | | | | |                     \
        /                       | |  | | | (_) | | | | | | |   | (_| | | | | | | (_| |   |  __/  | (_) | | |_) |     \__ \   |  _  | | |_| |                      \
       /                        |_|  |_|  \___/  |_| |_| |_|    \__,_| |_| |_|  \__,_|   |_|      \___/  | .__/      |___/   |_| |_|  \__\_\                       \
      /                                                                                                  |_|                                                        \
     /                                                                                                                                                               \
    /                                                                                                                                                                 \
   /                                                                                                                                                                   \
  /                                                                                                                                                                     \
 /                                                                                                                                                                       \
/_________________________________________________________________________________________________________________________________________________________________________\
|                                      _            __          _  _                                               _  _            _                                     |
|  _ __ ___     __ _    __ _   _ __   (_)   ___    / /  ___   _| || |_    ___    _ __            ___   _ __ ___   | || |    _ __  | |_                                   |
| | '_ ` _ \   / _` |  / _` | | '_ \  | |  / _ \  | |  / __| |_  ..  _|  / _ \  | '_ \          / __| | '_ ` _ \  | || |_  | '__| | __|                                  |
| | | | | | | | (_| | | (_| | | |_) | | | |  __/ < <   \__ \ |_      _| | (_) | | |_) |         \__ \ | | | | | | |__   _| | |    | |_                                   |
| |_| |_| |_|  \__,_|  \__, | | .__/  |_|  \___|  | |  |___/   |_||_|    \___/  | .__/   _____  |___/ |_| |_| |_|    |_|   |_|     \__|  _____                           |
|                      |___/  |_|                  \_\                          |_|     |_____|                                         |_____|                          |
|                                                                _  _                                                         _                                          |
|                                                        ___   _| || |_    ___    _ __             ___    _ __ ___    _ __   (_)                                         |
|                                                       / __| |_  ..  _|  / _ \  | '_ \           / _ \  | '_ ` _ \  | '_ \  | |                                         |
|                                                       \__ \ |_      _| | (_) | | |_) |         | (_) | | | | | | | | | | | | |                                         |
|                                                       |___/   |_||_|    \___/  | .__/   _____   \___/  |_| |_| |_| |_| |_| |_|  _____                                  |
|                                                                                |_|     |_____|                                 |_____|                                 |
|                                                                  _  _            _    __                                                                               |
|                                                      _ __ ___   | || |    _ __  | |_  \ \                                                                              |
|                                                     | '_ ` _ \  | || |_  | '__| | __|  | |                                                                             |
|                                                     | | | | | | |__   _| | |    | |_    > >                                                                            |
|                                                     |_| |_| |_|    |_|   |_|     \__|  | |                                                                             |
|                                                                                       /_/                                                                              |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                               __________________________                                                                               |
|                                                              |             |            |                                                                              |
|                                                              |             |            |                                                                              |
|                                                              |_____________|____________|                                   _______________________                    |
|                                                              |             |            |                                  |                       |                   |
|                                                              |             |            |                                  |                       |                   |
|                                                              |_____________|____________|                                  |                       |                   |
|                                                                                                                            |                       |                   |
|                                                                                                                            |                       |                   |
|    _____        ___                        _           _____   _                                                           |                       |                   |
|   / ___ \      / _ \   _ __ ___    _ __   (_)         |  ___| | |   __ _    __ _   _                                       |                       |                   |
|  / / __| \    | | | | | '_ ` _ \  | '_ \  | |  _____  | |_    | |  / _` |  / _` | (_)                                      |                       |                   |
| | | (__   |   | |_| | | | | | | | | | | | | | |_____| |  _|   | | | (_| | | (_| |  _                                       |                       |                   |
|  \ \___| /     \___/  |_| |_| |_| |_| |_| |_|         |_|     |_|  \__,_|  \__, | (_)                                      |                   _   |                   |
|   \_____/                                                                  |___/                                           |                  |_|  |                   |
|     _        _____                       _   _              ____                                                           |                       |                   |
|    / \      |  ___|   __ _   _ __ ___   (_) | |  _   _     / ___|   ___    _ __ ___    _ __     __ _   _ __    _   _       |                       |                   |
|   / _ \     | |_     / _` | | '_ ` _ \  | | | | | | | |   | |      / _ \  | '_ ` _ \  | '_ \   / _` | | '_ \  | | | |      |                       |                   |
|  / ___ \    |  _|   | (_| | | | | | | | | | | | | |_| |   | |___  | (_) | | | | | | | | |_) | | (_| | | | | | | |_| |      |                       |                   |
| /_/   \_\   |_|      \__,_| |_| |_| |_| |_| |_|  \__, |    \____|  \___/  |_| |_| |_| | .__/   \__,_| |_| |_|  \__, |      |                       |                   |
|                                                  |___/                                |_|                      |___/       |                       |                   |
|                                                                                                                            |                       |                   |
|____________________________________________________________________________________________________________________________|_______________________|___________________|

```

### GDB

Instead of finding the key, we can call the target function directly and skip the key validation using GDB:

```
$ gdb CONFIDENTIAL_BLUEPRINTS
pwndbg> start
Temporary breakpoint 1 at 0x100001070
pwndbg> jump *0x100001155
Continuing at 0x100001155.
	     _________________________________________________________________________________________________________________________________________________
            /                                                                                                                                                 \
           /                     __  __                                             _     ____                    _           _   _    ___                     \
          /                     |  \/  |   ___    _ __ ___       __ _   _ __     __| |   |  _ \    ___    _ __   ( )  ___    | | | |  / _ \                     \
         /                      | |\/| |  / _ \  | '_ ` _ \     / _` | | '_ \   / _` |   | |_) |  / _ \  | '_ \  |/  / __|   | |_| | | | | |                     \
        /                       | |  | | | (_) | | | | | | |   | (_| | | | | | | (_| |   |  __/  | (_) | | |_) |     \__ \   |  _  | | |_| |                      \
       /                        |_|  |_|  \___/  |_| |_| |_|    \__,_| |_| |_|  \__,_|   |_|      \___/  | .__/      |___/   |_| |_|  \__\_\                       \
      /                                                                                                  |_|                                                        \
     /                                                                                                                                                               \
    /                                                                                                                                                                 \
   /                                                                                                                                                                   \
  /                                                                                                                                                                     \
 /                                                                                                                                                                       \
/_________________________________________________________________________________________________________________________________________________________________________\
|                                      _            __          _  _                                               _  _            _                                     |
|  _ __ ___     __ _    __ _   _ __   (_)   ___    / /  ___   _| || |_    ___    _ __            ___   _ __ ___   | || |    _ __  | |_                                   |
| | '_ ` _ \   / _` |  / _` | | '_ \  | |  / _ \  | |  / __| |_  ..  _|  / _ \  | '_ \          / __| | '_ ` _ \  | || |_  | '__| | __|                                  |
| | | | | | | | (_| | | (_| | | |_) | | | |  __/ < <   \__ \ |_      _| | (_) | | |_) |         \__ \ | | | | | | |__   _| | |    | |_                                   |
| |_| |_| |_|  \__,_|  \__, | | .__/  |_|  \___|  | |  |___/   |_||_|    \___/  | .__/   _____  |___/ |_| |_| |_|    |_|   |_|     \__|  _____                           |
|                      |___/  |_|                  \_\                          |_|     |_____|                                         |_____|                          |
|                                                                _  _                                                         _                                          |
|                                                        ___   _| || |_    ___    _ __             ___    _ __ ___    _ __   (_)                                         |
|                                                       / __| |_  ..  _|  / _ \  | '_ \           / _ \  | '_ ` _ \  | '_ \  | |                                         |
|                                                       \__ \ |_      _| | (_) | | |_) |         | (_) | | | | | | | | | | | | |                                         |
|                                                       |___/   |_||_|    \___/  | .__/   _____   \___/  |_| |_| |_| |_| |_| |_|  _____                                  |
|                                                                                |_|     |_____|                                 |_____|                                 |
|                                                                  _  _            _    __                                                                               |
|                                                      _ __ ___   | || |    _ __  | |_  \ \                                                                              |
|                                                     | '_ ` _ \  | || |_  | '__| | __|  | |                                                                             |
|                                                     | | | | | | |__   _| | |    | |_    > >                                                                            |
|                                                     |_| |_| |_|    |_|   |_|     \__|  | |                                                                             |
|                                                                                       /_/                                                                              |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                               __________________________                                                                               |
|                                                              |             |            |                                                                              |
|                                                              |             |            |                                                                              |
|                                                              |_____________|____________|                                   _______________________                    |
|                                                              |             |            |                                  |                       |                   |
|                                                              |             |            |                                  |                       |                   |
|                                                              |_____________|____________|                                  |                       |                   |
|                                                                                                                            |                       |                   |
|                                                                                                                            |                       |                   |
|    _____        ___                        _           _____   _                                                           |                       |                   |
|   / ___ \      / _ \   _ __ ___    _ __   (_)         |  ___| | |   __ _    __ _   _                                       |                       |                   |
|  / / __| \    | | | | | '_ ` _ \  | '_ \  | |  _____  | |_    | |  / _` |  / _` | (_)                                      |                       |                   |
| | | (__   |   | |_| | | | | | | | | | | | | | |_____| |  _|   | | | (_| | | (_| |  _                                       |                       |                   |
|  \ \___| /     \___/  |_| |_| |_| |_| |_| |_|         |_|     |_|  \__,_|  \__, | (_)                                      |                   _   |                   |
|   \_____/                                                                  |___/                                           |                  |_|  |                   |
|     _        _____                       _   _              ____                                                           |                       |                   |
|    / \      |  ___|   __ _   _ __ ___   (_) | |  _   _     / ___|   ___    _ __ ___    _ __     __ _   _ __    _   _       |                       |                   |
|   / _ \     | |_     / _` | | '_ ` _ \  | | | | | | | |   | |      / _ \  | '_ ` _ \  | '_ \   / _` | | '_ \  | | | |      |                       |                   |
|  / ___ \    |  _|   | (_| | | | | | | | | | | | | |_| |   | |___  | (_) | | | | | | | | |_) | | (_| | | | | | | |_| |      |                       |                   |
| /_/   \_\   |_|      \__,_| |_| |_| |_| |_| |_|  \__, |    \____|  \___/  |_| |_| |_| | .__/   \__,_| |_| |_|  \__, |      |                       |                   |
|                                                  |___/                                |_|                      |___/       |                       |                   |
|                                                                                                                            |                       |                   |
|____________________________________________________________________________________________________________________________|_______________________|___________________|

Program received signal SIGSEGV, Segmentation fault.
```

### angr

We can use [angr](https://github.com/angr/angr) to find the key for us.

We set our `stdin` as 8 bit vectors of size 8 (one for each password character), plus a terminating newline.
We can add constraints that each bit vector is greater than 0x20 and less that 0x7f, assuming there will only be letters, numbers, and symbols.

Finally, we set the simulation to search for an input that reaches the address of the target function.
If found, we print `stdout`:

```
$ ./solve.py             
          ***CONFIDENTIAL***          

Please enter your unique key code:
Key validated...
TOP SECRET BLUEPRINTS BELOW

	     _________________________________________________________________________________________________________________________________________________
            /                                                                                                                                                 \
           /                     __  __                                             _     ____                    _           _   _    ___                     \
          /                     |  \/  |   ___    _ __ ___       __ _   _ __     __| |   |  _ \    ___    _ __   ( )  ___    | | | |  / _ \                     \
         /                      | |\/| |  / _ \  | '_ ` _ \     / _` | | '_ \   / _` |   | |_) |  / _ \  | '_ \  |/  / __|   | |_| | | | | |                     \
        /                       | |  | | | (_) | | | | | | |   | (_| | | | | | | (_| |   |  __/  | (_) | | |_) |     \__ \   |  _  | | |_| |                      \
       /                        |_|  |_|  \___/  |_| |_| |_|    \__,_| |_| |_|  \__,_|   |_|      \___/  | .__/      |___/   |_| |_|  \__\_\                       \
      /                                                                                                  |_|                                                        \
     /                                                                                                                                                               \
    /                                                                                                                                                                 \
   /                                                                                                                                                                   \
  /                                                                                                                                                                     \
 /                                                                                                                                                                       \
/_________________________________________________________________________________________________________________________________________________________________________\
|                                      _            __          _  _                                               _  _            _                                     |
|  _ __ ___     __ _    __ _   _ __   (_)   ___    / /  ___   _| || |_    ___    _ __            ___   _ __ ___   | || |    _ __  | |_                                   |
| | '_ ` _ \   / _` |  / _` | | '_ \  | |  / _ \  | |  / __| |_  ..  _|  / _ \  | '_ \          / __| | '_ ` _ \  | || |_  | '__| | __|                                  |
| | | | | | | | (_| | | (_| | | |_) | | | |  __/ < <   \__ \ |_      _| | (_) | | |_) |         \__ \ | | | | | | |__   _| | |    | |_                                   |
| |_| |_| |_|  \__,_|  \__, | | .__/  |_|  \___|  | |  |___/   |_||_|    \___/  | .__/   _____  |___/ |_| |_| |_|    |_|   |_|     \__|  _____                           |
|                      |___/  |_|                  \_\                          |_|     |_____|                                         |_____|                          |
|                                                                _  _                                                         _                                          |
|                                                        ___   _| || |_    ___    _ __             ___    _ __ ___    _ __   (_)                                         |
|                                                       / __| |_  ..  _|  / _ \  | '_ \           / _ \  | '_ ` _ \  | '_ \  | |                                         |
|                                                       \__ \ |_      _| | (_) | | |_) |         | (_) | | | | | | | | | | | | |                                         |
|                                                       |___/   |_||_|    \___/  | .__/   _____   \___/  |_| |_| |_| |_| |_| |_|  _____                                  |
|                                                                                |_|     |_____|                                 |_____|                                 |
|                                                                  _  _            _    __                                                                               |
|                                                      _ __ ___   | || |    _ __  | |_  \ \                                                                              |
|                                                     | '_ ` _ \  | || |_  | '__| | __|  | |                                                                             |
|                                                     | | | | | | |__   _| | |    | |_    > >                                                                            |
|                                                     |_| |_| |_|    |_|   |_|     \__|  | |                                                                             |
|                                                                                       /_/                                                                              |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                                                                                                                                        |
|                                                               __________________________                                                                               |
|                                                              |             |            |                                                                              |
|                                                              |             |            |                                                                              |
|                                                              |_____________|____________|                                   _______________________                    |
|                                                              |             |            |                                  |                       |                   |
|                                                              |             |            |                                  |                       |                   |
|                                                              |_____________|____________|                                  |                       |                   |
|                                                                                                                            |                       |                   |
|                                                                                                                            |                       |                   |
|    _____        ___                        _           _____   _                                                           |                       |                   |
|   / ___ \      / _ \   _ __ ___    _ __   (_)         |  ___| | |   __ _    __ _   _                                       |                       |                   |
|  / / __| \    | | | | | '_ ` _ \  | '_ \  | |  _____  | |_    | |  / _` |  / _` | (_)                                      |                       |                   |
| | | (__   |   | |_| | | | | | | | | | | | | | |_____| |  _|   | | | (_| | | (_| |  _                                       |                       |                   |
|  \ \___| /     \___/  |_| |_| |_| |_| |_| |_|         |_|     |_|  \__,_|  \__, | (_)                                      |                   _   |                   |
|   \_____/                                                                  |___/                                           |                  |_|  |                   |
|     _        _____                       _   _              ____                                                           |                       |                   |
|    / \      |  ___|   __ _   _ __ ___   (_) | |  _   _     / ___|   ___    _ __ ___    _ __     __ _   _ __    _   _       |                       |                   |
|   / _ \     | |_     / _` | | '_ ` _ \  | | | | | | | |   | |      / _ \  | '_ ` _ \  | '_ \   / _` | | '_ \  | | | |      |                       |                   |
|  / ___ \    |  _|   | (_| | | | | | | | | | | | | |_| |   | |___  | (_) | | | | | | | | |_) | | (_| | | | | | | |_| |      |                       |                   |
| /_/   \_\   |_|      \__,_| |_| |_| |_| |_| |_|  \__, |    \____|  \___/  |_| |_| |_| | .__/   \__,_| |_| |_|  \__, |      |                       |                   |
|                                                  |___/                                |_|                      |___/       |                       |                   |
|                                                                                                                            |                       |                   |
|____________________________________________________________________________________________________________________________|_______________________|___________________|

```

## Script

```py
#!/usr/bin/env python3

import angr
import claripy

p = angr.Project('./CONFIDENTIAL_BLUEPRINTS', main_opts={'base_addr': 0}, auto_load_libs=True)

password_chars = [claripy.BVS("byte_%d", 8) for i in range(8)]
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
```

## Flag

```
magpie{s#op_sm4rt_s#op_omni_m4rt}
```
