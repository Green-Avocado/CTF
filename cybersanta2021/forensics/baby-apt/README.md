# baby APT

## Challenge

We're given a pcap file with a hidden flag.

## Solution

By analysing the pcap file, we can see that there are some HTTP requests.

If we filter these out, we see some suspicious shell commands being sent.

One of these commands uses `echo` to print a base64 string.

If we decode this base64 string, we get the flag.

## Script

First, dump the packet contents using

```
tshark -r christmaswishlist.pcap -x > dump
```

Then run the following script

```py
#!/usr/bin/python3

import re
import base64

dump = open("dump", "r")

packet = ""

for line in dump:
    line = line.strip().split("   ")
    if len(line) == 2:
        packet += line[1]
    else:
        echocmd = re.search('echo [A-Za-z0-9+/=]+ ', packet)
        if echocmd:
            b64 = echocmd.group(0).split(' ')[1].encode()
            flag = base64.b64decode(b64).decode('utf-8')
            print(flag)

        packet = ""
```

## Flag

`HTB{0k_n0w_3v3ry0n3_h4s_t0_dr0p_0ff_th3ir_l3tt3rs_4t_th3_p0st_0ff1c3_4g41n}`
