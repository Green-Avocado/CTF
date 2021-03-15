# vault1

## Solution

Again, we're given a python script with an encrypted fag.
This one uses a function ```xor()``` and a key to encrypt user input and compare it to the flag.

```py
import base64

def xor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def checkpass():
    _input = input("Enter the password: ")
    key = "promortyusvatofacidpromortyusvato"
    encoded = str.encode(xor(key, _input))
    result = base64.b64encode(encoded, altchars=None)
    if result == b'ExMcGQAABzohNQ0TRQwtPidYAS8gXg4kAkcYISwOUQYS':
        return True
    else:
        return False

def main():
    global access
    access = checkpass()
    if access:
        print("Yeah...okay. You got it!")
    else:
        print("Lol...try again...")

access = False
main()
```

For xor operations, if ```a ^ b = c```, then ```c ^ b = a``` and ```c ^ a = b```.

Since we're given the result and the key, we can easily undo the operation by using the same ```xor()``` function by passing it the encrypted flag and key as parameters.

## Script

```py
#!/usr/bin/python
import base64

def xor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

target = b'ExMcGQAABzohNQ0TRQwtPidYAS8gXg4kAkcYISwOUQYS'
key = "promortyusvatofacidpromortyusvato"

target = base64.b64decode(target, altchars=None)
decoded = target.decode()

flag = xor(key, decoded)

print(flag)

f = open("flag.txt", "w")
f.write(flag)
f.close()
```

## Flag

```castorsCTF{r1cK_D1e_R1cKp3aT_x0r}```

