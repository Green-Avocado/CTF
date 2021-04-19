# Glitchity-Glitch

If you wanna take your mind off things, you're more than welcome to visit our shop.

nc chals20.cybercastors.com 14432

## Challenge

Connecting to the server at the specified port gives us a text base shop, where we have a balance, a list of items we can buy, and the ability to sell any items we buy for the original price.

One of the items is a flag, however, the cost of this item (6000) is far greater than the amount of money we start with.

## Solution

We need to find a way of increasing the user balance to be greater than or equal to the cost of the flag.

If try buying and selling each item, we notice that the VPN item can be bought and sold as normal, except the amount doesn't decrease when sold.
With this in mind, we can buy 1 VPN and sell it an unlimited number of times until we reach the correct balance.

Although it is theoretically possible to do this manually, the VPN costs very little in comparison to the flag, and this would require far too much time.
The process can be automated using the ```socket``` python module.

## Script

```py
#!/usr/bin/python
import socket

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    hasVPN = False
    selling = False
    working = True
    done = False
    flag = ""

    while not done:
        data = s.recv(1024)
        for item in data.decode().split("\n"):
            if "Your money: " in item and not "Here's" in item:
                print(f'{item} \r', end="")
                break
        if "Your money: 6000" in data.decode():
            working = False
        if "Choice: " in data.decode():
            if not working:
                message = "5\n"
            else:
                if hasVPN and selling:
                    message = "0\n"
                    selling = False
                elif hasVPN and not selling:
                    message = "1\n"
                    selling = True
                else:
                    message = "6\n"
                    hasVPN = True
            s.sendall(message.encode())
        if "castorsCTF" in data.decode():
            print("Flag:", data.decode())
            for item in data.decode().split("\n"):
                if "castorsCTF" in item:
                    flag = item
                    break
            done = True
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14432)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()
```

## Flag

```castorsCTF{$imPl3_sTUph_3h?}```

