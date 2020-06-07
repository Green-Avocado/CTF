# Flag-Gods

The prompt tells us that we need to calculate hamming distances to complete the challenge.
For each trial, we're given a plain-text string and a hexadecimal string, and we need to calculate the hamming distance between the two within a very limited amount of time.
After a certain number of trials, we are given the flag.

## Solution

Calculating hamming distance can be simple, given two binary sequences represented as strings.
If they are equal in length, we can loop through each character and compare it to the corresponding character in the other string.
From here, calculating hamming distance is simply a matter of adding 1 to a variable for each pair that is different.
This is the approach I went with due to clarity in code.
An alternative would be to xor the strings and find the sum of the digits.

The fact that both strings in different formats presents a slight challenge.
To suit our solution, they can both be converted to a series of ```1```s and ```0```s.

For the hexadecimal string, the simplest method seemed to be a dictionary, matching each of the 16 values the a corresponding 4-bit string.

For the plain-text string, I converted each character to a numberic value using ```ord()```.
I then formatted this value as binary using the built-in ```format()``` function.
Each value was set at a length of 8 using ```zfill()```, so that the lengths would not differ.

The ```hamming2()``` function looped through each character and returned a value equal to the number of different characters in these binary sequences.

Data was received from and sent to the server using the ```socket``` python module.

## Script

```py
#!/usr/bin/python
import socket

def hamming2(s1, s2):
    assert len(s1) == len(s2)
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))

def processStrings(s1, s2):
    hex2bin_map = {
    "0":"0000",
    "1":"0001",
    "2":"0010",
    "3":"0011",
    "4":"0100",
    "5":"0101",
    "6":"0110",
    "7":"0111",
    "8":"1000",
    "9":"1001",
    "a":"1010",
    "b":"1011",
    "c":"1100",
    "d":"1101",
    "e":"1110",
    "f":"1111",
    }
    binary1 = ''.join(hex2bin_map[i] for i in s1)
    binary2 = ''.join(format(ord(i),'b').zfill(8) for i in s2)

    return hamming2(binary1,binary2)

def netcat(hostname, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))

    done = False
    transmit = ""
    receive = ""
    flag = ""

    while not done:
        data = s.recv(1024).decode()
        if "<enter>" in data:
            s.sendall("\n".encode())
        else:
            for item in data.split("\n"):
                if "calibrated" in item:
                    print(f'{item} \r', end="")
                elif "Transmitted message: " in item:
                    transmit = item[len("Transmitted message: "):]
                elif "Received message: " in item:
                    receive = item[len("Received message: "):]
                elif "Enter hamming distance:" in item:
                    message = str(processStrings(receive, transmit)) + "\n"
                    s.sendall(message.encode())
                elif "castorsCTF" in item:
                    flag = item.split()[-1]
                    print("\n" + flag)
                    done = True
                    break
    print("Connection closed.")
    s.shutdown(socket.SHUT_WR)
    s.close()
    return flag

flagFileContents = netcat("chals20.cybercastors.com", 14431)

f = open("flag.txt", "w")
f.write(flagFileContents)
f.close()
```

Flag: ```castorsCTF{c0mmun1ng_w17h_7h3_f14g_g0d5}```

