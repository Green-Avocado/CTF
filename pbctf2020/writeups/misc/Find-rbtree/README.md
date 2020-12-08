# Find rbtree

## Description

Find rbtree among hundreds of people

nc find-rbtree.chal.perfect.blue 1

By: sampriti & rbtree

## Solution

## Script

```py
#!/usr/bin/env python3

from pwn import *
from collections import Counter
import operator

#p = process("./challenge.py")
p = remote("find-rbtree.chal.perfect.blue", 1)

categories = [
        "Eyewear",
        "Eye color",
        "Hair",
        "Outerwear",
        "T-shirt color",
        "Trousers",
        "Socks color",
        "Shoes"
        ]

def getGuess(people):
    guesses = []

    for i in people:
        for n in range(8):
            guesses.append(categories[n] + '/' + i[n].decode())

    a = dict(Counter(guesses))
    
    for i, j in a.items():
        a[i] = abs(2 * j - len(people))

    b = min(a.items(), key=operator.itemgetter(1))[0]

    guess = b.split('/')
    print(guess)

    return guess



def purge(people, guess, ans):
    trait = categories.index(guess[0])
    newpeople = []

    for i in people:
        testTrait = i[trait].decode()
        if (testTrait == guess[1] and ans == "YES\n") or (testTrait != guess[1] and ans != "YES\n"):
            newpeople.append(i)

    return newpeople



def stage(num_stage, num_people, num_ask):
    people = []

    for i in range(num_people):
        p.recvuntil("Eyewear       : ")
        EW = p.recvline()[:-1]

        p.recvuntil("Eye color     : ")
        EC = p.recvline()[:-1]

        p.recvuntil("Hair          : ")
        HA = p.recvline()[:-1]

        p.recvuntil("Outerwear     : ")
        OW = p.recvline()[:-1]

        p.recvuntil("T-shirt color : ")
        TC = p.recvline()[:-1]

        p.recvuntil("Trousers      : ")
        TR = p.recvline()[:-1]

        p.recvuntil("Socks color   : ")
        SC = p.recvline()[:-1]

        p.recvuntil("Shoes         : ")
        SH = p.recvline()[:-1]

        people.append([EW, EC, HA, OW, TC, TR, SC, SH])

    for i in range(num_ask):
        guess = getGuess(people)

        p.recvuntil("? > ")
        p.sendline(guess[0])

        p.recvuntil("! > ")
        p.sendline(guess[1])

        ans = p.recvline().decode()

        print(ans)

        people = purge(people, guess, ans)

    output = []
    print(people[0])

    for i in people[0]:
        output.append(i.decode())

    p.recvuntil("rbtree > ")
    p.sendline(' '.join(output))
    ans = p.recvline()

    print(ans)



def main():
    cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
    cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5

    for idx, (num_people, num_ask) in enumerate(cases):
        print("\n\n===== STAGE {} =====\n\n".format(idx + 1))
        stage(idx + 1, num_people, num_ask)

    p.interactive();



if __name__ == "__main__":
    main()
    exit(0)
```

## Flag
`pbctf{rbtree_is_not_bald,_and_does_not_wear_poncho}`

