# Find rbtree

## Description

Find rbtree among hundreds of people

nc find-rbtree.chal.perfect.blue 1

By: sampriti & rbtree

## Solution

Running the command in the description gives us an interactive prompt that looks something like this:

```
$ nc find-rbtree.chal.perfect.blue 1

  _____              _   _    ____          ____       ____    _____    ____    U _____ uU _____ u 
 |" ___|    ___     | \ |"|  |  _"\      U |  _"\ u U | __")u |_ " _|U |  _"\ u \| ___"|/\| ___"|/ 
U| |_  u   |_"_|   <|  \| |>/| | | |      \| |_) |/  \|  _ \/   | |   \| |_) |/  |  _|"   |  _|"   
\|  _|/     | |    U| |\  |uU| |_| |\      |  _ <     | |_) |  /| |\   |  _ <    | |___   | |___   
 |_|      U/| |\u   |_| \_|  |____/ u      |_| \_\    |____/  u |_|U   |_| \_\   |_____|  |_____|  
 )(\\,-.-,_|___|_,-.||   \\,-.|||_         //   \\_  _|| \\_  _// \\_  //   \\_  <<   >>  <<   >>  
(__)(_/ \_)-' '-(_/ (_")  (_/(__)_)       (__)  (__)(__) (__)(__) (__)(__)  (__)(__) (__)(__) (__)

STAGE 1 / 30
Generating people... (and rbtree)
=============================
  [ P E R S O N         1 ]  
Eyewear       : None
Eye color     : Hazel
Hair          : Straight
Outerwear     : Coat
T-shirt color : Red
Trousers      : Jeans
Socks color   : Gray
Shoes         : Boots
=============================
  [ P E R S O N         2 ]  
Eyewear       : None
Eye color     : Brown
Hair          : Straight
Outerwear     : Poncho
T-shirt color : Green
Trousers      : Sweatpants
Socks color   : Gray
Shoes         : Slippers
=============================
  [ P E R S O N         3 ]  
Eyewear       : Glasses
Eye color     : Blue
Hair          : Curly
Outerwear     : Hoodie
T-shirt color : Orange
Trousers      : Sweatpants
Socks color   : Gray
Shoes         : Boots
=============================
  [ P E R S O N         4 ]  
Eyewear       : None
Eye color     : Hazel
Hair          : Curly
Outerwear     : Hoodie
T-shirt color : Green
Trousers      : Leggings
Socks color   : Black
Shoes         : Sneakers
=============================
  [ P E R S O N         5 ]  
Eyewear       : Glasses
Eye color     : Blue
Hair          : Bald
Outerwear     : Hoodie
T-shirt color : Red
Trousers      : Leggings
Socks color   : White
Shoes         : Boots
=============================
Now ask me!
? >
```

Here, we can pick a category and make a guess.
The server responds with a `YES` or `NO` depending on whether rbtree, a randomly chosen person from this list, has that attribute.

We can see from the source code that we are limited to a certain number of guesses depending on the number of people in our list:

```py
cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
    cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5

    for idx, (num_people, num_ask) in enumerate(cases):
        if not stage(idx + 1, num_people, num_ask):
            print("WRONG :(")
            return
        print("You found rbtree!")
```

Some optimisation will be needed to reliably guess rbtree.

After parsing the attributes from the list, we can sort the attributes by the number of people who share that attribute.
Ideally, every question we ask reduces the pool of potential solutions by half, so we want to guess the trait thats shared by closest to half the remaining pool.
After each guess, we take the server output and purge our pool accordingly, then we recalculate the frequency of traits and repeat until we run out of guesses for the round.

Hopefully, our pool has been narrowed down to just one set of options, however, this may not always be the case.
While this method is efficient, it is not the most efficient possible, as there are cases where the guess we make results in the pool being split such that there are no efficient next guesses.
Still, the approach is close enough that we have a decent chance of finding rbtree anyways if we pick an entry from our remaining list.

While some attempts will fail, repeating this script until it succeeds still reaches a solution within a reasonable amount of time.

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

