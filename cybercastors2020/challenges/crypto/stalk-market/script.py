#!/usr/bin/python
import socket
from random import seed, randint

def gen_price():
    r = randint(1, 100)
    if   r >= 99: price = randint(500, 600)
    elif r >= 95: price = randint(450, 500)
    elif r >= 90: price = randint(400, 450)
    elif r >= 85: price = randint(350, 400)
    elif r >= 80: price = randint(300, 350)
    elif r >= 75: price = randint(250, 300)
    elif r >=  0: price = randint( 20, 250)
    return price

def bruteforce(value, cipher):
    testSeed = 0;
    while True:
        seed(testSeed)
        if(gen_price() == value)

