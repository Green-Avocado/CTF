# Infiltration

## Challenge

We are given a binary which communicates with a given server.

We have to reverse the binary to find the flag.

## Solution

If we debug the program, we can see that it makes some initial requests to the server, then reads up to 0x400 characters before exiting.

After this read, we can see the flag on the stack.

Alternatively, we can patch the binary so it prints the flag instead of the usual message.

`wx 89e790909090 @ 0x0000131a`

## Diff

```
--- 0x0000131a  8d3de80c0000
- lea edi, [rip + 0xce8]
+++ 0x0000131a  89e790909090
+ mov edi, esp
+ nop
+ nop
+ nop
+ nop
```

## Flag

`HTB{n0t_qu1t3_s0_0p4qu3}`
