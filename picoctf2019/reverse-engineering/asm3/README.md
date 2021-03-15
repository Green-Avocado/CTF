# asm3 - Points: 300

## description

What does asm3(0xc4bd37e3,0xf516e15e,0xeea4f333) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](./test.S) located in the directory at /problems/asm3_4_c89016e12b8f3cac92a2e637c03f6139.

## solution

In order to understand this code, we need to understand how the ```eax``` register is structured.
The register is subdivided as follows:

```
|                                                            |
|   --------        --------       --------      --------    |
|                                                            |
|                        EAX (32 bits)                       |
|                                                            |
|                              |                             |
|                              |         AX (16 bits)        |
|                              |                             |
|                              |              |              |
|                              | AH (8 bits)  | AL (8 bits)  |
|                              |              |              |
```

Additionally, there are a few new instructions in this challenge:

 - XOR

Compares two values of equal length in binary.
If two values at the same index are equal (i.e. both ```0``` or both ```1```), the resulting value at that index is ```0```.
If the values are different, the resulting value at that index is ```1```.

e.g. ```xor f0, aa```

```
11110000
10101010
--------
01011010
```

 - SHL

Performs a bitwise shift towards the left on the first operand.
The amount by which the first argument is shifted depends on the value of the second operand.

e.g. ```shl eax, 0x3 ; where eax contains 10101010```

```
10101010
     0x3
--------
01010000
```

 - NOP

Performs no operation, proceeds to the next instruction.

```asm
asm3:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	xor    eax,eax
	<+5>:	mov    ah,BYTE PTR [ebp+0x9]
	<+8>:	shl    ax,0x10
	<+12>:	sub    al,BYTE PTR [ebp+0xd]
	<+15>:	add    ah,BYTE PTR [ebp+0xe]
	<+18>:	xor    ax,WORD PTR [ebp+0x10]
	<+22>:	nop
	<+23>:	pop    ebp
	<+24>:	ret
```

We can see that the function ```xor```s ```eax``` with itself.
This essentially clears the register, setting every bit to ```0```.

It moved the byte at ```ebp+0x9``` to the ```ah``` register, then performs a bitwise shift on the ```ax``` register, 16 bits to the left.
Recall that the ```ah``` register is part of the ```ax``` register, and that the ```ax``` register is only 16 bits.
This ```shl``` instruction will essentially clear the register as well.

We subtract the value at ```ebp+0xe``` from the ```al``` register.
The ```al``` register is 0, and the value at ```ebp+0xd``` is 0xe1 (second argument starts at ```ebp+0xc```, while ```ebp+0xd``` is the second byte of this argument).
The subtraction equation looks something like this:

```
  00000000
- 11100001
----------
  ????????
```

To perform this operation, the program carries a 1 and sets the carry flag to 1 to indicate this.

```
  100000000
-  11100001
-----------
   00011111
```

This value, 0xf1, is stored in the ```al``` register.

Next we add the byte at ```ebp+0xe``` to the ```ah``` register.
This byte is the third byte of the second argument, which is 0x16.

Since the ```ah``` register was empty, this is the same as moving the value into the register.

The ```ax``` register now contains 0x161f.

The next step is to ```xor``` this value with the WORD at ```ebp+0x10```.

ebp+0x10 is the first address of the third argument, 0xeea4f333.
Since these arguments are stored in little endian, the first two bytes are going to be 0x33 and 0xf3.
The value of ```WORD PTR [ebp+0x10]``` is therefore 0xf333.

We can use python to perform the ```xor``` operation:

```py
>>> hex(0x161f ^ 0xf333)
'0xe52c'
```

As we can see, 0xe52c will be stored in the ```ax``` register when this is finished.

The next instruction is a ```nop```, which does nothing, and we can move on.
Here the function returns to the caller, so the return value will be whatever is stored in the ```eax``` register.
As the ```ax``` register is the less significant part of ```eax```, and the other bits are zeroed, the return value is equal to the value of the ```ax``` register.

Flag: ```0xe52c```

