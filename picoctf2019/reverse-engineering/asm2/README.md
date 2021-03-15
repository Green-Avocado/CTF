# asm2 - Points: 250

## Description

What does asm2(0x10,0x18) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](./test.S) located in the directory at /problems/asm2_0_a50f0b17a6f50b50a53305ebd71af535.

## Solution

This challenge is very similar to asm1, however, this time we have a second argument as well as local variables to keep in mind.

Arguments are stored as DWORDs, or 32 bits, regardless of their value and the fact that they only use 16 bits each in this example.
Therefore, the first argument includes ```ebp+0x8``` through ```ebp+0xb```, as with asm1.
The second argument includes ```ebp+0xc``` through ```ebp+0xf```.

Local variables can be stored anywhere between ```esp``` and ```ebp```, hence why this example includes an instruction to subtract 0x10 from ```esp``` to make room for local variables..

```asm
asm2:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	sub    esp,0x10
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]
	<+9>:	mov    DWORD PTR [ebp-0x4],eax
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
	<+18>:	jmp    0x50c <asm2+31>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1
	<+24>:	add    DWORD PTR [ebp-0x8],0xcb
	<+31>:	cmp    DWORD PTR [ebp-0x8],0xb693
	<+38>:	jle    0x501 <asm2+20>
	<+40>:	mov    eax,DWORD PTR [ebp-0x4]
	<+43>:	leave
	<+44>:	ret
```

The first three instructions are responsible for creating the call stack.

The second argument is then stored in eax and transfered to a local variable at ```ebp-0x4```.

```asm
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]
	<+9>:	mov    DWORD PTR [ebp-0x4],eax
```

The first argument is stored in eax and transfered to a local variable at ```ebp-0x8```.

```asm
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
```

We make a jump to ```<asm2+31>```.
The instruction at this address compares the value at ```ebp-0x8```, our first argument, to 0xb693.
If the variable is less than this value, we jump back to ```<asm2+20>``` which has instructions to add 0x1 to the value at ```ebp-0x4```, and add 0xcb to the value at ```ebp-0x8```.
Afterwards, it reaches the compare instruction at ```<asm2+31>``` again and repeats until the value at ```ebp-0x8``` is greater than 0xb693.

```asm
	<+18>:	jmp    0x50c <asm2+31>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1
	<+24>:	add    DWORD PTR [ebp-0x8],0xcb
	<+31>:	cmp    DWORD PTR [ebp-0x8],0xb693
	<+38>:	jle    0x501 <asm2+20>
```

This is essentially a while loop, and can be written in c as follows:

```c
asm2(uint32_t arg1, uint32_t arg2)
{
    uint32_t local1;
    uint32_t local2;

    local1 = arg2;
    local2 = arg1;

    while(local2 < 0xb693)
    {
        local1 += 0x1;
        local2 += 0xcb;
    }

    return local1
}
```

We first need to determine the number of times this loop is executed.
We can determine this by subtracting the initial value of this variable, 0x10, from the value we are comparing against, 0xb693, then dividing by the increment, 0xcb.

Python is useful when performing calculations using hexadecimal values:

```py
>>> hex(0xb693 - 0x10)
'0xb683'
>>> import math; math.ceil(0xb683 / 0xcb)
231
```

We can see that the loop will execute 231 times, which means that we will be adding 0x1 * 231 to the variable at ```ebp-04```.

```py
>>> 0x18 + 231
255
>>> hex(0x18 + 231)
'0xff'
```

Once the loop is finished, we move the value at ```ebp-0x4```, which is 0xff, into the ```eax``` register and return this value.

```asm
	<+40>:	mov    eax,DWORD PTR [ebp-0x4]
	<+43>:	leave
	<+44>:	ret
```

## Flag

```0xff```

