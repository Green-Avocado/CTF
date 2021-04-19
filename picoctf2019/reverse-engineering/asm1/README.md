# asm1 - Points: 200

## Description

What does asm1(0x1f3) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. Source located in the directory at /problems/asm1_2_4ced82d316c06cd3a46ba3bda9f6c144.

## Solution

We're given some assembly code and an argument.
Recall that the call stack looks something like this:

```
ebp-? Local Variables
ebp+0 EBP
ebp+4 Return Address
ebp+8 Arguments
```

Therefore, we know that the argument will be located at ```ebp+8``` in the code below.

```asm
asm1:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	cmp    DWORD PTR [ebp+0x8],0x767
	<+10>:	jg     0x512 <asm1+37>
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x1f3
	<+19>:	jne    0x50a <asm1+29>
	<+21>:	mov    eax,DWORD PTR [ebp+0x8]
	<+24>:	add    eax,0xb
	<+27>:	jmp    0x529 <asm1+60>
	<+29>:	mov    eax,DWORD PTR [ebp+0x8]
	<+32>:	sub    eax,0xb
	<+35>:	jmp    0x529 <asm1+60>
	<+37>:	cmp    DWORD PTR [ebp+0x8],0xcde
	<+44>:	jne    0x523 <asm1+54>
	<+46>:	mov    eax,DWORD PTR [ebp+0x8]
	<+49>:	sub    eax,0xb
	<+52>:	jmp    0x529 <asm1+60>
	<+54>:	mov    eax,DWORD PTR [ebp+0x8]
	<+57>:	add    eax,0xb
	<+60>:	pop    ebp
	<+61>:	ret
```

We can read through this relatively simple bit of code line by line.

The first two lines are generic instructions responsible for creating the call stack:

```asm
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
```

We then compare the argument to 0x767 and jump to ```<asm1+37>``` if the argument is greater:

```asm
	<+10>:	jg     0x512 <asm1+37>
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x1f3
```

As 0x1f3 < 0x737, we do not make the jump and move on to the next instruction.

Here, we compare the argument to 0x1f3 and jump to ```<asm1+29>``` if the two are not equal:

```asm
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x1f3
	<+19>:	jne    0x50a <asm1+29>
```

The argument is 0x1f3, so this jump does not succeed.

We move onto the next instruction and move our argument into the eax register, giving it a value of 0x1f3.
Then, we add 0xb to the register, changing the value of 0x1fe.
Lastly, we make an unconditional jump to ```<asm1+60>```.

```asm
	<+21>:	mov    eax,DWORD PTR [ebp+0x8]
	<+24>:	add    eax,0xb
	<+27>:	jmp    0x529 <asm1+60>
```

This next address is where the ```pop``` and ```ret``` instructions are, effectively ending the function call and returning to the caller.

```asm
	<+60>:	pop    ebp
	<+61>:	ret
```

As the last value stored in eax was 0x1f3, this is our return value.

## Flag

```0x1f3```

