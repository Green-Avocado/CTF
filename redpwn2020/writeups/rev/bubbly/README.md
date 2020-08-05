# bubbly

## Description

dns

It never ends

nc 2020.redpwnc.tf 31039

## Solution

```c
int main(void)

{
    uint32_t i;
    int unused;
    _Bool pass;

    setbuf(stdout,(char *)0x0);
    setbuf(stdin,(char *)0x0);
    setbuf(stderr,(char *)0x0);
    puts("I hate my data structures class! Why can\'t I just sort by hand?");
    pass = false;
    while( true ) {
        __isoc99_scanf(&DAT_00102058);
        if (8 < i) break;
        nums[i] = nums[i] ^ nums[i + 1];
        nums[i + 1] = nums[i + 1] ^ nums[i];
        nums[i] = nums[i] ^ nums[i + 1];
        pass = check();
    }
    if (pass == false) {
        puts("Try again!");
    }
    else {
        puts("Well done!");
        print_flag();
    }
    return 0;
}
```

```c
_Bool check(void)

    {
    uint32_t i;
    _Bool pass;
    
    i = 0;
    while( true ) {
        if (8 < i) {
            return true;
        }
        if (nums[i + 1] < nums[i]) break;
        i = i + 1;
    }
    return false;
}
```

```c
void print_flag(void)

{
    int unused;

    system("cat flag.txt");
    return;
}
```

## Flag

```flag{4ft3r_y0u_put_u54c0_0n_y0ur_c011ege_4pp5_y0u_5t1ll_h4ve_t0_d0_th15_57uff}```

