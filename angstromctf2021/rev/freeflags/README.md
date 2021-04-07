# FREE FLAGS!!1!!

Clam was browsing armstrongctf.com when suddenly a popup appeared saying "GET YOUR FREE FLAGS HERE!!!" along with a download. Can you fill out the survey for free flags?

Find it on the shell server at /problems/2021/free_flags or over netcat at nc shell.actf.co 21703.

Author: aplet123

## Challenge

We're given a relatively small binary file and a socket to connect to.

```c
uint64_t main(void)
{
    int32_t iVar1;
    uint64_t uVar2;
    undefined8 extraout_RDX;
    int64_t iVar3;
    char *pcVar4;
    undefined4 uVar5;
    int64_t in_FS_OFFSET;
    int64_t var_140h;
    int64_t var_120h;
    uint32_t var_118h;
    uint32_t var_114h;
    char *s1;
    int64_t var_8h;
    
    var_8h = *(int64_t *)(in_FS_OFFSET + 0x28);
    var_120h._0_4_ = 0;
    sym.imp.puts("Congratulations! You are the 1000th CTFer!!! Fill out this short survey to get FREE FLAGS!!!");
    sym.imp.puts("What number am I thinking of???");
    pcVar4 = (char *)&var_114h;
    sym.imp.__isoc99_scanf("%d", pcVar4);
    if (var_114h == 0x7a69) {
        sym.imp.puts("What two numbers am I thinking of???");
        pcVar4 = (char *)&var_118h;
        sym.imp.__isoc99_scanf("%d %d", pcVar4, (int64_t)&var_120h + 4);
        if ((var_118h + var_120h._4_4_ == 0x476) && (var_118h * var_120h._4_4_ == 0x49f59)) {
            sym.imp.puts("What animal am I thinking of???");
            sym.imp.__isoc99_scanf(" %256s", &s1);
            iVar3 = sym.imp.strcspn(&s1, 0x202d);
            *(undefined *)((int64_t)&s1 + iVar3) = 0;
            pcVar4 = "banana";
            iVar1 = sym.imp.strcmp(&s1, "banana");
            if (iVar1 == 0) {
                sym.imp.puts("Wow!!! Now I can sell your information to the Russian government!!!");
                uVar5 = 0x2156;
                sym.imp.puts("Oh yeah, here\'s the FREE FLAG:");
                sym.print_flag();
                var_120h._0_4_ = 0;
            } else {
                uVar5 = 0x20ac;
                sym.imp.puts("Wrong >:((((");
                var_120h._0_4_ = 1;
            }
        } else {
            uVar5 = 0x20ac;
            sym.imp.puts("Wrong >:((((");
            var_120h._0_4_ = 1;
        }
    } else {
        uVar5 = 0x20ac;
        sym.imp.puts("Wrong >:((((");
        var_120h._0_4_ = 1;
    }
    if (*(int64_t *)(in_FS_OFFSET + 0x28) != var_8h) {
        sym.imp.__stack_chk_fail();
        sym._init();
        iVar3 = 0;
        do {
            uVar2 = (**(code **)(segment.LOAD3 + iVar3 * 8))(uVar5, pcVar4, extraout_RDX);
            iVar3 = iVar3 + 1;
        } while (iVar3 != 1);
        return uVar2;
    }
    return (uint64_t)(uint32_t)var_120h;
}
```

## Solution

The code is fairly easy to read.
There are 3 conditions we have to satisfy to get the flag:

### Condition 1

```c
if (var_114h == 0x7a69)
```

The first condition is satisfied by entering `31337`.

### Condition 2

```c
if ((var_118h + var_120h._4_4_ == 0x476) && (var_118h * var_120h._4_4_ == 0x49f59))
```

The second condition requires 2 numbers that add to 0x476 and multiply to 0x49f59.
If we test factors of 0x49f59, we find that `419` and `723` satisfy these requirements.

### Condition 3

```c
iVar1 = sym.imp.strcmp(&s1, "banana");
if (iVar1 == 0)
```

The third condition is satisfied by entering `banana`.

### Solved

```
-> % nc shell.actf.co 21703
Congratulations! You are the 1000th CTFer!!! Fill out this short survey to get FREE FLAGS!!!
What number am I thinking of???
31337
What two numbers am I thinking of???
419 723
What animal am I thinking of???
banana
Wow!!! Now I can sell your information to the Russian government!!!
Oh yeah, here's the FREE FLAG:
actf{what_do_you_mean_bananas_arent_animals}
```

## Flag

`actf{what_do_you_mean_bananas_arent_animals}`

