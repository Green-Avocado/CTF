# Little Baby Rev

## Description

Author: TheEmperors

## Challenge

The binary appears to be a compiled Nim program.

### Program output:

```
-> % ./warmup 
I have a number from 1 to 10, what is it? 
1
Try again
I have a number from 1 to 10, what is it? 
2
Try again
```

### Decompiled code:

```c
void sym.NimMainModule(void)
{
    char cVar1;
    uint32_t uVar2;
    int64_t var_50h;
    char *var_48h;
    int64_t var_40h;
    char *var_38h;
    int64_t var_30h;
    int64_t var_18h;
    int64_t var_10h;
    int64_t var_8h;
     
    var_30h._0_2_ = 0;
    sym.nimRegisterGlobalMarker((int64_t)sym.TM__ijE9cayl8YPnol3rizbiT0g_2);
    sym.nimRegisterGlobalMarker((int64_t)sym.TM__ijE9cayl8YPnol3rizbiT0g_6);
    var_48h = "warmup";
    var_38h = "/root/rev/warmup.nim";
    var_40h = 0;
    var_30h._0_2_ = 0;
    sym.nimFrame_2((int64_t)&var_50h);
    var_40h = 0x24;
    var_38h = "/root/rev/warmup.nim";
    uVar2 = sym.decodeStr__R9b5IlyQjG2mcdkp9a67LGTQ((int64_t)obj.TM__ijE9cayl8YPnol3rizbiT0g_4, 0x3d211884);
    sym.asgnRef_2((int64_t)obj.answer__2bKjAtEJJ5cp19bpmXcStjQ, uVar2);
    while( true ) {
        var_40h = 0x26;
        var_38h = "/root/rev/warmup.nim";
        sym.nimZeroMem_1((int64_t)&var_8h, 8);
        var_8h = sym.decodeStr__R9b5IlyQjG2mcdkp9a67LGTQ((int64_t)obj.TM__ijE9cayl8YPnol3rizbiT0g_5, 0x3f1997cc);
        sym.echoBinSafe((int64_t)&var_8h, 1);
        sym.asgnRef_2((int64_t)obj.guess__62AlRyOQv9cCViqvgI14ssA, 0);
        var_40h = 0x27;
        var_38h = "/root/rev/warmup.nim";
        uVar2 = sym.readLine__IfmAdseskhTUnfEYpOo5fA(_reloc.stdin);
        sym.asgnRef_2((int64_t)obj.guess__62AlRyOQv9cCViqvgI14ssA, uVar2);
        var_40h = 0x29;
        var_38h = "/root/rev/warmup.nim";
        cVar1 = sym.eqStrings((uint32_t)_obj.guess__62AlRyOQv9cCViqvgI14ssA, 
                              (uint32_t)_obj.answer__2bKjAtEJJ5cp19bpmXcStjQ);
        if (cVar1 != '\0') break;
        var_40h = 0x2a;
        var_38h = "/root/rev/warmup.nim";
        sym.nimZeroMem_1((int64_t)&var_10h, 8);
        var_10h = sym.decodeStr__R9b5IlyQjG2mcdkp9a67LGTQ((int64_t)obj.TM__ijE9cayl8YPnol3rizbiT0g_7, 0x2149f624);
        sym.echoBinSafe((int64_t)&var_10h, 1);
    }
    var_40h = 0x2c;
    var_38h = "/root/rev/warmup.nim";
    sym.nimZeroMem_1((int64_t)&var_18h, 8);
    var_18h = sym.decodeStr__R9b5IlyQjG2mcdkp9a67LGTQ((int64_t)obj.TM__ijE9cayl8YPnol3rizbiT0g_8, 0xb6e7aac);
    sym.echoBinSafe((int64_t)&var_18h, 1);
    var_40h = 0x32;
    var_38h = "/root/rev/warmup.nim";
    sym.popFrame_2();
    return;
}

void sym.NimMain(void)
{
    int64_t var_8h;
    
    sym.PreMain();
    var_8h = (int64_t)sym.NimMainInner;
    sym.initStackBottomWith((int64_t)&var_8h);
    (*(code *)var_8h)();
    return;
}

undefined8 main(undefined8 argc, char **argv, char **envp)
{
    char **var_18h;
    char **var_10h;
    int64_t var_4h;
    
    _obj.cmdCount = (undefined4)argc;
    _obj.cmdLine = argv;
    _obj.gEnv = envp;
    sym.NimMain();
    return _obj.nim_program_result;
}
```

## Solution

## Flag

