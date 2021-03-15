# ropes

## Description

NotDeGhost

It's not just a string, it's a rope!

## Solution

We're given a binary file with an unknown format.

Printing the contents of the binary, one piece of text immediately stands out:

```
$ cat ropes

������� H__PAGEZERO�__TEXT__text__TEXT�i��__stubs__TEXT��__stub_helper__TEXT,.,�__cstring__TEXTZ^Z__unwind_info__TEXT�H��__DATA__nl_symbol_ptr__DATA__la_symbol_ptr__DATAH__LINKEDIT  H"�   (H 0� !H
                                       P�
                                          /usr/lib/dyldc�z���81��̝N�-2

�*(��
     8��/usr/lib/libSystem.B.dylib&x)� UH��H�� �E�H�=���MH�=�H�u��E���D�}�7�E��H�=}�"H�=��E���E�E�H�� ]Ð�%��%��%�L��AS�%��h�����h�����h������Give me a magic number: %dFirst part is: flag{r0pes_ar3_Second part is: just_l0ng_str1ngs}�44�4
                                                                               <FP"S@dyld_stub_binderQr�r@_printf�r@_puts�r @_scanf�__mh_execute_header!main%���$*1@ __mh_execute_header_main_printf_puts_scanfdyld_stub_binder[
```

```First part is: flag{r0pes_ar3_```

and

```Second part is: just_l0ng_str1ngs}```

Concatonating the two produces our flag.

## Flag

```flag{r0pes_ar3_just_l0ng_str1ngs}```

