# rm -rf'er

## Challenge

We ssh into a server where `rm -rf /*` has been executed as root.

We have an active `tcsh` session, but no binaries.

The objective is to recover the flag from the filesystem using only built-in shell commands.

## Solution

We first have to locate the flag file.

`ls` does not exist, however, `tcsh` has a built-in `ls-F` command.

```sh
buildbox:/home/rmrfer# cd /
buildbox:/# ls-F *
dev:
console% full%    mqueue/  null%    pts/     random%  shm/     tty%     urandom% zero%

etc:
apt/         ctf/         hostname     hosts        pam.d/       resolv.conf  security/

proc:
1/                 driver/            keys%              mtrr               sys/
acpi/              dynamic_debug/     kmsg               net@               sysrq-trigger
bootconfig         execdomains        kpagecgroup        pagetypeinfo       sysvipc/
buddyinfo          fb                 kpagecount         partitions         thread-self@
bus/               filesystems        kpageflags         pressure/          timer_list%
cgroups            fs/                loadavg            sched_debug%       tty/
cmdline            interrupts         locks              schedstat          uptime
consoles           iomem              mdstat             scsi/              version
cpuinfo            ioports            meminfo            self@              version_signature
crypto             irq/               misc               slabinfo           vmallocinfo
devices            kallsyms           modules            softirqs           vmstat
diskstats          kcore%             mounts@            stat               zoneinfo
dma                key-users          mpt/               swaps

sys:
block/      class/      devices/    fs/         kernel/     power/
bus/        dev/        firmware/   hypervisor/ module/

usr:
lib/   local/ sbin/  share/

var:
lib/
```

We can see in the `/etc/` directory that there is a `ctf/` directory.

```sh
buildbox:/# ls-F /etc/*
/etc/apt:

/etc/ctf:
Dockerfile  flag.txt    run.sh*

/etc/hostname  /etc/hosts

/etc/pam.d:

/etc/resolv.conf

/etc/security:
```

So the flag is located in `/etc/ctf/flag.txt`.

Using the built-in `echo` and pipes, we can write files of our own.
Using `source`, we can execute the contents of these files as `tcsh` scripts.

We can make a shell script that echos stdin as follows:

```sh
set line=($<)
echo $line
```

Which can be written using:

```sh
echo "set line=("`echo '$'`"<)" > /a.txt; echo "echo "`echo '$'`"line" >> /a.txt
```

To run the file, we `source /a.txt`.
To pipe the flag contents into the process, we `source /a.txt < /etc/ctf/flag.txt`

## Payload

```sh
echo "set line=("`echo '$'`"<)" > /a.txt; echo "echo "`echo '$'`"line" >> /a.txt; source /a.txt < /etc/ctf/flag.txt
```

## Flag

`cybrics{TCSHizzl3_Ma_N1zzl3}`

