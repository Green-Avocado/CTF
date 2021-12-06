# Toy Management

## Challenge

If we visit the link we're greeted with a simple login page but no where to register.

## Solution

If we look at how the page handles logins, we can see that it is vulnerable to SQL injection.

#### challenge/database.js

```js
let stmt = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
```

We should note that the injection has to be done in the username field, as the password field is hashed first.

#### challenge/routes/index.js

```js
passhash = crypto.createHash('md5').update(password).digest('hex');
return db.loginUser(username, passhash)
```

If we use the username `' OR 1=1;-- `, we are logged in as "manager" and we see a table with some toys, names, and other data.

Let's look at how the `/api/toylist` endpoint works.

#### challenge/routes/index.js

```js
approved = 1;
if (user[0].username == 'admin') approved = 0;
return db.listToys(approved)
```

The admin sees a different list than the manager.

To log in as the admin, we can use the username `admin';-- ` and any password.
This gives us the flag.

## Flag

`HTB{1nj3cti0n_1s_in3v1t4bl3}`
