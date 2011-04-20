## About

Password Hashing class, inspired by phpass v0.3 http://www.openwall.com/phpass/

Unlike the original phpass implementation, this class does not fallback when a
bcrypt implementation is not available. It also uses a consistent random seed
mechanism for generating the bcrypt salt aka unlike phpass it does not use
arcane methods for getting a bunch of random bytes. It uses
openssl_random_pseudo_bytes() behind the scenes. You don't have to generate the
salt by yourself. The hash method does all the heavy lifting.

The following statements imply certain system requirements.

## System Requirements

 * PHP 5.3.0+
 * OpenSSL extension

Since all the previous versions of PHP, including 5.2.0+, reached End Of Life
status, you ought to upgrade your setup anyway, therefore the requirements
aren't that restrictive. The advantage of this implementation is the fact that
it consistently work across platforms. There are no Windows-isms or *nix-isms
in this implementation. If fact, this is hack-free from the PHP implementation
point of view.

## How to use

The usage mode is straight forward.

```PasswordHash2::hash('password');```

> returns a bcrypt hash, false on failure aka the hash is shorter than expected.
> It should not fail unless you don't have the required PHP version and OpenSSL
> extension. Raises a warning if the OpenSSL random seed is not considered to
> be crypto strong. Unless your setup is really broken, this should not occur.

```PasswordHash2::hash('password', 10);```
> you may specify the cost parameter as well. The cost parameter defaults to 8.

```PasswordHash2::check($hash, '$password');```
> returns bool. Basically this method is a crypt wrapper, added for convenience.

```PasswordHash2::test();```
> test method, added for convenience. Yells at you if you don't have the
> system requirements.