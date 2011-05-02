## About

Password Hashing class, inspired by phpass v0.3
http://www.openwall.com/phpass/

Unlike the original phpass implementation, this class does not
fallback when the desired hashing method is unavailable. It also uses
a consistent random seed mechanism for generating the salt aka unlike
phpass it does not use arcane methods for getting a bunch of random
bytes. It uses openssl_random_pseudo_bytes() behind the scenes. You
don't have to generate the salt by yourself. The hash method does all
the heavy lifting as well as the boundary checking for the cost
(rounds) parameter. Fails gracefully by returning FALSE if the algo
is missing or the resulted hash length is unexpected.

The following statements imply certain system requirements.

## System Requirements

 * PHP 5.3.0+ (bcrypt) or PHP 5.3.2+ (all methods)
 * OpenSSL extension

Since all the previous versions of PHP, including 5.2.0+, reached
End Of Life status, you ought to upgrade your setup anyway, therefore
the requirements aren't that restrictive. The advantage of this
implementation is the fact that it consistently works across
platforms. There are no Windows-isms or *nix-isms in this
implementation. In fact, this is hack-free from the PHP implementation
point of view.

## How to use

The usage mode is straight forward.

PasswordHash2::hash('password');

> returns a bcrypt hash, FALSE on failure aka the hash is shorter than
> expected or the desired algo is unavailable. It should not fail
> unless you don't have the required PHP version and the OpenSSL
> extension. Raises a warning if the OpenSSL random seed is not
> considered to be crypto strong. Unless your setup is really broken,
> this should not occur. The returned hash is base64 encoded due to
> the fact that the SHA2-based scheme uses 16 bytes of random seed for
> salt, *NOT* 16 chars as stated by PHP's crypt() documentation. The
> base64 encoding makes it ASCII friendly at the cost of 33% more used
> space for storing a hash.

PasswordHash2::hash('password', 'bcrypt');

> This call is equivalent with the above call. The second ($algo)
> parameter defaults to bcrypt. Other accepted values: sha256, sha512.
> For the SHA2-based scheme it doesn't use the plain SHA2 hasing
> algos, but the Ulrich Drepper's scheme (check the source for
> details).

PasswordHash2::hash('password', 'bcrypt', 8);

> you may specify the cost parameter as well. The cost parameter
> defaults to 8 for bcrypt. For bcrypt, the cost parameter is
> truncated to the nearest limit of 4 and 31. The SHA2 method
> truncates the value to nearest limit of 1000 and 999999999.

PasswordHash2::check($hash, $password);

> returns bool.

php test.php

> test script, added for convenience. Yells at you if you don't have
> the system requirements.

