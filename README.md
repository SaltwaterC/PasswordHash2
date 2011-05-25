## About

Password Hashing class, inspired by phpass v0.3
http://www.openwall.com/phpass/

Unlike the original phpass implementation, this class does not fallback when the
desired hashing method is unavailable. It also uses a consistent random seed
mechanism for generating the salt aka unlike phpass it does not use arcane
methods for getting a bunch of random bytes. It uses
openssl_random_pseudo_bytes() behind the scenes. You don't have to generate the
salt by yourself. The hash method does all the heavy lifting as well as the
boundary checking for the cost (rounds) parameter. Fails gracefully by returning
FALSE if the algo is missing or the resulted hash length is unexpected. Since
v0.2 this implementation isn't compatible with the hashes generated by phpass
and crypt() schemes as it stores the string as base64 encoded due to the
implementation of the SHA2-based scheme with 16 bytes of random seed for salt.

For more details over the implemented crypt() schemes, follow these links:

 - http://en.wikipedia.org/wiki/Crypt_%28Unix%29#Blowfish-based_scheme
 - http://en.wikipedia.org/wiki/Crypt_%28Unix%29#SHA-based_scheme

The previous statements imply certain system requirements.

## System Requirements

 * PHP 5.3.0+ (bcrypt) or PHP 5.3.2+ (all methods)
 * OpenSSL extension

This implementation works consistently across platforms. There are no
Windows-isms or *nix-isms in this implementation. In fact, this is hack-free
from the PHP implementation point of view.

## How to use

The usage mode is straight forward.

PasswordHash2::hash('password');

> Returns a bcrypt hash, FALSE on failure aka the hash is shorter than expected
> or the desired algo is unavailable. It should not fail unless you don't have
> the required PHP version and the OpenSSL extension. Raises an E_USER_WARNING
> if the OpenSSL random seed is not considered to be crypto strong. Unless your
> setup is really broken, this should not occur. The returned hash is base64
> encoded due to the fact that the SHA2-based scheme uses 16 bytes of random
> seed for salt, *NOT* 16 chars as stated by PHP's crypt() documentation. The
> base64 encoding makes it ASCII friendly at the cost of 33% more used space for
> storing a hash.

PasswordHash2::hash('password', 'bcrypt');

> This call is equivalent with the above call. The second ($algo) parameter
> defaults to bcrypt. Other accepted values: sha256, sha512. For the SHA2-based
> scheme it doesn't use the plain SHA2 hasing algos, but the Ulrich Drepper's
> scheme. The Wikipedia article linked above explains the implementation
> details.

PasswordHash2::hash('password', 'bcrypt', 8);

> You may specify the cost parameter as well. The cost parameter defaults to 8
> for bcrypt. For bcrypt, the cost parameter is truncated to the nearest limit
> of 4 and 31. The SHA2 method truncates the value to nearest limit of 1000 and
> 999999999. PHP's crypt() documentation,
> http://ua.php.net/manual/en/function.crypt.php provides you all the details
> about the cost parameter.

PasswordHash2::check($password, $hash);

> Returns bool.

PasswordHash2::rehash($password, $hash, $algo, $cost);

> Wrapper for check() and hash() in order to ease the implementation of adaptive
> hashing. May replace check() while the returned value, if it's a string, not
> FALSE, it may be saved to the database. However, this method for changing the
> existing hashes with hashes that have higher cost values is not efficient, but
> easier to implement than wrapping your own logic.

PasswordHash::cost($hash);

> Returns the cost parameter for a given hash. May be used for implementing
> resource efficient methods for adaptive hashing instead of using rehash()
> which comes with added overhead. You have to wrap your own logic over the
> PasswordHash2 API such as: hash() a new password if the cost() value of a given
> $hash is different than the defined default $cost. Unlike rehash(), it reduces
> the number of hash() calls as well as the number of writes to the database.

php test.php

> Test script, added for convenience. Yells at you if you don't have the system
> requirements.

