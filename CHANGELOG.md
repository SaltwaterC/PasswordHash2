## v0.3
 * backward incompatible release. Drops some public API calls, adds some new.
 * dropped support: standard SHA2 schemes, base64 encoded hashes, short hashes, the algo(), cost(), rehash(), shorten(), expand() methods.
 * added info() method for getting the algo, cost / rounds, seed information from a hash / salt.
 * added crypt() method as crypt() wrapper for calling either the native implementation or a pure PHP implementation of the desired algo. No more failures, the algos always exist.
 * added support for my proposed SHA2 schemes that feature several improvements over the original, mainstream, schemes.
 * added exceptions as error handlers. The original v0.1 implementation didn't need them. This version does.
 * simplified a lot of the existing API as the feature creep started to pile up in v0.2.

## v0.2.3
 * adds an algo() method for determining the algo from the input hash.
 * better docs.

## v0.2.2
 * adds support for short hashes. These hashes are the shortest possible textual representation of the resulted hashes, but the form is incompatible with the crypt() scheme. However, the possibility to expand them to the crypt() scheme is implemented.
 * adds some aliases of the hash() method in order to ease the integration with IDEs while it avoids typo errors.

## v0.2.1
 * rehash() method for easier check() + hash() when adaptive hashing is intended.
 * cost() method for retrieving the cost / rounds parameter of a given hash. Also useful for implementing the adaptive hashing. With more wrapped logic, using cost() is more efficient than straight rehash().

## v0.2
 * Implements Ulrich Drepper's SHA2 based hashing scheme (SHA256 / SHA512) besides bcrypt.
 * The v0.2 implementation isn't backward compatible due to the fact that the hash is stored as base64 encoded string. It also pushes the cost parameter to the end of the hash method parameter order. The main reason for this incompatibility is the base64 encoding as the SHA2 based scheme uses 16 *bytes* of random seed for salt, not 16 *chars* as stated by the PHP's crypt documentation. Using plain ASCII chars decreases the randomness of the seed.
 * Removed the test() method. Implemented it as independent script.

## v0.1
 * Initial implementation. Features bcrypt hashing and checking.

