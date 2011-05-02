## v0.2
 * Implements Ulrich Drepper's SHA2 hashing method (SHA256 / SHA512)
 besides bcrypt.
 * The v0.2 implementation isn't backward compatible due to the fact
 that the hash is stored as base64 encoded string. It also pushes the
 cost parameter to the end of the hash method parameter order. The
 main reason for this incompatibility is the base64 encoding as the
 SHA2 based schema uses 16 *bytes* of random seed for salt, not 16
 *chars* as stated by the PHP's crypt documentation. Using plain ASCII
 chars decreases the randomness of the seed.
 * Removed the test() method. Implemented it as independent script.

## v0.1
 * Initial implementation. Features bcrypt hashing and checking.

