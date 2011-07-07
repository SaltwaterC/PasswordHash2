<?php
/**
 * Portable password hashing framework for PHP.
 * 
 * Implements:
 * 
 * - the CRYPT_BLOWFISH (bcrypt) scheme
 * - my variation of CRYPT_SHA256 and CRYPT_SHA512 that borrows some concepts
 *   from bcrypt to the SHA2 schemes in order to make them more friendly
 * 
 * @link http://en.wikipedia.org/wiki/Crypt_%28Unix%29#Blowfish-based_scheme
 * @link http://en.wikipedia.org/wiki/Crypt_%28Unix%29#SHA-based_scheme
 * @link https://github.com/SaltwaterC/PasswordHash2/wiki/Proposed-SHA2-crypt%28%29-schemes
 * 
 * @author Stefan Rusu
 * @license New BSD
 * @version 0.3-dev
 */
class PasswordHash2 {
	const bcrypt = 'bcrypt';
	const sha256 = 'sha256';
	const sha512 = 'sha512';
	/**
	 * The errors thrown by the framework. Numbering starts at 1 in order to
	 * make possible their usage as exit codes.
	 */
	static $error = array(
		1 => 'invalid resulted hash length',
		2 => 'invalid hash / salt',
		3 => 'invalid algo',
	);
	/**
	 * Maps the lenght of the resulting hash. Since the SHA2 based scheme has
	 * a variable length, the length value is pushed to the map when the rounds
	 * number is known. It also maps the algorithm prefixes for the crypt()
	 * scheme.
	 */
	protected static $map = array(
		self::bcrypt => array(
			'prefix'     => '$2a$',
			'length'     => 60,
		),
		self::sha256 => array(
			'prefix'     => '$5a$',
			'min_length' => 75,
		),
		self::sha512 => array(
			'prefix'     => '$6a$',
			'min_length' => 118,
		),
	);
	// The Public API
	/**
	 * Computes a bcrypt hash of $password using $algo with $cost value. May
	 * enable the native flag to use the native crypt() method.
	 * @param string $password
	 * @param string $algo
	 * @param int $cost
	 * @param bool $native
	 * @return mixed
	 */
	static function hash($password, $algo = self::bcrypt, $cost = 8, $native = FALSE)
	{
		$hash = self::crypt($password, self::salt($algo, $cost), $native);
		if (strlen($hash) === self::$map[$algo]['length'])
		{
			return $hash;
		}
		throw new Exception(self::$error[1], 1); // invalid resulted hash length
	}
	/**
	 * crypt() wrapper for supporting addition of pure PHP algos. Hopefully one
	 * day this will be gone.
	 * @param string $password
	 * @param string $salt
	 * @param bool $native
	 * @return string
	 */
	static function crypt($password, $salt, $native = FALSE)
	{
		$info = self::info($salt);
		switch ($info['algo'])
		{
			case self::bcrypt:
				if ($native AND CRYPT_BLOWFISH === 1)
				{
					return crypt($password, $salt);
				}
				else
				{
					return CryptPHP::bcrypt($password, $info['seed'], $info['cost']);
				}
			break;
			case self::sha256:
				return CryptPHP::sha256($password, $info['seed'], $info['cost']);
			break;
			case self::sha512:
				return CryptPHP::sha512($password, $info['seed'], $info['cost']);
			break;
		}
	}
	/**
	 * Checks a $password against a $hash.
	 * @param string $password
	 * @param string $hash
	 * @return bool
	 */
	static function check($password, $hash)
	{
		return (self::crypt($password, $hash) === $hash);
	}
		/**
	 * Alias for hash + bcrypt.
	 * @param string $password
	 * @param int $cost
	 * @param bool $native
	 * @return mixed
	 */
	static function bcrypt($password, $cost = 8, $native = FALSE)
	{
		return self::hash($password, self::bcrypt, $cost, $native);
	}
	/**
	 * Alias for hash + sha256.
	 * @param string $password
	 * @param int $rounds
	 * @param bool $native
	 * @return mixed
	 */
	static function sha256($password, $rounds = 5000, $native = FALSE)
	{
		return self::hash($password, self::sha256, $rounds, $native);
	}
	/**
	 * Alias for hash + sha512.
	 * @param string $password
	 * @param int $rounds
	 * @param bool $native
	 * @return mixed
	 */
	static function sha512($password, $rounds = 5000, $native = FALSE)
	{
		return self::hash($password, self::sha512, $rounds, $native);
	}
	/**
	 * Returns the info about an input $hash / $salt
	 * @param string $hash
	 * @return array
	 */
	static function info($hash)
	{
		$map = array(
			'2a' => self::bcrypt,
			'5a' => self::sha256,
			'6a' => self::sha512,
		);
		$hash = explode('$', $hash);
		if ( ! isset($hash[1]) OR ! isset($hash[2]) OR ! isset($hash[3]))
		{
			throw new Exception(self::$error[2], 2); // invalid hash / salt
		}
		if ( ! isset($map[$hash[1]]))
		{
			throw new Exception(self::$error[3], 3); // invalid algo
		}
		return array(
			'algo' => $map[$hash[1]],
			'cost' => (int) $hash[2],
			'seed' => $hash[3],
		);
	}
	// The Private API
	/**
	 * Random seed generator for the salt.
	 * @return string
	 */
	protected static function seed()
	{
		$seed = openssl_random_pseudo_bytes(16, $crypto_strong);
		if ($crypto_strong !== TRUE)
		{
			trigger_error('The random bytes generator isn\'t "cryptographically strong". An '.
				'update to the PHP stack and / or OpenSSL is advisable.', E_USER_WARNING);
		}
		$seed = base64_encode($seed);
		$seed = substr($seed, 0, 22);
		return str_replace('+', '.', $seed);
	}
	/**
	 * Generates the $salt for $algo with $cost.
	 * @param string $algo
	 * @param int $cost
	 * @return string
	 */
	protected static function salt($algo, $cost)
	{
		$cost = (int) $cost;
		$seed = self::seed();
		switch ($algo)
		{
			case self::bcrypt:
				if ($cost < 4)
				{
					$cost = 4;
				}
				if ($cost > 31)
				{
					$cost = 31;
				}
				return self::$map[$algo]['prefix'].self::bcrypt_format_cost($cost).'$'.$seed;
			break;
			case self::sha256:
			case self::sha512:
				if ($cost < 1000)
				{
					$cost = 1000;
				}
				if ($cost > 999999999)
				{
					$cost = 999999999;
				}
				$length = strlen((string) $cost) - 4;
				$length = self::$map[$algo]['min_length'] + $length;
				self::$map[$algo]['length'] = $length;
				return self::$map[$algo]['prefix'].$cost.'$'.$seed.'$';
			break;
		}
	}
	/**
	 * Returns the zero padded cost parameter for bcrypt.
	 * @param int $cost
	 * @return string
	 */
	protected static function bcrypt_format_cost($cost)
	{
		return sprintf('%02d', $cost);
	}
} // End PasswordHash2
/**
 * Implements the hashing algos in pure PHP
 */
class CryptPHP {
	// Public API
	/**
	 * Pure PHP implementation of bcrypt
	 */
	static function bcrypt($password, $seed, $cost)
	{
		
	}
	/**
	 * Pure PHP implementation of sha256 / crypt()
	 */
	static function sha256($password, $seed, $rounds)
	{
		
	}
	/**
	 * Pure PHP implementation of sha512 / crypt()
	 */
	static function sha512($password, $seed, $rounds)
	{
		
	}
	// Private API
	
} // End CryptPHP
