<?php
/**
 * Portable password hashing framework for PHP.
 * 
 * Implements:
 * 
 * - the CRYPT_BLOWFISH (bcrypt) scheme
 * - my variation of CRYPT_SHA256 and CRYPT_SHA512 that borrows some concepts
 *   from bcrypt to the SHA2 schemes
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
	 * Maps the lenght of the resulting hash. Since the SHA-2 based scheme has
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
	 * Computes a bcrypt hash of $password using $algo with $cost value. Has
	 * the $short flag for returning a compact version of the hash.
	 * 
	 * @param string $password
	 * @param string $algo
	 * @param int $cost
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function hash($password, $algo = self::bcrypt, $cost = 8, $short = FALSE)
	{
		$salt = self::salt($algo, $cost);
		
		if ( ! $salt)
		{
			return FALSE; // TODO implement error codes, exceptions
		}
		
		switch ($algo)
		{
			case self::bcrypt:
				$hash = crypt($password, $salt);
			break;
			
			case self::sha256:
			case self::sha512:
				// TODO
				$hash = '';
			break;
		}
		
		if (strlen($hash) === self::$map[$algo]['length'])
		{
			if ( ! $short)
			{
				return $hash;
			}
			else
			{
				return self::shorten($hash);
			}
		}
		
		return FALSE; // TODO implement error codes, exceptions
	}
	
	/**
	 * Returns a shorter version of the $hash for $algo type. Incompatible
	 * with the standard crypt() scheme.
	 * 
	 * @param string $hash
	 * 
	 * @return mixed
	 */
	static function shorten($hash)
	{
		// TODO refactor, the same method may be used for all hashes
		$algo = substr($hash, 1, 1);
		
		switch ($algo)
		{
			case '2': // bcrypt
				$hash = explode('$', $hash);
				$hash[2] = self::base36_encode($hash[2]); // the cost
				
				// algo + (salt + hash) + cost
				return $algo.$hash[3].$hash[2];
			break;
			
			case '5': // sha256
			case '6': // sha512
				$hash = substr($hash, 10); // the header just stays in the way
				$hash = explode('$', $hash);
				$hash[0] = self::base36_encode($hash[0]); // cost
				$hash[1] = substr(base64_encode($hash[1]), 0, 22); // salt
				
				// algo + salt + hash + cost
				return $algo.$hash[1].$hash[2].$hash[0];
			break;
		}
		
		return FALSE; // TODO implement error codes, exceptions
	}
	
	/**
	 * Checks a $password against a $hash. Has the $short flag capability.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @param bool $short
	 * 
	 * @return bool
	 */
	static function check($password, $hash, $short = FALSE)
	{
		if ($short)
		{
			$hash = self::expand($hash);
		}
		
		$algo = self::algo($hash);
		
		switch ($algo)
		{
			case self::bcrypt:
				return (crypt($password, $hash) === $hash);
			break;
			
			case self::sha256:
			case self::sha512:
				// TODO
			break;
		}
		
		// TODO fail with code, exception
	}
	
	/**
	 * Expands a $shorhash to the appropriate crypt() scheme representation.
	 * 
	 * @param string $shorthash
	 * 
	 * @return mixed
	 */
	static function expand($shorthash)
	{
		// TODO refactor, the same expand method may be used by all hashes
		$algo = substr($shorthash, 0, 1);
		
		switch ($algo)
		{
			case '2': // bcrypt
				$cost = self::bcrypt_short_cost($shorthash);
				$cost = self::bcrypt_format_cost($cost);
				
				return '$2a$'.$cost.'$'.substr($shorthash, 1, 53);
			break;
			
			case '5': // sha256
				return '$5$rounds='.self::sha256_short_cost($shorthash).'$'
					.self::sha_short_salt($shorthash).'$'
					.substr($shorthash, 23, 43);
			break;
			
			case '6': // sha512
				return '$6$rounds='.self::sha512_short_cost($shorthash).'$'
					.self::sha_short_salt($shorthash).'$'
					.substr($shorthash, 23, 86);
			break;
		}
		
		return FALSE; // TODO: fail with code, exception
	}
	
	/**
	 * Rehash method for easier implementation of adaptive hasing.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @param string $algo
	 * @param int $cost
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function rehash($password, $hash, $algo = self::bcrypt, $cost = 10, $short = FALSE)
	{
		if ( ! self::check($password, $hash))
		{
			return FALSE; // TODO: fail with code, exception
		}
		
		return self::hash($password, $algo, $cost, $short);
	}
	
	/**
	 * Returns the $cost parameter of an input $hash. Has the $short flag
	 * capability.
	 * 
	 * @param string $hash
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function cost($hash, $short = FALSE)
	{
		// TODO refactor, the new proposed algos have the cost as the first section of the salt
		if ( ! $short)
		{
			$hash = base64_decode($hash, TRUE);
			
			if ( ! $hash)
			{
				return FALSE;
			}
			
			$match = preg_match(
				'/^\$(?:2a|5|6)\$(?:rounds=)?(\d+)\$/', $hash, $matches
			);
			
			if ($match === 1)
			{
				if (isset ($matches[1]))
				{
					return (int) $matches[1];
				}
			}
		}
		else
		{
			$algo = substr($hash, 0, 1);
			
			switch ($algo)
			{
				case '2':
					return self::bcrypt_short_cost($hash);
				break;
				
				case '5':
					return self::sha256_short_cost($hash);
				break;
				
				case '6':
					return self::sha512_short_cost($hash);
				break;
			}
		}
		
		return FALSE; // TODO exit with code, exception
	}
	
	/**
	 * Returns the algo of a given hash.
	 * 
	 * @param string $hash
	 * 
	 * @return mixed
	 */
	static function algo($hash)
	{
		for ($i = 0; $i <= 1; $i++)
		{
			$algo = substr($hash, $i, 1);
			switch ($algo)
			{
				case '2':
					return self::bcrypt;
				break;
				
				case '5':
					return self::sha256;
				break;
				
				case '6':
					return self::sha512;
				break;
			}
		}
		
		return FALSE; // TODO exit with code, exception
	}
	
	/**
	 * Alias for hash + bcrypt.
	 * 
	 * @param string $password
	 * @param int $cost
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function bcrypt($password, $cost = 8, $short = FALSE)
	{
		return self::hash($password, self::bcrypt, $cost, $short);
	}
	
	/**
	 * Alias for hash + sha256.
	 * 
	 * @param string $password
	 * @param int $rounds
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function sha256($password, $rounds = 5000, $short = FALSE)
	{
		return self::hash($password, self::sha256, $rounds, $short);
	}
	
	/**
	 * Alias for hash + sha512.
	 * 
	 * @param string $password
	 * @param int $rounds
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function sha512($password, $rounds = 5000, $short = FALSE)
	{
		return self::hash($password, self::sha512, $rounds, $short);
	}
	
	// The Private API
	
	/**
	 * Generates the $salt for $algo with $cost.
	 * 
	 * @param string $algo
	 * @param int $cost
	 * 
	 * @return mixed
	 */
	protected static function salt($algo, $cost)
	{
		// TODO refactor this junk, may use a much simpler salt generator
		$cost = (int) $cost;
		$seed = openssl_random_pseudo_bytes(16, $crypto_strong);
		
		if ($crypto_strong !== TRUE)
		{
			trigger_error('The random bytes generator isn\'t "cryptographically'
				.' strong". An update to the PHP stack and / or OpenSSL is '
				.'advisable.', E_USER_WARNING);
		}
		
		switch ($algo)
		{
			case self::bcrypt:
				if (CRYPT_BLOWFISH === 1)
				{
					if ($cost < 4)
					{
						$cost = 4;
					}
					
					if ($cost > 31)
					{
						$cost = 31;
					}
					
					$salt = base64_encode($seed);
					$salt = substr($salt, 0, 22);
					$salt = str_replace('+', '.', $salt);
					
					return self::$map[$algo]['prefix']
						.self::bcrypt_format_cost($cost).'$'.$salt;
				}
			break;
			
			case self::sha256:
			case self::sha512:
				if (CRYPT_SHA256 === 1 AND CRYPT_SHA512 === 1)
				{
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
					
					for ($i = 0; $i < 16; $i++)
					{
						// Search for the 'bad' bytes that break the hashing
						if (ord($seed{$i}) === 0 OR ord($seed{$i}) === 36)
						{
							$seed{$i} = self::random_byte();
						}
					}
					
					return self::$map[$algo]['prefix'].'rounds='.$cost.'$'
						.$seed.'$';
				}
			break;
		}
		
		return FALSE; // TODO of course, exit with code, exception
	}
	
	/**
	 * Returns the zero padded cost parameter for bcrypt.
	 * 
	 * @param int $cost
	 * 
	 * @return string
	 */
	protected static function bcrypt_format_cost($cost)
	{
		return sprintf('%02d', $cost);
	}
	
	/**
	 * Returns the cost parameter of a bcrypt short hash.
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function bcrypt_short_cost($hash)
	{
		return (int) self::base36_decode(substr($hash, -1)); // TODO replaced with unified method
	}
	
	/**
	 * Returns the cost parameter of a sha256 short hash.
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function sha256_short_cost($hash)
	{
		return (int) self::base36_decode(substr($hash, 66)); // TODO replaced with unified method
	}
	
	/**
	 * Returns the cost parameter of a sha512 short hash.
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function sha512_short_cost($hash)
	{
		return (int) self::base36_decode(substr($hash, 109)); // TODO replaced with unified method
	}
	
	/**
	 * Returns the salt of a SHA-2 short hash.
	 * 
	 * @param string $hash
	 * 
	 * @return mixed
	 */
	protected static function sha_short_salt($hash)
	{
		// TODO most probably this may be removed
		$salt = substr($hash, 1, 22);
		$salt = base64_decode($salt, TRUE);
		
		if ( ! $salt)
		{
			return FALSE;
		}
		
		return $salt;
	}
	
	/**
	 * base10 to base36 numeric converter.
	 * 
	 * @param int $number
	 * 
	 * @return string
	 */
	protected static function base36_encode($number)
	{
		return base_convert($number, 10, 36);
	}
	
	/**
	 * base36 to base10 numeric converter.
	 * 
	 * @param string $number
	 * 
	 * @return int
	 */
	protected static function base36_decode($number)
	{
		return base_convert($number, 36, 10);
	}
		
} // End PasswordHash2
