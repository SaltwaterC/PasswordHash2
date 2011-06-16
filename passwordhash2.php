<?php
/**
 * Password Hashing class for PHP. Uses bcrypt (PHP 5.3.0+) or Ulrich Drepper's
 * SHA2 implementation (PHP 5.3.2+).
 * 
 * @link http://en.wikipedia.org/wiki/Crypt_%28Unix%29#Blowfish-based_scheme
 * @link http://en.wikipedia.org/wiki/Crypt_%28Unix%29#SHA-based_scheme
 * 
 * @author Stefan Rusu
 * @license New BSD
 * @version 0.2.2
 */
class PasswordHash2 {
	
	const bcrypt = 'bcrypt';
	const sha256 = 'sha256';
	const sha512 = 'sha512';
	
	/**
	 * Maps the lenght of the resulting hash. Since the SHA-2 based scheme has
	 * a variable length, the length value is pushed to the map when the rounds
	 * number is known.
	 */
	protected static $map = array(
		
		self::bcrypt => array(
			'prefix'     => '$2a$',
			'length'     => 60,
		),
		
		self::sha256 => array(
			'prefix'     => '$5$',
			'min_length' => 75,
		),
		
		self::sha512 => array(
			'prefix'     => '$6$',
			'min_length' => 118,
		),
	);
	
	/**
	 * Returns a 'good' random byte for use with the SHA-2 based scheme salt
	 * that can use any byte, except NUL and $ - which is used as separator by
	 * the crypt() schemes.
	 * 
	 * @return string
	 */
	protected static function random_byte()
	{
		$pos = mt_rand(0, 1);
		$char = array(
			mt_rand(1, 35),
			mt_rand(37, 255),
		);
		return ord($char[$pos]);
	}
	
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
		
		return FALSE;
	}
	
	/**
	 * Returns the zero padded cost parameter for bcrypt
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
	 * Returns the cost parameter of a bcrypt short hash
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function bcrypt_short_cost($hash)
	{
		return (int) base_convert(substr($hash, -1), 32, 10);
	}
	
	/**
	 * Returns the cost parameter of a sha256 short hash
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function sha256_short_cost($hash)
	{
		return (int) base_convert(substr($hash, 65), 36, 10);
	}
	
	/**
	 * Returns the cost parameter of a sha512 short hash
	 * 
	 * @param string $hash
	 * 
	 * @return int
	 */
	protected static function sha512_short_cost($hash)
	{
		return (int) base_convert(substr($hash, 108), 36, 10);
	}
	
	/**
	 * Returns the salt of a SHA-2 hash
	 * 
	 * @param string $hash
	 * 
	 * @return mixed
	 */
	protected static function sha_short_salt($hash)
	{
		$salt = substr($hash, 0, 22);
		$salt = base64_decode($salt, TRUE);
		
		if ( ! $salt)
		{
			return FALSE;
		}
		
		return $salt;
	}
	
	/**
	 * Computes a bcrypt hash of $password using $algo with $cost value.
	 * 
	 * @param string $password
	 * @param string $algo
	 * @param int $cost
	 * @param bool $short
	 * 
	 * @return mixed
	 */
	static function hash($password, $algo = self::bcrypt, $cost = 8,
			$short = FALSE)
	{
		$salt = self::salt($algo, $cost);
		
		if ( ! $salt)
		{
			return FALSE;
		}
		
		$hash = crypt($password, $salt);
		
		if (strlen($hash) === self::$map[$algo]['length'])
		{
			if ( ! $short)
			{
				return base64_encode($hash);
			}
			else
			{
				return self::shorten($hash, $algo);
			}
		}
		
		return FALSE;
	}
	
	/**
	 * Returns a shorter version of the raw $hash for $algo type. Incompatible
	 * with the standard crypt() scheme.
	 * 
	 * @param string $hash
	 * @param string $algo
	 * 
	 * @return mixed
	 */
	static function shorten($hash, $algo)
	{
		switch ($algo)
		{
			case 'bcrypt':
				$hash = explode('$', $hash);
				$hash[2] = base_convert($hash[2], 10, 32);
				
				return $hash[3].$hash[2];
			break;
			
			case 'sha512':
			case 'sha256':
				$hash = substr($hash, 10);
				$hash = explode('$', $hash);
				$hash[0] = base_convert($hash[0], 10, 36);
				$hash[1] = substr(base64_encode($hash[1]), 0, 22);
				
				return $hash[1].$hash[2].$hash[0];
			break;
		}
		
		return FALSE;
	}
	
	/**
	 * Checks a hash.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @param string $algo
	 * @param bool $short
	 * 
	 * @return bool
	 */
	static function check($password, $hash, $algo = self::bcrypt,
			$short = FALSE)
	{
		if ( ! $short)
		{
			$hash = base64_decode($hash, TRUE);
			
			if ( ! $hash)
			{
				return FALSE;
			}
		}
		else
		{
			$hash = self::expand($hash, $algo);
		}
		
		return (crypt($password, $hash) === $hash);
	}
	
	/**
	 * Expands a $hash to the appropriate crypt() scheme representation for
	 * $algo.
	 * 
	 * @param string $hash
	 * @param string $algo
	 * 
	 * @return mixed
	 */
	static function expand($hash, $algo)
	{
		switch ($algo)
		{
			case self::bcrypt:
				$cost = self::bcrypt_short_cost($hash);
				$cost = self::bcrypt_format_cost($cost);
				
				return '$2a$'.$cost.'$'.substr($hash, 0, 53);
			break;
			
			case self::sha256:
				return '$5$rounds='.self::sha256_short_cost($hash).'$'
					.self::sha_short_salt($hash).'$'.substr($hash, 22, 43);
			break;
			
			case self::sha512:
				return '$6$rounds='.self::sha512_short_cost($hash).'$'
					.self::sha_short_salt($hash).'$'.substr($hash, 22, 86);
			break;
		}
		
		return FALSE;
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
	static function rehash($password, $hash, $algo = self::bcrypt,
			$cost = 10, $short = FALSE)
	{
		if ( ! self::check($password, $hash))
		{
			return FALSE;
		}
		
		return self::hash($password, $algo, $cost, $short);
	}
	
	/**
	 * Returns the cost parameter of an input hash.
	 * 
	 * @param string $hash
	 * 
	 * @return mixed
	 */
	static function cost($hash, $algo = self::bcrypt, $short = FALSE)
	{
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
			switch ($algo)
			{
				case self::bcrypt:
					return self::bcrypt_short_cost($hash);
				break;
				
				case self::sha256:
					return self::sha256_short_cost($hash);
				break;
				
				case self::sha512:
					return self::sha512_short_cost($hash);
				break;
			}
		}
		
		return FALSE;
	}
	
	/**
	 * Alias for hash + bcrypt
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
	 * Alias for hash + sha256
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
	 * Alias for hash + sha512
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
	
} // End PasswordHash2
