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
 * @version 0.2.1
 */
class PasswordHash2 {
	/**
	 * Maps the lenght of the resulting hash. Since the SHA-2 based scheme has
	 * a variable length, the length value is pushed to the map when the rounds
	 * number is known.
	 */
	protected static $map = array(
		
		'bcrypt' => array(
			'prefix'     => '$2a$',
			'length'     => 60,
		),
		
		'sha256' => array(
			'prefix'     => '$5$',
			'min_length' => 75,
		),
		
		'sha512' => array(
			'prefix'     => '$6$',
			'min_length' => 118,
		),
	);
	
	/**
	 * Returns a 'good' random byte for use with the SHA-2 based scheme salt
	 * that can use any byte, except NUL and $ - which is used as separator by
	 * the crypt() schemes.
	 * 
	 * return string
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
			case 'bcrypt':
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
					$cost = sprintf('%02d', $cost);
					
					return self::$map[$algo]['prefix'].$cost.'$'.$salt;
				}
			break;
			
			case 'sha256':
			case 'sha512':
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
	 * Computes a bcrypt hash of $password using $algo with $cost value.
	 * 
	 * @param string $password
	 * @param int $cost
	 * @return mixed
	 */
	public static function hash($password, $algo = 'bcrypt', $cost = 8)
	{
		$salt = self::salt($algo, $cost);
		
		if ( ! $salt)
		{
			return FALSE;
		}
		
		$hash = crypt($password, $salt);
		
		if (strlen($hash) === self::$map[$algo]['length'])
		{
			return base64_encode($hash);
		}
		
		return FALSE;
	}
	
	/**
	 * Checks a hash.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @return bool
	 */
	public static function check($password, $hash)
	{
		$hash = base64_decode($hash, TRUE);
		
		if ( ! $hash)
		{
			return FALSE;
		}
		
		return (crypt($password, $hash) === $hash);
	}
	
	/**
	 * Rehash method for easier implementation of adaptive hasing.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @param string $algo
	 * @param int $cost
	 * @return mixed
	 */
	public static function rehash($password, $hash, $algo = 'bcrypt', $cost = 10)
	{
		if ( ! self::check($password, $hash))
		{
			return FALSE;
		}
		
		return self::hash($password, $algo, $cost);
	}
	
	/**
	 * Returns the cost parameter of an input hash.
	 * 
	 * @param string $hash
	 * @return mixed
	 */
	public static function cost($hash)
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
		
		return FALSE;
	}
	
} // End PasswordHash2
