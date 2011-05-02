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
 * @version 0.2
 */
class PasswordHash2 {
	
	protected static $map = array(
		
		'bcrypt' => array(
			'prefix' => '$2a$',
			'length' => 80,
		),
		
		'sha256' => array(
			'prefix' => '$5$',
			'length' => 100,
		),
		
		'sha512' => array(
			'prefix' => '$6$',
			'length' => 160,
		),
	);
	
	/**
	 * Generates the $salt for $algo with $cost
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
					$salt = self::$map[$algo]['prefix'].$cost.'$'.$salt;
				}
				else
				{
					return FALSE;
				}
			break;
			
			case 'sha256':
			case 'sha512':
				if (CRYPT_SHA256 === 1 AND CRYPT_SHA512 === 1)
				{
					$salt = self::$map[$algo]['prefix'].'rounds='.$cost.'$'
						.$seed.'$';
				}
				else
				{
					return FALSE;
				}
			break;
			
			default:
				$salt = FALSE;
			break;
		}
		
		return $salt;
	}
	
	/**
	 * Computes a bcrypt hash of $password using $algo with $cost value
	 * 
	 * @param string $password
	 * @param int $cost
	 * @return mixed
	 */
	public static function hash($password, $algo = 'bcrypt', $cost = 8)
	{
		$cost = (int) $cost;
		$salt = self::salt($algo, $cost);
		
		if ($salt === FALSE)
		{
			return FALSE;
		}
		
		$hash = base64_encode(crypt($password, $salt));
		
		if (strlen($hash) === self::$map[$algo]['length'])
		{
			return $hash;
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
		$hash = base64_decode($hash);
		return (crypt($password, $hash) == $hash);
	}
	
} // End PasswordHash2