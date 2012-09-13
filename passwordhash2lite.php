<?php
/**
 * Portable password hashing framework for PHP. This is the lite version.
 * 
 * Implements:
 * 
 * - the CRYPT_BLOWFISH (bcrypt) scheme
 * 
 * @link http://en.wikipedia.org/wiki/Crypt_%28Unix%29#Blowfish-based_scheme
 * 
 * @author Stefan Rusu
 * @license New BSD
 * @version 0.3-bcrypt
 */
class PasswordHash2 {
	
	// The Public API
	
	/**
	 * Computes a bcrypt hash of $password using $algo with $cost value.
	 * 
	 * @param string $password
	 * @param int $cost
	 * @return mixed
	 */
	static function hash($password, $cost = 10)
	{
		$hash = crypt($password, self::salt($cost));
		
		if (strlen($hash) === 60)
		{
			return $hash;
		}
		
		return FALSE;
	}
	
	/**
	 * Checks a $password against a $hash.
	 * 
	 * @param string $password
	 * @param string $hash
	 * @return bool
	 */
	static function check($password, $hash)
	{
		return (crypt($password, $hash) === $hash);
	}
	
	/**
	 * Returns the info about an input $hash / $salt
	 * 
	 * @param string $hash
	 * @return array
	 */
	static function info($hash)
	{
		$hash = explode('$', $hash);
		
		if ( ! isset($hash[1]) OR ! isset($hash[2]) OR ! isset($hash[3]))
		{
			return FALSE;
		}
		
		if ($hash[1] !== '2a')
		{
			return FALSE;
		}
		
		if (strlen($hash[3]) < 22)
		{
			return FALSE;
		}
		
		return array(
			'algo' => 'bcrypt',
			'cost' => (int) $hash[2],
			'seed' => substr($hash[3], 0, 22),
		);
	}
	
	// The Protected API
	
	/**
	 * Random seed generator for the salt.
	 * 
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
		return self::base64_encode($seed);
	}
	
	/**
	 * bcrypt base64-style encoder. Basically a port from Crypt::Eksblowfish::Bcrypt
	 * 
	 * @param string $string
	 * @return string
	 */
	protected static function base64_encode($string)
	{
		$string = base64_encode($string);
		$string = str_replace('=', '', $string);
		return strtr(
			$string,
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
			'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
		);
	}
	
	/**
	 * Generates the $salt for $algo with $cost.
	 * 
	 * @param int $cost
	 * @return string
	 */
	protected static function salt($cost)
	{
		$cost = (int) $cost;
		$seed = self::seed();
		
		if ($cost < 4)
		{
			$cost = 4;
		}
		
		if ($cost > 31)
		{
			$cost = 31;
		}
		
		return '$2a$'.self::format_cost($cost).'$'.$seed;
	}
	
	/**
	 * Returns the zero padded cost parameter for bcrypt.
	 * 
	 * @param int $cost
	 * @return string
	 */
	protected static function format_cost($cost)
	{
		return sprintf('%02d', $cost);
	}
}

