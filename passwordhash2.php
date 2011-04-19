<?php
/**
 * Password Hashing class for PHP. Uses bcrypt.
 * 
 * @author Stefan Rusu
 * @license New BSD
 */
class PasswordHash2 {
	/**
	 * Salt generator for crypt.
	 *
	 * @param string $input
	 * @return string
	 */
	public static function salt($cost)
	{
		$seed = openssl_random_pseudo_bytes(16, $crypto_strong);
		
		if ($crypto_strong !== TRUE)
		{
			trigger_error('The random bytes generator isn\'t "cryptographically'
			.' strong". An update to the PHP stack and / or OpenSSL is '
			.'advisable.', E_USER_WARNING);
		}
		
		$salt = base64_encode($seed);
		$salt = substr($salt, 0, 22);
		$salt = str_replace('+', '.', $salt);
		
		return '$2a$'.sprintf('%02d', $cost).'$'.$salt;
	}
	
	/**
	 * Computes a bcrypt hash of $password with $cost value
	 * 
	 * @param string $password
	 * @param int $cost
	 */
	public static function hash($password, $cost = 8)
	{
		$cost = (int) $cost;
		
		if ($cost < 4)
		{
			$cost = 4;
		}
		
		if ($cost > 31)
		{
			$cost = 31;
		}
		
		$hash = crypt($password, self::salt($cost));
		
		if (strlen($hash) === 60)
		{
			return $hash;
		}
		else
		{
			return FALSE;
		}
	}
	
	/**
	 * Checks a hash. Added for convenience since it's just a crypt wrapper.
	 * 
	 * @param string $password
	 * @param string $hash
	 */
	public static function check($password, $hash)
	{
		return (crypt($password, $hash) == $hash);
	}
	
	/**
	 * Test method. Added for convenience. Usually it validates the runtime.
	 */
	public static function test()
	{
		// Enable all the error reporting bits
		error_reporting(-1);
		
		// System tests
		if (version_compare(PHP_VERSION, '5.3.0', '<'))
		{
			trigger_error('This class requires PHP 5.3.0+.', E_USER_ERROR);
		}
		
		if ( ! function_exists('openssl_random_pseudo_bytes'))
		{
			trigger_error('This class requires the OpenSSL extension.', 
				E_USER_ERROR);
		}
		
		// Functionality test
		$password = uniqid(NULL, TRUE);
		
		$hash = self::hash($password);
		$check = self::check($password, $hash);
		
		echo 'Generated password: '.$password.'; Generated hash: '.$hash.
			'; Is valid: '.(($check) ? 'TRUE' : 'FALSE').".\n";
	}
	
} // End PasswordHash2