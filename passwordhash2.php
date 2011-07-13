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
		4 => 'invalid seed length',
		5 => 'invalid rounds parameter',
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
	 * Computes a bcrypt hash of $password using $algo with $cost value.
	 * @param string $password
	 * @param string $algo
	 * @param int $cost
	 * @return mixed
	 */
	static function hash($password, $algo = self::bcrypt, $cost = 8)
	{
		$hash = self::crypt($password, self::salt($algo, $cost));
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
	 * @return string
	 */
	static function crypt($password, $salt)
	{
		$info = self::info($salt);
		switch ($info['algo'])
		{
			case self::bcrypt:
				return crypt($password, $salt);
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
	 * @return mixed
	 */
	static function bcrypt($password, $cost = 8)
	{
		return self::hash($password, self::bcrypt, $cost);
	}
	/**
	 * Alias for hash + sha256.
	 * @param string $password
	 * @param int $rounds
	 * @return mixed
	 */
	static function sha256($password, $rounds = 5000)
	{
		return self::hash($password, self::sha256, $rounds);
	}
	/**
	 * Alias for hash + sha512.
	 * @param string $password
	 * @param int $rounds
	 * @return mixed
	 */
	static function sha512($password, $rounds = 5000)
	{
		return self::hash($password, self::sha512, $rounds);
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
		if (strlen($hash[3]) < 22)
		{
			throw new Exception(self::$error[4], 4); // invalid seed length
		}
		return array(
			'algo' => $map[$hash[1]],
			'cost' => (int) $hash[2],
			'seed' => substr($hash[3], 0, 22),
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
		return CryptPHP::base64_encode($seed);
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
				return self::$map[$algo]['prefix'].$cost.'$'.$seed;
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
	 * Pure PHP implementation of sha256 / crypt() ID: 5a
	 * @param string $password
	 * @param string $seed
	 * @param int $rounds
	 * @return string
	 */
	static function sha256($password, $seed, $rounds)
	{
		$alt_result = self::crypt_sha2('sha256', $password, $seed, $rounds);
		if ($alt_result == '*0')
		{
			return $alt_result;
		}
		$encoded = self::b64_from_24bit($alt_result{0},   $alt_result{10}, $alt_result{20}, 4);
		$encoded .= self::b64_from_24bit($alt_result{21}, $alt_result{1},  $alt_result{11}, 4);
		$encoded .= self::b64_from_24bit($alt_result{12}, $alt_result{22}, $alt_result{2},  4);
		$encoded .= self::b64_from_24bit($alt_result{3},  $alt_result{13}, $alt_result{23}, 4);
		$encoded .= self::b64_from_24bit($alt_result{24}, $alt_result{4},  $alt_result{14}, 4);
		$encoded .= self::b64_from_24bit($alt_result{15}, $alt_result{25}, $alt_result{5},  4);
		$encoded .= self::b64_from_24bit($alt_result{6},  $alt_result{16}, $alt_result{26}, 4);
		$encoded .= self::b64_from_24bit($alt_result{27}, $alt_result{7},  $alt_result{17}, 4);
		$encoded .= self::b64_from_24bit($alt_result{18}, $alt_result{28}, $alt_result{8},  4);
		$encoded .= self::b64_from_24bit($alt_result{9},  $alt_result{19}, $alt_result{29}, 4);
		$encoded .= self::b64_from_24bit(chr(0),          $alt_result{31}, $alt_result{30}, 3);
		return "\$5a\$${rounds}\$${seed}\$${encoded}";
	}
	/**
	 * Pure PHP implementation of sha512 / crypt() ID: 6a
	 * @param string $password
	 * @param string $seed
	 * @param int $rounds
	 * @return string
	 */
	static function sha512($password, $seed, $rounds)
	{
		$alt_result = self::crypt_sha2('sha512', $password, $seed, $rounds);
		if ($alt_result == '*0')
		{
			return $alt_result;
		}
		$encoded = self::b64_from_24bit($alt_result{0},   $alt_result{21}, $alt_result{42}, 4);
		$encoded .= self::b64_from_24bit($alt_result{22}, $alt_result{43}, $alt_result{1},  4);
		$encoded .= self::b64_from_24bit($alt_result{44}, $alt_result{2},  $alt_result{23}, 4);
		$encoded .= self::b64_from_24bit($alt_result{3},  $alt_result{24}, $alt_result{45}, 4);
		$encoded .= self::b64_from_24bit($alt_result{25}, $alt_result{46}, $alt_result{4},  4);
		$encoded .= self::b64_from_24bit($alt_result{47}, $alt_result{5},  $alt_result{26}, 4);
		$encoded .= self::b64_from_24bit($alt_result{6},  $alt_result{27}, $alt_result{48}, 4);
		$encoded .= self::b64_from_24bit($alt_result{28}, $alt_result{49}, $alt_result{7},  4);
		$encoded .= self::b64_from_24bit($alt_result{50}, $alt_result{8},  $alt_result{29}, 4);
		$encoded .= self::b64_from_24bit($alt_result{9},  $alt_result{30}, $alt_result{51}, 4);
		$encoded .= self::b64_from_24bit($alt_result{31}, $alt_result{52}, $alt_result{10}, 4);
		$encoded .= self::b64_from_24bit($alt_result{53}, $alt_result{11}, $alt_result{32}, 4);
		$encoded .= self::b64_from_24bit($alt_result{12}, $alt_result{33}, $alt_result{54}, 4);
		$encoded .= self::b64_from_24bit($alt_result{34}, $alt_result{55}, $alt_result{13}, 4);
		$encoded .= self::b64_from_24bit($alt_result{56}, $alt_result{14}, $alt_result{35}, 4);
		$encoded .= self::b64_from_24bit($alt_result{15}, $alt_result{36}, $alt_result{57}, 4);
		$encoded .= self::b64_from_24bit($alt_result{37}, $alt_result{58}, $alt_result{16}, 4);
		$encoded .= self::b64_from_24bit($alt_result{59}, $alt_result{17}, $alt_result{38}, 4);
		$encoded .= self::b64_from_24bit($alt_result{18}, $alt_result{39}, $alt_result{60}, 4);
		$encoded .= self::b64_from_24bit($alt_result{40}, $alt_result{61}, $alt_result{19}, 4);
		$encoded .= self::b64_from_24bit($alt_result{62}, $alt_result{20}, $alt_result{41}, 4);
		$encoded .= self::b64_from_24bit(chr(0),          chr(0),          $alt_result{63}, 2);
		return "\$6a\$${rounds}\$${seed}\$${encoded}";
	}
	/**
	 * bcrypt base64-style decoder. Basically a port from Crypt::Eksblowfish::Bcrypt
	 * @param string $string
	 * @return string
	 */
	static function base64_decode($string)
	{
		$string = strtr(
			$string,
			'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
		);
		return base64_decode($string, TRUE);
	}
	/**
	 * bcrypt base64-style encoder. Basically a port from Crypt::Eksblowfish::Bcrypt
	 * @param string $string
	 * @return string
	 */
	static function base64_encode($string)
	{
		$string = base64_encode($string);
		$string = str_replace('=', '', $string);	
		return strtr(
			$string,
			'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
			'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
		);
	}
	// Private API
	/**
	 * Converts 24 bits of input to a base64-style string
	 * @param string $b2
	 * @param string $b1
	 * @param string $b0
	 * @param string $n
	 */
	protected static function b64_from_24bit($b2, $b1, $b0, $n)
	{
		$chars = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
		$w = (ord($b2) << 16) | (ord($b1) << 8) | ord($b0);
		$buf = '';
		while ($n-- > 0)
		{
			$buf .= $chars[$w & 63];
			$w >>= 6;
		}
		return $buf;
	}
	/**
	 * The method that does the heavy work. Basically an optimized and refactored
	 * version of the implementation from @link http://code.google.com/p/securestring/
	 * @param string $algo
	 * @param string $key
	 * @param string $salt
	 * @param int $rounds
	 */
	protected static function crypt_sha2($algo, $key, $salt, $rounds)
	{
		if ($rounds < 1000 OR $rounds > 999999999)
		{
			return '*0';
		}
		if (strlen($salt) !== 22)
		{
			return '*0';
		}
		$salt = self::base64_decode($salt);
		$salt_len = strlen($salt);
		if ($salt_len !== 16)
		{
			return '*0';
		}
		$key_len = strlen($key);
		$ctx = $key . $salt;
		$alt_ctx = $key . $salt . $key;
		$alt_result = hash($algo, $alt_ctx, TRUE);
		for ($cnt = $key_len; $cnt > 32; $cnt -= 32)
		{
			$ctx .= $alt_result;
		}
		$ctx .= substr($alt_result, 0, $cnt);
		for ($cnt = $key_len; $cnt > 0; $cnt >>= 1)
		{
			if (($cnt & 1) != 0)
			{
				$ctx .= $alt_result;
			}
			else
			{
				$ctx .= $key;
			}
		}
		$alt_result = hash($algo, $ctx, TRUE);
		$alt_ctx = '';
		for ($cnt = 0; $cnt < $key_len; ++$cnt)
		{
			$alt_ctx .= $key;
		}
		$tmp_result = hash($algo, $alt_ctx, TRUE);
		$p_bytes = '';
		for ($cnt = $key_len; $cnt >= 32; $cnt -= 32)
		{
			$p_bytes .= $tmp_result;
		}
		$p_bytes .= substr($tmp_result, 0, $cnt);
		$alt_ctx = '';
		for ($cnt = 0; $cnt < 16 + ord($alt_result{0}); ++$cnt)
		{
			$alt_ctx .= $salt;
		}
		$tmp_result = hash($algo, $alt_ctx, TRUE);
		$s_bytes = '';
		for ($cnt = $salt_len; $cnt >= 32; $cnt -= 32)
		{
			$s_bytes .= $tmp_result;
		}
		$s_bytes .= substr($tmp_result, 0, $cnt);
		for ($cnt = 0; $cnt < $rounds; ++$cnt)
		{
			if (($cnt & 1) != 0)
			{
				$ctx = $p_bytes;
				if ($cnt % 3 != 0)
				{
					$ctx .= $s_bytes;
				}
				if ($cnt % 7 != 0)
				{
					$ctx .= $p_bytes;
				}
				$ctx .= $alt_result;
			}
			else
			{
				$ctx = $alt_result;
				if ($cnt % 3 != 0)
				{
					$ctx .= $s_bytes;
				}
				if ($cnt % 7 != 0)
				{
					$ctx .= $p_bytes;
				}
				$ctx .= $p_bytes;
			}
			$alt_result = hash($algo, $ctx, TRUE);
		}
		return $alt_result;
	}
} // End CryptPHP
