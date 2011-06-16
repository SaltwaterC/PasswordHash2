<?php
require dirname(__FILE__).DIRECTORY_SEPARATOR.'passwordhash2.php';

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

if (version_compare(PHP_VERSION, '5.3.2', '<'))
{
	trigger_error('PHP 5.3.2+ is required for SHA256 / SHA512 hashes.',
		E_USER_WARNING);
}

// Functionality test
$password = uniqid(NULL, TRUE);

$tests = array(
	
	array(
		'cost'     => 8,
		'new_cost' => 10,
		'algo'     => PasswordHash2::bcrypt,
	),
	
	array(
		'cost'     => 5000,
		'new_cost' => 10000,
		'algo'     => PasswordHash2::sha256,
	),
	
	array(
		'cost'     => 5000,
		'new_cost' => 10000,
		'algo'     => PasswordHash2::sha512,
	),
	
);

$lt = (strtolower(PHP_SAPI) === 'cli') ? PHP_EOL : '<br>' ;

echo $lt;

foreach ($tests as $params)
{
	$hash = PasswordHash2::hash($password, $params['algo'], $params['cost']);
	$check = PasswordHash2::check($password, $hash);
	$cost = PasswordHash2::cost($hash);
	
	$rehash = PasswordHash2::rehash(
		$password, $hash, $params['algo'], $params['new_cost']
	);
	$recheck = PasswordHash2::check($password, $rehash);
	$recost = PasswordHash2::cost($rehash);
	
	$shorthash = PasswordHash2::hash(
		$password, $params['algo'], $params['cost'],TRUE
	);
	$shortcheck = PasswordHash2::check(
		$password, $shorthash, $params['algo'], TRUE
	);
	$shortcost = PasswordHash2::cost($shorthash, $params['algo'], TRUE);
	
	echo 'Generated password: '.$password.$lt;
	echo 'Generated '.$params['algo'].' hash: '.$hash.$lt;
	echo 'Is valid: '.(($check) ? 'TRUE' : 'FALSE').$lt;
	echo 'Cost: '.$cost.$lt;
	echo 'Rehashed password: '.$rehash.$lt;
	echo 'Is valid: '.(($recheck) ? 'TRUE' : 'FALSE').$lt;
	echo 'Cost: '.$recost.$lt;
	echo 'Short '.$params['algo'].' hash: '.$shorthash.$lt;
	echo 'Is valid: '.(($shortcheck) ? 'TRUE' : 'FALSE').$lt;
	echo 'Short Cost: '.$shortcost.$lt;
	
	echo $lt;
}

