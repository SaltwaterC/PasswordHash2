<?php
require dirname(__FILE__).DIRECTORY_SEPARATOR.'passwordhash2.php';

// Enable all the error reporting bits
error_reporting(-1);

// System tests
if (version_compare(PHP_VERSION, '5.3.8', '<'))
{
	trigger_error('This framework requires PHP 5.3.8+.', E_USER_ERROR);
}

if ( ! function_exists('openssl_random_pseudo_bytes'))
{
	trigger_error('This framework requires the OpenSSL extension.', E_USER_ERROR);
}

if ( ! function_exists('hash'))
{
	trigger_error('This framework requires the hash extension.', E_USER_ERROR);
}

if ( ! in_array('sha256', hash_algos()))
{
	trigger_error('This framework requires the sha256 support into the hash extension.', E_USER_ERROR);
}

if ( ! in_array('sha512', hash_algos()))
{
	trigger_error('This framework requires the sha512 support into the hash extension.', E_USER_ERROR);
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
	$info = PasswordHash2::info($hash);
	
	echo 'Generated password: '.$password.$lt;
	echo 'Generated '.$params['algo'].' hash: '.$hash.$lt;
	echo 'Is valid: '.(($check) ? 'TRUE' : 'FALSE').$lt;
	
	echo 'Info algo: '.$info['algo'].$lt;
	echo 'Info cost: '.$info['cost'].$lt;
	echo 'Info seed: '.$info['seed'].$lt;
	
	echo $lt;
}
