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
		'cost' => 8,
		'algo' => 'bcrypt',
	),
	
	array(
		'cost' => 5000,
		'algo' => 'sha256',
	),
	
	array(
		'cost' => 5000,
		'algo' => 'sha512',
	),
	
);

$line_terminator = (strtolower(PHP_SAPI) === 'cli') ? PHP_EOL : '<br>' ;

echo $line_terminator;

foreach ($tests as $params)
{
	$hash = PasswordHash2::hash($password, $params['algo'], $params['cost']);
	$check = PasswordHash2::check($password, $hash);
	
	echo 'Generated password: '.$password.'; Generated '.
		$params['algo'].' hash: '.$hash.'; Is valid: '.
		(($check) ? 'TRUE' : 'FALSE').$line_terminator.$line_terminator;
}

