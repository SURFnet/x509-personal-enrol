<?php
session_start();

if (empty($_POST['csrftoken']) or empty($_SESSION['csrftoken']) or $_SESSION['csrftoken'] !== $_POST['csrftoken']) {
  error_log("ERROR: csrf token mismatch");
  http_response_code(400);
  exit();
}

$orderNumber = $_POST['orderNumber'];

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
if( $config === NULL ) {
  error_log("ERROR: cannot parse config file");
  http_response_code(500);
  exit();
}

$url = $config['api']['download_uri'] . $orderNumber;
$uri = $config['api']['uri'];
$login = $config['api']['login'];
$key = $config['api']['key'];

$opts = array('http' =>
  array(
    'method'  => 'GET',
    'header'  => 
        "Content-Type: application/json;charset=utf-8\r\n".
        "Accept: application/json;charset=utf-8\r\n".
        "customerUri: $uri\r\n".
        "login: $login\r\n".
        "password: $key\r\n",
    'timeout' => 60,
    'ignore_errors' => true
  )
);
$context  = stream_context_create($opts);
$result = @file_get_contents($url, false, $context);
// error_log(print_r($http_response_header, true));

if( $result === FALSE ) {
  http_response_code(400);
  echo '{ "error":"order failed"}';
  error_log('ERROR: order failed for certificate request ' . json_encode($content));
  exit();
}

echo $result;

// $result is either a JSON error message or a PKCS7 data structure
// {"errors":[{"code":"cert_unavailable_processing","message":"Unable to download certificate, the certificate has not yet been issued.  Try back in a bit."}]}
if (preg_match("/-----BEGIN PKCS7-----/", $result)) {
  error_log('INFO: retrieved certificate with ID ' . $orderNumber);
} else {
  error_log("ERROR: retrieving certificate with ID $orderNumber: " . $result);
}
