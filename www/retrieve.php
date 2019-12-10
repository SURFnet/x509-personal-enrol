<?php
//error_log(print_r($_POST, true));
$certificate_id = $_POST['certificate_id'];

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
$key = $config['api']['key'];
$url = $config['api']['download_uri'] . $certificate_id . '/download/format/p7b';

$opts = array('http' =>
  array(
    'method'  => 'GET',
    'header'  => "X-DC-DEVKEY: $key\r\n",
    'timeout' => 60,
    'ignore_errors' => true
  )
);
$context  = stream_context_create($opts);
$result = file_get_contents($url, false, $context);
// error_log(print_r($http_response_header, true));
echo $result;

// $result is either a JSON error message or a PKCS7 data structure
// {"errors":[{"code":"cert_unavailable_processing","message":"Unable to download certificate, the certificate has not yet been issued.  Try back in a bit."}]}
if (preg_match("/-----BEGIN PKCS7-----/", $result)) {
  error_log('INFO: retrieved certificate with ID ' . $certificate_id);
} else {
  error_log("ERROR: retrieving certificate with ID $certificate_id: " . $result);
}