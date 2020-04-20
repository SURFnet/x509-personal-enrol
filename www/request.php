<?php
// TODO: use the userinfo endpoint using an access token instead of relying on server environment
//       to avoid issues with redirects when authentication has expired (eg CORS policy violations)
$cn = ($_SERVER['OIDC_CLAIM_name']) or $cn = getenv('OIDC_CLAIM_name');
$email = $_SERVER['OIDC_CLAIM_email'] or $email = getenv('OIDC_CLAIM_email');

# these assertions are enforced by apache auth_openid
assert($_SERVER['OIDC_CLAIM_schac_home_organization'] == 'surfnet.nl'
      or getenv('OIDC_CLAIM_schac_home_organization') ==  'surfnet.nl');
assert($_SERVER['OIDC_CLAIM_eduperson_entitlement'] == 'urn:mace:terena.org:tcs:personal-user' or
         getenv('OIDC_CLAIM_eduperson_entitlement') ==  'urn:mace:terena.org:tcs:personal-user');
if (!filter_var($email, FILTER_VALIDATE_EMAIL) or !preg_match("/^[a-zA-Z- ]*$/",$cn)) {
  error_log("ERROR: invalid cn ('$cn') and email ('$email')");
  header("HTTP/1.1 500 Internal Server Error");
  exit();
}

$csr = $_POST['csr'];
assert(openssl_csr_get_subject($csr) == []);  // check CSR can be parsed

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);

$content = $config['request_template'];
$content['certificate']['common_name'] = $cn;
$content['certificate']['emails'] = [ $email ];
$content['certificate']['csr'] = $csr;
$body = json_encode($content);
$key = $config['api']['key'];

$opts = array('http' =>
  array(
    'method'  => 'POST',
    'header'  => "Content-Type: application/json\r\n".
      "X-DC-DEVKEY: $key\r\n",
    'content' => $body,
    'timeout' => 60
  )
);

$context  = stream_context_create($opts);
$url = $config['api']['order_uri'];
$result = file_get_contents($url, false, $context);
// { "id": 13274378, "certificate_id": 14009458 }

$data = json_decode($result, true);
echo json_encode($data, JSON_PRETTY_PRINT);
error_log('INFO: completed certificate request ' . json_encode(array_merge($content, $data)));
