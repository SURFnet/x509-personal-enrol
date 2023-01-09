<?php
// TODO: use the userinfo endpoint using an access token instead of relying on server environment
//       to avoid issues with redirects when authentication has expired (eg CORS policy violations)
$email = $_SERVER['OIDC_CLAIM_email'] or $email = getenv('OIDC_CLAIM_email');
$givenName = ($_SERVER['OIDC_CLAIM_given_name']) or $givenName = getenv('OIDC_CLAIM_given_name');
$familyName = ($_SERVER['OIDC_CLAIM_family_name']) or $familyName = getenv('OIDC_CLAIM_family_name');
$homeOrganization = ($_SERVER['OIDC_CLAIM_schac_home_organization']) or $homeOrganization = getenv('OIDC_CLAIM_schac_home_organization');
$edupersonEntitlement = ($_SERVER['OIDC_CLAIM_eduperson_entitlement']) or $edupersonEntitlement = getenv('OIDC_CLAIM_eduperson_entitlement');

# these assertions are enforced by apache auth_openid
# Note:
# - schac_home_organization restricts claims originating from a specific provider
# - eduperson_entitlement restricts claims from specific users
if($_SERVER['OIDC_CLAIM_schac_home_organization'] !== 'surf.nl'
      and getenv('OIDC_CLAIM_schac_home_organization') !==  'surf.nl') {
  error_log("[PERSOON]ERROR: invalid organization " . json_encode(array('email' => $email, 'givenName' => $givenName, 'familyName' => $familyName, 'homeOrganization' => $homeOrganization, 'edupersonEntitlement' => $edupersonEntitlement)));
  http_response_code(400);
  exit();
}

if($_SERVER['OIDC_CLAIM_eduperson_entitlement'] !== 'urn:mace:terena.org:tcs:personal-user' and
         getenv('OIDC_CLAIM_eduperson_entitlement') !==  'urn:mace:terena.org:tcs:personal-user') {
  error_log("[PERSOON]ERROR: missing entitlement " . json_encode(array('email' => $email, 'givenName' => $givenName, 'familyName' => $familyName, 'homeOrganization' => $homeOrganization, 'edupersonEntitlement' => $edupersonEntitlement)));
  http_response_code(400);
  exit();
}

if (!preg_match("/^[a-zA-ZàâáçéèèêëìîíïôòóùûüÂÊÎÔúÛÄËÏÖÜÀÆæÇÉÈŒœÙñý'’, -]+$/",$givenName)) {
  error_log("[PERSOON]ERROR: invalid givenName ('$givenName')");
  header("HTTP/1.1 500 Internal Server Error");
  exit();
}
if (!preg_match("/^[a-zA-ZàâáçéèèêëìîíïôòóùûüÂÊÎÔúÛÄËÏÖÜÀÆæÇÉÈŒœÙñý'’, -]+$/",$familyName)) {
  error_log("[PERSOON]ERROR: invalid familyName ('$familyName')");
  header("HTTP/1.1 500 Internal Server Error");
  exit();
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL) or !preg_match("/^[a-zA-Z0-9 +-.@]+$/",$email)) {
  error_log("[PERSOON]ERROR: invalid email ('$email')");
  header("HTTP/1.1 500 Internal Server Error");
  exit();
}

session_start();
if (empty($_POST['csrftoken']) or empty($_SESSION['csrftoken']) or $_SESSION['csrftoken'] !== $_POST['csrftoken']) {
  error_log("[PERSOON]ERROR: csrf token mismatch");
  http_response_code(400);
  exit();
}

$csr = $_POST['csr'];
// check that the CSR can be parsed and that the subject DN is empty (it is completely derived from claims)
if(openssl_csr_get_subject($csr) !== []) {
  error_log("[PERSOON]ERROR: invalid CSR or CSR subject DN not empty");
  http_response_code(400);
  exit();
}

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
if( $config === NULL ) {
  error_log("[PERSOON]ERROR: cannot parse config file");
  http_response_code(500);
  exit();
} // TODO retrieve, refactor.

$template = $config['enroll_template'];
$template['firstName'] = $givenName;
$template['lastName'] = $familyName;
$template['email'] = $email;
$template['csr'] = $csr;
$body = json_encode($template);
$uri = $config['api']['uri'];
$login = $config['api']['login'];
$key = $config['api']['key'];

#    'ignore_errors' => TRUE,
$opts = array('http' =>
  array(
    'method'  => 'POST',
    'header'  => "Content-Type: application/json;charset=utf-8\r\n".
      "Accept: application/json;charset=utf-8\r\n".
      "customerUri: $uri\r\n".
      "login: $login\r\n".
      "password: $key\r\n",
      'content' => $body,
    'timeout' => 60
  )
);

$context = stream_context_create($opts);
$url = $config['api']['order_uri'];
$result = file_get_contents($url, false, $context);

if( $result === FALSE ) {
//  http_response_code(400);
  echo '{"error":"order failed"}';
  error_log('[PERSOON]ERROR: order failed for certificate request ' . json_encode($template));
  exit();
}

$data = json_decode($result, true);
echo json_encode($data, JSON_PRETTY_PRINT);
error_log('[PERSOON]INFO: completed certificate request ' . json_encode(array_merge($template, $data)));
