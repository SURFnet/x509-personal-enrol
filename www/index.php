<?php

$cn = ($_SERVER['OIDC_CLAIM_name']) or $cn = getenv('OIDC_CLAIM_name');
$email = $_SERVER['OIDC_CLAIM_email'] or $email = getenv('OIDC_CLAIM_email');
if (!preg_match("/^[a-zA-Z -]+$/",$cn)) {
  echo "ERROR: we could not determine your name (received '<code>" . htmlspecialchars($cn) . "</code>'). Please contact your helpdesk.";
  exit();
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL) or !preg_match("/^[a-zA-Z0-9 +-.@]+$/",$email)) {
  echo "ERROR: we could not determine your email address (received '<code>" . htmlspecialchars($email) . "</code>'). Please contact your helpdesk.";
  exit();
}

?>
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- Add icon library -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" href="style.css">
</head>
<body>

<div id="regForm">
  <h1>Request a new Certificate:</h1>
  <!-- One "tab" for each step in the form: -->
  <div class="tab">You are requesting a new certificate with the following name and email address:
    <p><input readonly value="<?php echo $cn; ?>"></p>
    <p><input readonly value="<?php echo $email; ?>"></p>
    <div style="overflow:auto;">
      <div style="float:right;">
        <button type="button" id="postOrder">Next: order Certificate</button>
      </div>
    </div>
  </div>
  <div class="tab">Your certificate request has been submitted. Your certificate ID is:
    <p><input name="certificate_id" id="certificate_id"></p>
    <div style="overflow:auto;">
      <div style="float:right;">
        <button type="button" id="getCertificate">Next: retrieve new certificate</button>
      </div>
    </div>
  </div>
  <div class="tab">Download your certificate. To install, open the certificate.p12 file from your Download folder and enter the password below:
    <p><input name="password" id="password" type="text" size="50" readonly><i class="fa fa-clipboard fa-2x" id="copyPasswordToClipboard"></i></p>
    <div style="overflow:auto;">
      <div style="float:right;">
      <a id="p12link" class="button" href="#" rel="noopener" download="certificate.p12"><button type="button" class="btn"><i class="fa fa-download"></i> Download .p12</button></a>
      <a class="button" href="https://x509test.aai.surfnet.nl/cgi-bin/env"><button type="button" class="btn">Optional: Test your certificate</button></a>
     </div>
    </div>
  </div>
  <!-- Circles which indicates the steps of the form: -->
  <div style="text-align:center;margin-top:40px;">
    <span class="step"></span>
    <span class="step"></span>
    <span class="step"></span>
  </div>
</div>

<div id="message" class="info">Generating keys...</div>

<script src="main.js"></script>

</body>
</html>
