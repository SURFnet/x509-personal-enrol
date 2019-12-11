<?php
$cn = ($_SERVER['OIDC_CLAIM_name']);
$email = ($_SERVER['OIDC_CLAIM_email']);
if (!filter_var($email, FILTER_VALIDATE_EMAIL) or !preg_match("/^[a-zA-Z -]*$/",$cn)) {
  echo "ERROR: we could not determine your name (received '$cn') and email address (received '$email') . Please contact your helpdesk.";
  exit();
}

?>
<!DOCTYPE html>
<html>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- Add icon library -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<!-- Add pki library -->
<script src="https://cdn.jsdelivr.net/npm/node-forge@0.7.0/dist/forge.min.js"></script>
<style>
* {
  box-sizing: border-box;
}

body {
  background-color: #f1f1f1;
}

#regForm {
  background-color: #ffffff;
  margin: 100px auto;
  font-family: sans-serif;
  padding: 40px;
  width: 70%;
  min-width: 300px;
}

h1 {
  text-align: center;  
}

input {
  padding: 10px;
  width: 100%;
  font-size: 17px;
  font-family: sans-serif;
  border: 1px solid #aaaaaa;
}

/* Mark input boxes that gets an error on validation: */
input.invalid {
  background-color: #ffdddd;
}

/* Hide all steps by default: */
.tab {
  display: none;
}

button {
  background-color: #4CAF50;
  color: #ffffff;
  border: none;
  padding: 10px 20px;
  font-size: 17px;
  font-family: sans-serif;
  cursor: pointer;
}

button:hover {
  opacity: 0.8;
}

#prevBtn {
  background-color: #bbbbbb;
}

/* Make circles that indicate the steps of the form: */
.step {
  height: 15px;
  width: 15px;
  margin: 0 2px;
  background-color: #bbbbbb;
  border: none;  
  border-radius: 50%;
  display: inline-block;
  opacity: 0.5;
}

.step.active {
  opacity: 1;
}

/* Mark the steps that are finished and valid: */
.step.finish {
  background-color: #4CAF50;
}

/* Feedback messages: */
.info {
  padding: 4px 12px;
  width: 100%;
  font-size: 17px;
  font-family: sans-serif;
  position: fixed;
  bottom: 0;
  background-color: #e7f3fe;
  border-left: 6px solid #2196F3;
}
</style>
<body>

<div id="regForm">
  <h1>Request a new Certificate:</h1>
  <!-- One "tab" for each step in the form: -->
  <div class="tab">You are requesting a new certificate with the following name and email address:
    <p><input readonly value="<?php echo $cn; ?>"></p>
    <p><input readonly value="<?php echo $email; ?>"></p>
    <div style="overflow:auto;">
      <div style="float:right;">
        <button type="button" onclick="postOrder()">Next: order Certificate</button>
      </div>
    </div>
  </div>
  <div class="tab">Your certificate request has been submitted. Your certificate ID is:
    <p><input name="certificate_id" id="certificate_id"></p>
    <div style="overflow:auto;">
      <div style="float:right;">
        <button type="button" onclick="getCertificate()">Next: check for certificate</button>
      </div>
    </div>
  </div>
  <div class="tab">Install certificate:
    <p><input name="password" id="password" type="text" size="50" readonly><i class="fa fa-clipboard fa-2x" onclick="copyPasswordToClipboard()"></i></p>
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

<script>
var currentTab = 0; // Current tab is set to be the first tab (0)
showTab(currentTab); // Display the current tab

function showTab(n) {
  // This function will display the specified tab of the form...
  var x = document.getElementsByClassName("tab");
  x[n].style.display = "block";
  //... and run a function that will display the correct step indicator:
  fixStepIndicator(n)
}

function nextTab() {
  // This function will figure out which tab to display
  var x = document.getElementsByClassName("tab");
  // Exit the function if any field in the current tab is invalid:
  if (!validateForm()) return false;
  // Hide the current tab:
  x[currentTab].style.display = "none";
  // Increase or decrease the current tab by 1:
  currentTab++;
  // if you have reached the end of the form...
  if (currentTab >= x.length) {
    // ... the form gets submitted:
    // close window?
    return false;
  }
  // Otherwise, display the correct tab:
  showTab(currentTab);
}

function validateForm() {
  // This function deals with validation of the form fields
  var x, y, i, valid = true;
  x = document.getElementsByClassName("tab");
  y = x[currentTab].getElementsByTagName("input");
  // A loop that checks every input field in the current tab:
  for (i = 0; i < y.length; i++) {
    // If a field is empty...
    if (y[i].value == "") {
      // add an "invalid" class to the field:
      y[i].className += " invalid";
      // and set the current valid status to false
      valid = false;
    }
  }
  // If the valid status is true, mark the step as finished and valid:
  if (valid) {
    document.getElementsByClassName("step")[currentTab].className += " finish";
  }
  return valid; // return the valid status
}

function fixStepIndicator(n) {
  // This function removes the "active" class of all steps...
  var i, x = document.getElementsByClassName("step");
  for (i = 0; i < x.length; i++) {
    x[i].className = x[i].className.replace(" active", "");
  }
  //... and adds the "active" class on the current step:
  x[n].className += " active";
}

// certs

let keys = null;
let csr = null;
let certificate_id = null;
let certs = null;
let password = null;

function baseURL() {
  return window.location.origin + window.location.pathname.split('/').slice(0,-1).join('/');
}

function log(msg) {
    var m = document.getElementById("message");
    m.innerHTML = msg;
}

function copyPasswordToClipboard() {
  var copyText = document.getElementById("password");
  copyText.select();
  copyText.setSelectionRange(0, 99999)
  document.execCommand("copy");
  log("Copied password: " + copyText.value);
}

function generatePassword(size) {
  var bytes = forge.random.getBytesSync(size)
    return forge.util.encode64(bytes).replace(/[\+\/]/g, '').replace(/=+$/,'');
}

function generateCSR() {
    keys = forge.pki.rsa.generateKeyPair(2048);
    csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.sign(keys.privateKey, forge.md.sha256.create());
    csr = forge.pki.certificationRequestToPem(csr);
}

function postOrder() {
  var request = new XMLHttpRequest();
  // var url = "https://digicert.aai.surfnet.nl/new/request.php";
  var url = baseURL() + "/request.php";
  var params = `csr=${encodeURIComponent(csr)}`;

  request.open('POST', url, true);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  request.onreadystatechange = function() {
    if (request.readyState === XMLHttpRequest.DONE) {
      if (request.status === 200) {
          console.log(request.response);
        var response = JSON.parse(request.response);
        if (response.certificate_id) {
          certificate_id = response.certificate_id;
          document.getElementById("certificate_id").value = certificate_id;
          nextTab();
          log(`Certificate order with ID ${certificate_id} succesfully submitted.`);
        } else {
          log(`Certificate order failed`);
        }
      } else {
        log(`Certificate order failed (status ${request.status})`);
      }
    }
  };
  request.send(params);
}

function typedArrayToURL(typedArray, mimeType) {
  return URL.createObjectURL(new Blob([typedArray.buffer], {type: mimeType}))
}

function bytesToTypedArray(bytes) {
  nums = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) { nums[i] = bytes.charCodeAt(i); }
  return new Uint8Array(nums);
}

function getCertificate() {
    var request = new XMLHttpRequest();
    // var url = "https://digicert.aai.surfnet.nl/new/retrieve.php";
    var url = baseURL() + "/retrieve.php";
    var params = `certificate_id=${certificate_id}`;

    request.open('POST', url, true);
    request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    request.onreadystatechange = function() {
      if (request.readyState === XMLHttpRequest.DONE) {
        if (request.status === 200) {
            console.log(request.response);
            try {
                var response = JSON.parse(request.response);
                if (response.errors) {
                    document.getElementById('message').innerHTML = response.errors[0].message;
                }
            } catch (e) { // No JSON, no error
                var pem = request.response;
                certs = null;
                if(pem.startsWith("-----BEGIN PKCS7-----")) {
                    let p7 = forge.pkcs7.messageFromPem(pem);
                    certs = p7.certificates;
                    console.log("PKCS#7" + certs[0].subject.attributes);
                }
                nextTab();

                password = generatePassword(16);
                document.getElementById("password").value = password;
                
                // generate a p12 that can be imported by Chrome/Firefox/iOS (requires the use of Triple DES instead of AES)
                var p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, certs, password, {algorithm: '3des', generateLocalKeyId: true, friendlyName: 'key generated by p12js'});
                var p12Der = forge.asn1.toDer(p12Asn1).getBytes();
                var p12b64 = forge.util.encode64(p12Der);
                // check that end-entity-certificate public key matches generated key pair
                if( JSON.stringify(keys.publicKey) != JSON.stringify(certs[0].publicKey) ) {
                  log("ERROR: Generated RSA key does not match public key from certificate!");
                } else {
                  subject = certs[0].subject.attributes.map( (e) => e.shortName+'='+e.value ).join("/");
                  log(`Retrieved certificate for ${subject}`);
                  link = document.getElementById('p12link');
                  // link.href = `data:application/x-pkcs12;base64,${p12b64}`;
                  bytes = bytesToTypedArray(p12Der)
                  link.href = typedArrayToURL(bytes, "application/x-pkcs12");
                  // destroy keys
                  keys = csr = certificate_id = certs = password = null;
                }
            }
        }
      }
    };
    request.send(params);
}

window.addEventListener('load', function() {
  generateCSR();
  log('Succesfully generated new keys for your certificate');
});

</script>

</body>
</html>
