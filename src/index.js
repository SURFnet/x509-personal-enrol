import { random, util, pki, md, pkcs7, pkcs12, asn1 } from 'node-forge';

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
    m.textContent = msg;
}

function copyPasswordToClipboard() {
  var copyText = document.getElementById("password");
  copyText.select();
  copyText.setSelectionRange(0, 99999)
  document.execCommand("copy");
  log("Copied password: " + copyText.value);
}

function generatePassword(size) {
  var bytes = random.getBytesSync(size)
    return util.encode64(bytes).replace(/[\+\/]/g, '').replace(/=+$/,'');
}

function generateCSR() {
    keys = null;
    pki.rsa.generateKeyPair( {bits: 2048, workers: 2}, function(err, keypair) {
      keys = keypair;
      csr = pki.createCertificationRequest();
      csr.publicKey = keys.publicKey;
      csr.sign(keys.privateKey, md.sha256.create());
      csr = pki.certificationRequestToPem(csr);
    });
}

function postOrder() {
  var request = new XMLHttpRequest();
  // var url = "https://digicert.aai.surfnet.nl/new/request.php";
  var url = baseURL() + "/request.php";
  var token = document.querySelector("meta[name='csrftoken']").getAttribute("content");
  var params = `csr=${encodeURIComponent(csr)}&csrftoken=${token}`;

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
  let nums = new Array(bytes.length);
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
                    log(response.errors[0].message);
                }
            } catch (e) { // No JSON, no error
                var pem = request.response;
                certs = null;
                if(pem.startsWith("-----BEGIN PKCS7-----")) {
                    let p7 = pkcs7.messageFromPem(pem);
                    certs = p7.certificates;
                    console.log("PKCS#7" + certs[0].subject.attributes);
                }
                nextTab();

                password = generatePassword(16);
                document.getElementById("password").value = password;
                
                // generate a p12 that can be imported by Chrome/Firefox/iOS (requires the use of Triple DES instead of AES)
                var p12Asn1 = pkcs12.toPkcs12Asn1(keys.privateKey, certs, password, {algorithm: '3des', generateLocalKeyId: true, friendlyName: 'key generated by p12js'});
                var p12Der = asn1.toDer(p12Asn1).getBytes();
                var p12b64 = util.encode64(p12Der);
                // check that end-entity-certificate public key matches generated key pair
                if( JSON.stringify(keys.publicKey) != JSON.stringify(certs[0].publicKey) ) {
                  log("ERROR: Generated RSA key does not match public key from certificate!");
                } else {
                  var subject = certs[0].subject.attributes.map( (e) => e.shortName+'='+e.value ).join("/");
                  log(`Retrieved certificate for ${subject}`);
                  var link = document.getElementById('p12link');
                  // link.href = `data:application/x-pkcs12;base64,${p12b64}`;
                  let bytes = bytesToTypedArray(p12Der)
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

document.getElementById("postOrder").onclick = postOrder;
document.getElementById("getCertificate").onclick = getCertificate;
document.getElementById("copyPasswordToClipboard").onclick = copyPasswordToClipboard;
