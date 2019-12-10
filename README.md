# x509-personal-enrol

Simple application to enrol a personal X.509 certificate in modern browsers (lacking support for the keygen element).

# Motivation

To obtain a personal X.509 certificate you need to generate a public/private key pair, and submit the public key to a Certification Authority (CA).
Such a key pair can be generated in your browser using the HTML [KEYGEN element](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen).
However, this element will soon be [no longer supported](https://lists.w3.org/Archives/Public/public-html/2016Jun/0001.html) by modern browsers.
An alternative is to submit a PKCS #10 Certificate Signing Request (CSR) to your Certification Authority (CA).
Such a CSR can be generated by tools like [OpenSSL](openssl.org), which require users to be familiar with a command-line interface,
and which is not installed by default on Windows systems.

However,
[modern browsers](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/keygen#Browser_compatibility)
support the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), providing native methods for
[generating key pairs](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey).

This allows for a JavaScript implementation of a "wizzard" for generating key pairs, CSRs,
and combining the resulting certificate received from the CA into a PKCS#12 file in a
[standalone, client-side implementation](dist/index.html).

# CA backend

This implementation currently only supports DigiCert as backend Certification Authority using its API.

# Install

- Install Apache web server with `mod_ssl` and the default-ssl vhost, using a proper server certificate
- Also install `mod_php` and `mod_auth_openidc`
- Configure your PHP-enabled webroot to point to this repository's content and configure your OpenID Connect Provider such that the following claims are available:
`name`, `email`, and optinally `eduperson_entitlement` and `schac_home_organization`.

Instead of OpenID Connect, you can also use SAML by replacing `mod_auth_openidc` with `mood_shib` from [Shibboleth](https://wiki.shibboleth.net/confluence/display/CONCEPT/Home).


# Configuration

Use the example configuration to specify options needed for obtaining certificates:

    cp config.json.example config.json
    
Obtain an API key for your Digicert CertCentral account and configure it in the `api` section at entry `key`.
In the `request_template` section, fill in your `organization.id` and the `container.id`.

# User authentication

Users need to authenticate

# Known Issues

TO DO

## Credits

- Thanks to [Digital Bazaar](https://digitalbazaar.com) for their PKCS#12 implementation in [forge](https://github.com/digitalbazaar/forge)
- Thanks to [Zmartzone](https://www.zmartzone.eu) for their OpenID Connect implementation for Apache Web Server [mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc)
