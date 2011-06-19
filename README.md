
#jQuery plugin to impliment RSA public key encryption

  Utilizes the pidCrypt libraries for client public key
  encryption while the associated PHP class uses
  OpenSSL to generate the necessary private/public key pairs used
  by this plug-in

  Fork me @ https://www.github.com/jas-/jQuery.pidCrypt

## REQUIREMENTS:
* jQuery libraries (required - http://www.jquery.com)
* pidCrypt RSA & AES libraries (required - https://www.pidder.com/pidcrypt/)
* jQuery cookie plugin (optional - http://plugins.jquery.com/files/jquery.cookie.js.txt)
* OpenSSL < 0.9.8
* PHP < 5.3

## FEATURES:
* HTML5 localStorage support
* HTML5 sessionStorage support
* Cookie support
* Debugging output

## METHODS:
* Default: Uses public key to encrypt form data prior to sending
* Sign: Uses public key to sign data being emailed to recipient
* Encypt_sign: Uses public key to encrypt and send email to recipient
* Authenticate: Uses PKCS#12 PEM encoded certificaes for passwordless authentication

## OPTIONS:
* storage: HTML5 localStorage, sessionStorage and cookies supported
* callback: Optional function used once server recieves encrypted data
* reset: Prevent local caching of public key (forces server requests)
* debug: Appends debugging information

## EXAMPLES:

### DEFAULT USAGE:
* Default usage using HTML5 localStorage
```$('#form').pidCrypt();```

* Default Using HTML5 sessionStorage
```$('#form').pidCrypt({storage:'sessionStorage'});```

* Default using cookies (requires the jQuery cookie plug-in)
```$('#form').pidCrypt({storage:'cookie'});```

* Example of using the callback method to process server response
```$('#form').pidCrypt({callback:function(){ console.log('foo'); }});```

* Disable local caching of public key
```$('#form').pidCrypt({cache:false});```

* Enable debugging output
```$('#form').pidCrypt({debug:true});```

### Using PKCS#7 email signing:
* Using a PKCS#7 certificate for email signing
```$('#form').pidCrypt('sign');```

* Using a PKCS#7 certificate for email signing and sessionStorage
```$('#form').pidCrypt('sign',{storage:'sessionStorage'});```

* Using a PKCS#7 certificate for email signing and cookies (requires the jQuery cookie plug-in)
```$('#form').pidCrypt('sign',{storage:'cookie'});```

* Using a PKCS#7 certificate for email signing using the callback method to process server response
```$('#form').pidCrypt('sign',{callback:function(){ console.log('foo'); }});```

* Using a PKCS#7 certificate for email signing while disabling local caching of public key
```$('#form').pidCrypt('sign',{cache:false});```

* Using a PKCS#7 certificate for email signing while enabling debugging output
```$('#form').pidCrypt('sign',{debug:true});```

### Using PKCS#7 email encryption and signing
* Using a PKCS#7 certificate for email encryption & signing
```$('#form').pidCrypt('encrypt_sign');```

* Using a PKCS#7 certificate for email encryption & signing and sessionStorage
```$('#form').pidCrypt('encrypt_sign',{storage:'sessionStorage'});```

* Using a PKCS#7 certificate for email encryption & signing and cookies (requires the jQuery cookie plug-in)
```$('#form').pidCrypt('encrypt_sign',{storage:'cookie'});```

* Using a PKCS#7 certificate for email signing using the callback method to process server response
```$('#form').pidCrypt('sign',{callback:function(){ console.log('foo'); }});```

* Using a PKCS#7 certificate for email encryption & signing while disabling local caching of public key
```$('#form').pidCrypt('encrypt_sign',{cache:false});```

* Using a PKCS#7 certificate for email encryption & signing while enabling debugging output
```$('#form').pidCrypt('encrypt_sign',{debug:true});```

### Using PKCS#12 certificate authentication
* Using a PKCS#12 certificate for authentication
```$('#form').pidCrypt('authenticate');```

* Using a PKCS#12 certificate for authentication with sessionStorage
```$('#form').pidCrypt('authenticate',{storage:'sessionStorage'});```

* Using a PKCS#12 certificate for authentication with cookies (requires the jQuery cookie plug-in)
```$('#form').pidCrypt('authenticate',{storage:'cookie'});```

* Using a PKCS#12 certificate for authentication while using the callback method to process server response
```$('#form').pidCrypt('authenticate',{callback:function(){ console.log('foo'); }});```

* Using a PKCS#12 certificate for authentication while disabling local caching of public key
```$('#form').pidCrypt('authenticate',{cache:false});```

* Using a PKCS#12 certificate for authentication while enabling debugging output
```$('#form').pidCrypt('authenticate',{debug:true});```

## TODO:
* Add PKCS#7 signed email validation
* Add PKCS#7 email decryption and signed validation
* Add stricter conditional regarding authentication with PKCS#12 certificates

Author: Jason Gerfen <jason.gerfen@gmail.com>
License: GPL (see LICENSE)
