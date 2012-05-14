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
* A modern browser (doh!)

## FEATURES:
* Multiple key support
* AES-256-CBC encryption of all keyring data
* Modal window dialog for selection of appropriate keyring entry when multiple keys exist
* HTML5 localStorage support
* HTML5 sessionStorage support
* Cookie support
* Debugging output

## OPTIONS:
* appID: Optional CSRF token
* storage: HTML5 localStorage, sessionStorage and cookies supported
* callback: Optional function used once server recieves encrypted data
* preCallback: Optional function to perform prior to form submission
* errCallback: Optional function to perform on errors

## EXAMPLES:
Here are a few usage examples to get you started

Default usage using HTML5 localStorage

```javascript
$('#form').pidCrypt();
```

Default Using HTML5 sessionStorage

```javascript
$('#form').pidCrypt({storage:'sessionStorage'});
```

Default using cookies (requires the jQuery cookie plug-in)

```javascript
$('#form').pidCrypt({storage:'cookie'});
```

Example of using the callback method to process server response

```javascript
$('#form').pidCrypt({callback:function(){ console.log(this); }});
```

Example of using the preCallback method to load a function prior to form
submission

```javascript
$('#form').pidCrypt({preCallback:function(){ console.log(this); }});
```

Example of using the errCallback method to load a function on error

```javascript
$('#form').pidCrypt({preCallback:function(){ console.log(this); }});
```

Example of enabling a custom CSRF token (sets the X-Alt-Referer header value)

```javascript
$('#form').pidCrypt({appID:'<?php echo $_SESSION['csrf-token']; ?>'});
```

Author: Jason Gerfen <jason.gerfen@gmail.com>
License: GPL (see LICENSE)
