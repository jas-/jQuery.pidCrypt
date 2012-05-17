#jQuery.pidCrypt an implementation guide

## Requirements:
* jQuery libraries (required - http://www.jquery.com)
* pidCrypt RSA & AES libraries (required - https://www.pidder.com/pidcrypt/)
* jQuery cookie plugin (optional - http://plugins.jquery.com/files/jquery.cookie.js.txt)
* OpenSSL < 0.9.8
* PHP < 5.3
* A modern browser (doh!)


## Client setup
Here is a simple method of getting the necessary requirements in place to
begin implementing this project.

### Includes:
The necessary libraries must be included. In the following example I am
including the minified versions of the pidCrypt JS libraries as well as the
CDN minified version of the latest stable jQuery libraries and finally
including the minified version of the client for this project.

```html
 <!-- Latest CDN version of jQuery -->
 <script src="http://code.jquery.com/jquery.min.js"></script>

 <!-- Latest minified versions of pidCrypt library -->
 <script src="libs/js/pidCrypt/javascripts/compressed/pidcrypt_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/pidcrypt_util_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/md5_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/sha512_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/asn1_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/jsbn_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/rng_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/prng4_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/rsa_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/aes_core_c.js"></script>
 <script src="libs/js/pidCrypt/javascripts/compressed/aes_cbc_c.js"></script>

 <!-- Latest minified version of this plug-in -->
 <script src="libs/js/jquery.pidCrypt.min.js"></script>
```

### Binding:
Next bind the plug-in to the form you wish to provide RSA public key
encryption for. There are several options available for the plug-in however
here I will only provide the *recommended* argument.
   
```javascript
 <script>
  $(document).ready(function(){
   $('#form-id').pidCrypt({
    appID:'<?php echo $_SESSION[$libs->_getRealIPv4()]["token"]; ?>'
   });
  });
 </script>
```

Simply echo out the server generated CSRF token to make the client aware. The
AJAX framework which accompanies this project uses customized headers to help
with data integrity.
   
## 