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
here I will only provide the *recommended* arguments.
   
```javascript
 <script>
  $(document).ready(function(){
   $('#form-id').pidCrypt({
    appID:'<?php echo $_SESSION[$libs->_getRealIPv4()]["token"]; ?>',
    callback: function(data){ console.log(data); }
   });
  });
```

Simply echo out the server generated CSRF token to make the client aware. The
AJAX framework which accompanies this project uses customized headers to help
with data integrity in various manners.
   
## Server setup
Here we go over the necessary server settings and requirements as well as
code flow.

### Configuration
A sample configuration was deemed necessary to clarify the requirements of the
PHP OpenSSL extension. Two arrays are necessary, one specifies the runtime
configuration options including key size, algorithm for signing etc. Please
see http://www.php.net/manual/en/function.openssl-csr-new.php for more
information about this array's available options.

```php
<?php
$settings['config']['cnf']                = array('config'=>'openssl.cnf',
                                                  'x509_extensions'=>'usr_cert');
$settings['config']['expires']            = 365;
$settings['config']['private']            = true;
$settings['config']['private_key_type']   = OPENSSL_KEYTYPE_RSA;
$settings['config']['digest']             = '';
$settings['config']['keybits']            = 256;
```

The second is location specific and used when certificate creation and signing
is used. Please see http://www.php.net/manual/en/function.openssl-csr-new.php for
more information on its options and use.

```php
<?php
$settings['dn']['countryName']            = 'US';
$settings['dn']['stateOrProvinceName']    = 'Utah';
$settings['dn']['localityName']           = 'Salt Lake City';
$settings['dn']['organizationName']       = 'jQuery.pidCrypt';
$settings['dn']['organizationalUnitName'] = 'Plug-in for easy implementation of RSA public key encryption';
$settings['dn']['commonName']             = 'Jason Gerfen';
$settings['dn']['emailAddress']           = 'jason.gerfen@gmail.com';
```

It is recommended you place these above two arrays within their own configuration
file and simply include it withing your project like so.

```php
<?php
if (!file_exists('config.php')) {
 exit('config.php file does not exist');
}
include 'config.php';
```

### Includes
The project includes several core class files providing for easy implementation
and extendability. These core class files can be located in the 'libs/classes/'
folder.

#### class.libraries.php
Several re-usable functions reside within the class allowing such as retrieving
the remote clients IPv4 address, generating a valid RFC-4122 GUID & serialization
of strings.

```php
<?php
if (!file_exists('../libs/classes/class.libraries.php')) {
 exit('../libs/classes/class.libraries.php does not exist');
}
include '../libs/classes/class.libraries.php';

/* handle for libraries object */
$libs = new libraries;
```

#### class.ajax.php
This class attempts to provide methods of preventing script injections, cross
site request forgeries even going so far as to checksum the submitted form
data.

```php
<?php
/* load the ajax class */
if (!file_exists('../libs/classes/class.ajax.php')) {
 exit('../libs/classes/class.ajax.php does not exist');
}
include '../libs/classes/class.ajax.php';

/* ensure our ajax request passes required checks */
$ajax = new ajax;
if (!$ajax){
 exit($libs->JSONencode(array('error'=>'AJAX request did not pass sanity checks')));
}
```

#### class.openssl.php
An easy to use interface to PHP's OpenSSL functionality. Methods exist to seed
the random number generators, generate password protected private keys, derive
public keys, encrypt & decrypt (both symmetric and asymmetric cihpers) as well
as sign and validate signed data.

```php
<?php
if (!file_exists('../libs/classes/class.openssl.php')) {
 exit('../libs/classes/class.openssl.php does not exist');
}
include '../libs/classes/class.openssl.php';
```

### 
