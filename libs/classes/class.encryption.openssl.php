<?php
/**
 * Handle openssl encryption functionality
 *
 * Generate private / public key pairs
 * Use RSA encrypt / decrypt functions
 * Use AES encrypt / decrypt functions
 * Parse x509 certificates
 * Generate and use x509 certificates for email signing
 * Generate pkcs#12 certificates
 *
 * LICENSE: This source file is subject to version 3.01 of the GPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/licenses/gpl.html.  If you did not receive a copy of
 * the GPL License and are unable to obtain it through the web, please
 *
 * @category   encryption
 * @author     Jason Gerfen <jason.gerfen@gmail.com>
 * @copyright  2010-2011 Jason Gerfen
 * @license    http://www.gnu.org/licenses/gpl.html  GPL
 * @version    0.1
 */

/*!
 * @class openssl
 * @abstract Implement PHP openssl functions
 */
class openssl
{

 protected static $instance;
 private $handle=NULL;
 private $opt=array();
 private $dn=array();
 public $output;

 /*!
  * @function __construct
  * @abstract Private constructor tests for openssl libraries, sets up the
  *           required DN array and cipher options
  * @param $configuration Array Nested array of configuration options
  */
 private function __construct($configuration)
 {
  if (function_exists('openssl_pkey_new')){
   $this->setOpt($configuration);
   $this->setDN($configuration);
   return;
  } else {
   unset($instance);
   exit('The openssl extensions are not loaded.');
  }
 }

 /*!
  * @function instance
  * @abstract Public class access method, implements __construct
  * @param $configuration Array Nested array of configuration options
  * @return object The class object
  */
 public static function instance($configuration, $killswitch=false)
 {
  if ((!isset(self::$instance))||($killswitch)){
   $c = __CLASS__;
   self::$instance = new self($configuration);
  }
  return self::$instance;
 }

 /*!
  * @function setOpt
  * @abstract Copies OpenSSL cipher options to private class array
  * @param $configuration Array Nested array of configuration options
  * @return array Cipher options
  */
 private function setOpt($configuration)
 {
  $this->opt = $configuration['config'];
 }

 /*!
  * @function setDN
  * @abstract Copies OpenSSL required location data to private class array
  * @param $configuration array Nested array of configuration options
  * @return array OpenSSL location (DN) information
  */
 private function setDN($configuration)
 {
  $this->dn = $configuration['dn'];
 }

 /*!
  * @function genRand
  * @abstract Wrapper for openssl_random_pseudo_bytes with graceful degrading
  *           for weak entropy sources
  * @param $int int Size of random bytes to produce
  * @return string
  */
 public function genRand($int = 2048)
 {
  return (function_exists('openssl_random_pseudo_bytes')) ?
           bin2hex(openssl_random_pseudo_bytes($int)) :
            bin2hex($this->altRand($int));
 }

 /*!
  * @function altRand
  * @abstract Alternative random seeder
  * @param $int int Size of random bytes to produce
  * @return string
  */
 public function altRand($int = 2048)
 {
  if (is_readable('/dev/random')){
   $f=fopen('/dev/random', 'r');
   if ($f){
    $urandom=fread($f, $int);
   } else {
    return $this->_altRand($int);
   }
   fclose($f);
  } else {
   return $this->_altRand($int);
  }
  $return='';
  for ($i=0;$i<$int;++$i){
   if (!isset($urandom)){
    if ($i%2==0){
     mt_srand(time()%2147 * 1000000 + (double)microtime() * 1000000);
    }
    $rand=48+mt_rand()%64;
   } else {
    $rand=48+ord($urandom[$i])%64;
    if ($rand>57){
     $rand+=7;
    }
    if ($rand>90){
     $rand+=6;
    }
    if ($rand==123) $rand=45;
    if ($rand==124) $rand=46;
    $return.=chr($rand);
   }
  }
  return $return;
 }

 /*!
  * @function _altRand
  * @abstract Alternative random seeder
  * @param $int int Size of random bytes to produce
  * @return string
  */
 public function _altRand($int = 2048)
 {
  for ($i=0;$i<$int;++$i){
   if ($i%2==0){
    mt_srand(time()%2147 * 1000000 + (double)microtime() * 1000000);
   }
   $rand=48+mt_rand()%64;
   $r.=chr($rand);
  }
  return $r;
 }

 /*!
  * @function genPriv
  * @abstract Public method of generating new private key
  * @param $password string Passphrase used for private key creation
  * @return object The private key object
  */
 public function genPriv($password)
 {
  $this->handle = openssl_pkey_new($this->opt);
  openssl_pkey_export($this->handle, $privatekey, $password, $this->opt);
  return $privatekey;
 }

 /*!
  * @function genPub
  * @abstract Public method of obtaining public key
  * @return array The public key and its bit size
  */
 public function genPub()
 {
  $results = openssl_pkey_get_details($this->handle);
  return $results['key'];
 }

 /*!
  * @function parsex509
  * @abstract Public method of parsing x.509 certificate
  * @param $certificate file or string x.509 certificate file or string
  * @return array The decoded x.509 certificate parameters
  */
 public function parsex509($certificate)
 {
  return openssl_x509_parse(openssl_x509_read($certificate));
 }

 /*!
  * @function createx509
  * @abstract Public method to create a signed x.509 certificate
  * @param $o array An array of options for both DN and SSL configuration opts
  * @param $p string The private key to create a new CSR with
  * @param $x string The password originally used to create private key
  * @return string The x.509 certificate
  */
 public function createx509($o, $p, $x, $f=false)
 {
  $a = openssl_pkey_get_private($p, $x);
  $b = openssl_csr_new($o['dn'], $a, $o['config']);
  $c = openssl_csr_sign($b, null, $a, 365);
  ($f===false) ? openssl_x509_export($c, $d) : openssl_x509_export_to_file($c, $f);
  return ($f===false) ? $d :$f;
 }

 /*!
  * @function signx509
  * @abstract Use a x.509 certificate to sign data
  * @param $fin string Path to file of email contents
  * @param $fout string Path to file once signed
  * @param $c string x.509 certificate used to sign email
  * @param $p mixed Private key or array of private key and password
  * @param $o array Array of header information regarding email
  */
 public function signx509($fin, $fout, $c, $p, $o)
 {
  openssl_pkcs7_sign($fin, $fout, $c, $p, $o);
  return $fout;
 }

 /*!
  * @function verifyx509
  * @abstract Verify a signed message
  * @param $fin string Path to file of email contents
  * @param $f integer PKCS7 flag
  * @param $fout string Path to file once signed
  * @param $c string x.509 certificate used to sign email
  * @param $p mixed Private key or array of private key and password
  * @param $o array Array of header information regarding email
  */
 public function verifyx509($fin, $fout, $c=array(), $p=null, $o=null,
                            $f=PKCS7_TEXT)
 {
  openssl_pkcs7_verify($fin, $f, $fout, $c, $p, $o);
  return $fout;
 }

 /*!
  * @function encryptx509
  * @abstract Use public key to encrypt email
  * @param $fin string Path to file of email contents
  * @param $fout string Path to file once signed
  * @param $c string Public key used to encrypt data
  * @param $o array Array of header information regarding email
  */
 public function encryptx509($fin, $fout, $k, $o)
 {
  openssl_pkcs7_encrypt($fin, $fout, $k, $o);
  return $fout;
 }

 /*!
  * @function createpkcs12
  * @abstract Export a pkcs12 file for client auth from the x.509 certificate
  * @param $c string The x.509 certificate
  * @param $k string The private key to generate a new pkcs#12 file
  * @param $p string The password originally used to create private key
  * @return string The pkcs#12 certificate
  */
 public function createpkcs12($c, $k, $p,
                              $a=array('friendly_name'=>'',
                                       'extracerts'=>''), $f=false, $d=false)
 {
  $key = openssl_pkey_get_private($k, $p);
  ($f===false) ?
   openssl_pkcs12_export($c, $r, $key, $p, $a) :
   openssl_pkcs12_export_to_file($c, $r, $key, $p, $a);
  return $r;
 }

 /*!
  * @function readpkcs12
  * @abstract Read a pkcs12 file into an array
  * @param $c string The pkcs12 certificate
  * @param $p string The password originally used to create pkcs12 certificate
  * @return array The pkcs#12 certificate details
  */
 public function readpkcs12($c, $p)
 {
  openssl_pkcs12_read($c, $r, $p);
  return $r;
 }

 /*!
  * @function enc
  * @abstract Public method of encrypting data using private key
  * @param $private object Private key object used to encrypt data
  * @param $data string Data to be encrypted
  * @param $password string Passphrase used to create private key
  * @return string The encrypted data
  */
 public function enc($private, $data, $password)
 {
  if ((!empty($private))&&(!empty($data))) {
   $res = openssl_get_privatekey($private, $password);
   openssl_private_encrypt($data, $this->output, $res);
   return $this->output;
  } else {
   return FALSE;
  }
 }

 /*!
  * @function pubDenc
  * @abstract Public method of using public key to decrypt data that was
  *           encrypted using the private key
  * @param $crypt string Encrypted data
  * @param $key object Private key object used to create certificate
  * @return string The decrypted string
  */
 public function pubDenc($crypt, $key)
 {
  $res = (is_array($key)) ? openssl_get_publickey($key['key']) :
                            openssl_get_publickey($key);
  ($_SERVER["HTTP_X_REQUESTED_WITH"]==='XMLHttpRequest') ?
   openssl_public_decrypt($this->convertBin($crypt), $this->output, $res) :
   openssl_public_decrypt($crypt, $this->output, $res);
  return ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ?
   base64_decode($this->output) : $this->output;
 }

 /*!
  * @function privDenc
  * @abstract Public method of using the private key to decrypt data that was
  *           encrypted using the private key
  * @param $crypt string String to be encrypted
  * @param $key object Private key object used to create certificate
  * @param $pass string Passphrase used to generate private key
  * @return string The decrypted string
  */
 public function privDenc($crypt, $key, $pass)
 {
  $res = (is_array($key)) ? openssl_get_privatekey($key['key'], $pass) :
                            openssl_get_privatekey($key, $pass);
  if (is_resource($res)){
   ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ?
     openssl_private_decrypt($this->convertBin($crypt), $this->output, $res) :
     openssl_private_decrypt($crypt, $this->output, $res);
  } else {
   return false;
  }
  return ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ?
    base64_decode($this->output) : $this->output;
 }

 /*!
  * @function aesEnc
  * @abstract Public method of encryption using AES
  * @param $data string String to be encrypted
  * @param $password string Passphrase used for encryption
  * @param $iv int Integer 16bits in length
  * @param $raw boolean Raw encryption
  * @param $cipher string Encryption cipher
  * @return string The encrypted string
  */
 public function aesEnc($data, $password, $iv='', $raw=false, $cipher='aes-256-cbc')
 {
  return openssl_encrypt($data, $cipher, $password, $raw, $iv);
 }

 /*!
  * @function aesDenc
  * @abstract Public method of decryption using AES
  * @param $data string String to be encrypted
  * @param $password string Passphrase used for encryption
  * @param $iv int Integer 16bits in length
  * @param $raw boolean Raw encryption
  * @param $cipher string Encryption cipher
  * @return string The decrypted string
  */
 public function aesDenc($data, $password, $iv='', $raw=false, $cipher='aes-256-cbc')
 {
  return openssl_decrypt($data, $cipher, $password, $raw, $iv);
 }

 /*!
  * @function sign
  * @abstract Sign specified data using private key
  * @param $data string Data to sign
  * @param $key string Private key
  * @param $algo boolean Signature algorithm (default sha512)
  * @return string The signature assocated with data
  */
 public function sign($data, $key, $pass=null, $algo="sha512")
 {
  $id = openssl_pkey_get_private($key, $pass);
  openssl_sign($data, $signature, $id, $algo);
  openssl_free_key($id);
  return ($signature) ? base64_encode($signature) : false;
 }

 /*!
  * @function verify
  * @abstract verify signature on data
  * @param $data string Data to verify
  * @param $public string Users public key
  * @param $algo boolean Signature algorithm (default sha512)
  * @return string The signature assocated with data
  */
 public function verify($data, $sig, $key, $algo="sha512")
 {
  $id = openssl_pkey_get_public($key);
  $r = openssl_verify($data, $sig, $id, $algo);
  openssl_free_key($id);
  return $r;
 }

 /*!
  * @function convertBin
  * @abstract Private function to convert hex data to binary
  * @param $key string Hexadecimal data
  * @return string The binary equivelant
  */
 private function convertBin($key)
 {
  $data='';
  $hexLength = strlen($key);
  if ($hexLength % 2 != 0 || preg_match("/[^\da-fA-F]/", $key)) { $binString = -1; }
  unset($binString);
  for ($x = 1; $x <= $hexLength / 2; $x++) {
   $data .= chr(hexdec(substr($key, 2 * $x - 2, 2)));
  }
  return $data;
 }
}
?>
