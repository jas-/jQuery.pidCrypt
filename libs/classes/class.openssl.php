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
  if (function_exists('openssl_pkey_new')) {
   $this->setOpt($configuration);
   $this->setDN($configuration);
   return;
  } else {
   echo 'The openssl extensions are not loaded.';
   unset($instance);
   exit;
  }
 }

 /*!
  * @function instance
  * @abstract Public class access method, implements __construct
  * @param $configuration Array Nested array of configuration options
  * @return object The class object
  */
 public static function instance($configuration)
 {
  if (!isset(self::$instance)) {
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
  * @function genPriv
  * @abstract Public method of generating new private key
  * @param $password string Passphrase used for private key creation
  * @return object The private key object
  */
 public function genPriv($password)
 {
  $this->handle = openssl_pkey_new();
  openssl_pkey_export($this->handle, $privatekey, $password);
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
  return $results;
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
 public function createx509($o, $p, $x)
 {
  $a = openssl_pkey_get_private($p, $x);
  $b = openssl_csr_new($o['dn'], $a, $o['config']);
  $c = openssl_csr_sign($b, null, $a, 365);
  openssl_x509_export($c, $d);
  return $d;
 }

 /*!
  * @function createxpkcs12
  * @abstract Export a pkcs12 file for client auth from the x.509 certificate
  * @param $c string The x.509 certificate
  * @param $k string The private key to generate a new pkcs#12 file
  * @param $p string The password originally used to create private key
  * @return string The pkcs#12 certificate
  */
 public function createpkcs12($c, $k, $p, $n='jQuery.pidCrypt', $f=false)
 {
  $key = openssl_pkey_get_private($k, $p);
  ($f===false) ?
   openssl_pkcs12_export($c, $r, $key, $p, array('friendly_name'=>
                                                 'jQuery.pidCrypt')) :
   openssl_pkcs12_export_to_file($c, $r, $key, $p, array('friendly_name'=>$n));
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

  ($_SERVER["HTTP_X_REQUESTED_WITH"] === 'XMLHttpRequest') ?
   openssl_private_decrypt($this->convertBin($crypt), $this->output, $res) :
   openssl_private_decrypt($crypt, $this->output, $res);

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
