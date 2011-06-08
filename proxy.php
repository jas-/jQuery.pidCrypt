<?php

/* openssl settings see http://www.php.net/manual/en/function.openssl-csr-new.php */
$settings['config']['cnf']                = array('config'=>'openssl.cnf',
                                                  'x509_extensions'=>'usr_cert');
$settings['config']['expires']            = 365;
$settings['config']['private']            = true;
$settings['config']['private_key_type']   = OPENSSL_KEYTYPE_RSA;
$settings['config']['digest']             = '';
$settings['config']['keybits']            = 256;

/* openssl location data see http://www.php.net/manual/en/function.openssl-csr-new.php */
$settings['dn']['countryName']            = 'US';
$settings['dn']['stateOrProvinceName']    = 'Utah';
$settings['dn']['localityName']           = 'Salt Lake City';
$settings['dn']['organizationName']       = 'jQuery.pidCrypt';
$settings['dn']['organizationalUnitName'] = 'Plug-in for easy implementation of
                                             RSA public key encryption';
$settings['dn']['commonName']             = 'Jason Gerfen';
$settings['dn']['emailAddress']           = 'jason.gerfen@gmail.com';

/* session init */
session_start();

/* does the class exist */
if (file_exists('libs/classes/class.openssl.php')) {
 include 'libs/classes/class.openssl.php';

 /* handle for class object */
 $openssl = openssl::instance($settings);

 if (is_object($openssl)) {
  if ((!empty($_POST))&&($_SERVER["HTTP_X_REQUESTED_WITH"]==='XMLHttpRequest')) {

   /*
    * public key?
    * If you used a database to store existing keys
    * add the support after this conditional
    */
   if ((!empty($_POST['k']))&&($_POST['k']==='true')) {

    /* Generate the private key */
    $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'] = $openssl->genPriv($_SERVER['REMOTE_ADDR']);

    /* Here we can either generate a public key or a certificate holding a public key */
    $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'] = $openssl->genPub();

    /* Because we want to avoid MITM use AES to encrypt public key first */
    if ((!empty($_POST['u']))&&(!empty($_POST['i']))){
     echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key']['key'];
     //echo $openssl->aesEnc($_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'], $_POST['u'], $_POST['i'], false, 'aes-256-cbc');
    } else {
     echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key']['key'];
    }
    exit;
   }

   /*
    * If you wish to do anything further such as add a response that the data was recieved by the server etc
    * add it here
    */
   echo 'Data recieved and processed...';
  }
 }
}

/*
 * Because of limitations with the RSA encryption
 * using public keys we may need to process an
 * array of encrypted data from the client
 */
function helper($array, $openssl)
{
 foreach($array as $key => $value) {
  if (is_array($value)) {
   foreach($value as $k => $v) {
    $b[$k] = $openssl->privDenc($v, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']);
   }
   $a[$key] = combine($b);
  } else {
   $a[$key] = $openssl->privDenc($value, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']);
  }
 }
 return $a;
}

/*
 * Put the original string back
 * together
 */
function combine($array) {
 $a = '';
 foreach($array as $k => $v) {
  $a .= $v;
 }
 return $a;
}
?>
