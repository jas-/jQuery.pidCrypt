<?php

/* session init */
session_start();

/* fix sync problems or delete session file */
//unset($_SESSION); exit();

/* does our configuration file exist? */
if (!file_exists('config.php')) {
 exit('config.php file does not exist');
}
include 'config.php';

/* load the libraries class */
if (!file_exists('../libs/classes/class.libraries.php')) {
 exit('../libs/classes/class.libraries.php does not exist');
}
include '../libs/classes/class.libraries.php';

/* handle for libraries object */
$libs = new libraries;

/* load the ajax class */
if (!file_exists('../libs/classes/class.ajax.php')) {
 exit('../libs/classes/class.ajax.php does not exist');
}
include '../libs/classes/class.ajax.php';

/* load the openssl class */
if (!file_exists('../libs/classes/class.openssl.php')) {
 exit('../libs/classes/class.openssl.php does not exist');
}
include '../libs/classes/class.openssl.php';

/* verify settings */
if (!verify($settings)) {
 exit($libs->JSONencode(array('error'=>'Please configure the config.php file')));
}

/* handle for class object */
$openssl = openssl::instance($settings);

if (!is_object($openssl)) {
 exit($libs->JSONencode(array('error'=>'An error occured when initializing the OpenSSL class')));
}

if (!empty($_POST)) {

 /* ensure our ajax request passes required checks */
 $ajax = new ajax;
 if (!$ajax){
  exit($libs->JSONencode(array('error'=>'AJAX request did not pass sanity checks')));
 }

 /* make sure we have our necessary data, creates new keypair if not */
 if ((empty($_SESSION[$libs->_getRealIPv4()]['default']['private-key']))||
     (empty($_SESSION[$libs->_getRealIPv4()]['default']['public-key']))){
  create($settings, $openssl, $libs, 'default');
 }

 /*
  * public key?
  * If you used a database to store existing keys
  * add the support after this conditional
  */
 if ((!empty($_POST['key']))&&($_POST['key']==='true')){
  exit($libs->JSONencode(array('key'=>$_SESSION[$libs->_getRealIPv4()]['default']['public-key'])));
 }

 /* if more then two keyring entries exist with our users session pick the last entry */
 $c = count($_SESSION[$libs->_getRealIPv4()]);
 $email = ($c >= 2) ? array_pop(array_keys($_SESSION[$libs->_getRealIPv4()])) : 'default';

 /*
  * If you wish to do anything further such as add a response that the data was recieved by the server etc
  * add it here (this is EXAMPLE ONLY because it decrypts the sent data)
  */
 $x = $libs->JSONencode(helper($_POST, $openssl, $libs, $_SESSION[$libs->_getRealIPv4()][$email]['private-key']));

 /*
  * We create and append a new keyring entry for the client to store based on the email
  * that was provided. This is example code only and a database driven example should be
  * developed within your project. Please see the implementation guide for more information.
  */
 exit($libs->JSONencode(array('success'=>$x,'keyring'=>keyring($settings, $openssl, $libs, $x))));
}

/*
 * Create private/public/certificate for referring machine (stored in sessions)
 */
function create($settings, $openssl, $libs, $email)
{
 /* seed the generator */
 $openssl->genRand();

 /* Generate the private key */
 $_SESSION[$libs->_getRealIPv4()][$email]['private-key'] = $openssl->genPriv($libs->_getRealIPv4());

 /* Get the public key */
 $_SESSION[$libs->_getRealIPv4()][$email]['public-key'] = $openssl->genPub();
}

/*
 * Create a new keyring for the response to allow for multiple local public keys
 */
function keyring($s, $ssl, $libs, $d)
{
 $r = '';
 if (!empty($d)){

  /* decode object */
  $obj = json_decode($d);

  /* call create() if keyring entry doesnt exist & $obj->{'email'} is valid */
  if ((!array_key_exists($obj->{'email'}, $_SESSION[$libs->_getRealIPv4()]))&&(!empty($obj->{'email'}))) {
   create($s, $ssl, $libs, $obj->{'email'});
  }

  /* create new array with public key and associated email */
  $r = (!empty($obj->{'email'})) ? array('email'=>$obj->{'email'}, 'key'=>$_SESSION[$libs->_getRealIPv4()][$obj->{'email'}]['public-key']) : $r;
 }
 return $r;
}

/*
 * Verify our $settings array
 */
function verify($array)
{
 return ((!empty($array['dn']['countryName']))&&
         (!empty($array['dn']['stateOrProvinceName']))&&
         (!empty($array['dn']['localityName']))&&
         (!empty($array['dn']['organizationName']))&&
         (!empty($array['dn']['organizationalUnitName']))&&
         (!empty($array['dn']['commonName']))&&
         (!empty($array['dn']['emailAddress']))) ? true : false;
}

/*
 * Because of limitations with the RSA encryption
 * using public keys we may need to process an
 * array of encrypted data from the client
 */
function helper($array, $openssl, $libs, $pkey)
{
 if (is_array($array)) {
  foreach($array as $key => $value) {
   if (is_array($value)) {
    foreach($value as $k => $v) {
     $b[$k] = $openssl->privDenc($v, $pkey, $libs->_getRealIPv4());
    }
    $a[$key] = combine($b);
   } else {
    $a[$key] = $openssl->privDenc($value, $pkey, $libs->_getRealIPv4());
   }
  }
 } else {
  $a = $openssl->privDenc($array, $pkey, $libs->_getRealIPv4());
 }
 return $a;
}

/*
 * Put the original string back
 * together
 */
function combine($array) {
 $a = '';
 if (is_array($array)){
  foreach($array as $k => $v) {
   if (is_array($v)) {
    combine($array);
   } else {
    $a .= $v;
   }
  }
 } else {
  $a = $array;
 }
 return $a;
}

?>
