<?php

/* session init */
session_start();

/* does our configuration file exist? */
if (!file_exists('config.php')) {
 exit('config.php file does not exist');
}
include 'config.php';

/* does the class exist */
if (!file_exists('../libs/classes/class.openssl.php')) {
 exit('../libs/classes/class.openssl.php does not exist');
}
include '../libs/classes/class.openssl.php';

/* verify settings */
if (!verify($settings)) {
 exit('Please configure the config.php file');
}

/* handle for class object */
$openssl = openssl::instance($settings);

if (!is_object($openssl)) {
 exit('An error occured when initializing the OpenSSL class');
}

if (strcmp($_SERVER['HTTP_X_REQUESTED_WITH'], 'XMLHttpRequest')!==0){
 exit('An XMLHttpRequest was not made');
}

if (strcmp($_SERVER['HTTP_X_ALT_REFERER'], 'jQuery.pidCrypt')!==0){
 exit('The X-Alt-Referer information recieved is invalid');
}

if (!empty($_POST)) {

 /* make sure we have our necessary data */
 if ((empty($_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key']))||
     (empty($_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key']))||
     (empty($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']))||
     (empty($_SESSION[$_SERVER['REMOTE_ADDR'].'-pkcs12']))){
  create($settings, $openssl);
 }

 /*
  * Use locale/email/pin private key to decode pkcs#12 session
  * varibale and compare pkcs#7 with pkcs#7 session
  */
 if ((!empty($_POST['do']))&&($_POST['do']==='authenticate')) {
  exit(authenticate($_POST['c'], $openssl));
 }

 /*
  * public key?
  * If you used a database to store existing keys
  * add the support after this conditional
  */
 if ((!empty($_POST['k']))&&($_POST['k']==='true')) {

  /* Because we want to avoid MITM use AES to encrypt public key first */
  if ((!empty($_POST['u']))&&(!empty($_POST['i']))){
   echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'];
   // until I can resolve the problems with the pidCrypt AES-CBC to
   // PHP's OpenSSL AES-CBC decryption formats this is disabled
   //echo $openssl->aesEnc($_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'], $_POST['u'], $_POST['i'], false, 'aes-256-cbc');
  } else {
   echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'];
  }
  exit;
 }

 /* was a passphrase/pin specified? make a unique key pair */
 if ((!empty($_POST['pin']))&&(!empty($_POST['cert']))&&
     ($_POST['cert']==='true')&&(!empty($_POST['email']))) {

  /* setup DN information specific to this user vs. computer */
  $settings['dn'] = parsegeo(geolocation($_SERVER['REMOTE_ADDR']), $_SERVER['REMOTE_ADDR'],
                             $openssl->privDenc($_POST['email'],
                                                $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                                                $_SERVER['REMOTE_ADDR']),
                             $settings);
  create($settings, $openssl, $_POST['pin'], true);

  /* Because we want to avoid MITM use AES to encrypt public key first */
  if ((!empty($_POST['u']))&&(!empty($_POST['i']))){
   echo base64_encode($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']);
   // until I can resolve the problems with the pidCrypt AES-CBC to
   // PHP's OpenSSL AES-CBC decryption formats this is disabled
   //echo $openssl->aesEnc($_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'], $_POST['u'], $_POST['i'], false, 'aes-256-cbc');
  } else {
   echo base64_encode($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']);
  }
  exit;
 }

 /*
  * PKCS#12 certificate
  * If you used a database to store existing certificates
  * add the support after this conditional
  */
 if (($_POST['c']==='true')&&(!empty($_POST['pin']))&&(empty($_POST['do']))) {

  if ((!empty($_POST['u']))&&(!empty($_POST['i']))){
   echo base64_encode($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']);
  } else {
   echo base64_encode($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']);
  }
  exit;
 }
}

/*
 * Create private/public/certificate for referring machine (stored in session)
 */
function create($settings, $openssl, $pin='', $reset=false)
{
 echo '<pre>'; print_r($_SESSION); echo '</pre>';
 $pin = (!empty($pin)) ?
  $openssl->privDenc($pin, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                     $_SERVER['REMOTE_ADDR']) : false;

 /* Generate the private key */
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'] = (($pin!==false)&&($reset===true)) ?
  $openssl->genPriv($pin) :
  $openssl->genPriv($_SERVER['REMOTE_ADDR']);

 /* Get the public key */
 $k = $openssl->genPub();
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'] = $k['key'];
//echo '<pre>'; print_r($settings); echo '</pre>';
 /* Create certificate */
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'] = (($pin!==false)&&($reset===true)) ?
  $openssl->createx509($settings, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                       $pin) :
  $openssl->createx509($settings, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                       $_SERVER['REMOTE_ADDR']);

 /* Create pkcs12 password protected certificate for authenticaiton */
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-pkcs12'] = (($pin!==false)&&($reset===true)) ?
  $openssl->createpkcs12($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'],
                         $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                         $pin) :
  $openssl->createpkcs12($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'],
                         $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                         $_SERVER['REMOTE_ADDR']);
 echo '<pre>'; print_r($_SESSION); echo '</pre>';
}

/*
 * decode and authenticate using pkcs12 certificate
 */
function authenticate($cert, $openssl)
{
 $a = $openssl->readpkcs12($_SESSION[$_SERVER['REMOTE_ADDR'].'-pkcs12'],
                           $_POST['pin']);
 if ((!empty($cert))&&($cert!==false)) {
  if ($a['cert']===base64_decode($cert)) {
   return response(array('Authenticate'=>'true'));
  } else {
   return response(array('Authenticate'=>'false'));
  }
 } else {
  return response(array('Authenticate'=>'false'));
 }
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
function helper($array, $openssl)
{
 if (is_array($array)) {
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
 } else {
  $a = $openssl->privDenc($array, $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']);
 }
 return $a;
}

/*
 * handle encoding of responses
 */
function response($array){
 if (!function_exists('json_encode')) {
  return arr2json($array);
 } else {
  return json_encode($array);
 }
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

/*
 * Use these if json_encode not available
 */
function arr2json($array)
{
 if (is_array($array)) {
  foreach($array as $key => $value) $json[] = $key . ':' . php2js($value);
  if(count($json)>0) return '{'.implode(',',$json).'}';
  else return '';
 }
}

function php2js($value)
{
 if(is_array($value)) return arr2json($val);
 if(is_string($value)) return '"'.addslashes($value).'"';
 if(is_bool($value)) return 'Boolean('.(int) $value.')';
 if(is_null($value)) return '""';
 return $value;
}

function geolocation($ip)
{
 $opts = array('http'=>array('method'=>'GET',
                             'header'=>'Accept-language: en\r\n'));
 $context = stream_context_create($opts);
 $ex = unserialize(file_get_contents('http://www.geoplugin.net/php.gp?ip='.$ip,
                                     false, $context));
 return $ex;
}

function parsegeo($data, $ip, $email, $config)
{
 $settings['organizationName'] = $ip;
 $settings['organizationalUnitName'] = $ip;
 $settings['emailAddress'] = $email;
 $settings['localityName'] = (!empty($data['geoplugin_city'])) ?
                              $data['geoplugin_city'] :
                              $config['dn']['localityName'];
 $settings['stateOrProvinceName'] = (!empty($data['geoplugin_region'])) ?
                                     $data['geoplugin_region'] :
                                     $config['dn']['stateOrProvinceName'];
 $settings['countryName'] = (!empty($data['geoplugin_countryCode'])) ?
                             $data['geoplugin_countryCode'] :
                             $config['dn']['CountryName'];
 $settings['commonName'] = ((!empty($data['geoplugin_latitude']))&&
                            (!empty($data['geoplugin_longitude']))) ?
                             $data['geoplugin_latitude'].
                             '::'.$data['geoplugin_longitude'] : $ip;
 return $settings;
}

?>
