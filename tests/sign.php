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
     (empty($_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']))){
  create($settings, $openssl);
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

 /*
  * If you wish to do anything further such as add a response that the data was recieved by the server etc
  * add it here (delete this because it returns the decrypted examples)
  */
 if ($_POST['do']==='sign') {
  $response = 'Data recieved and processed...<br/>';
  $response .= response(sign(array('name'=>$_POST['name'],'email'=>$_POST['email'],
                                   'message'=>$_POST['message']),
                             $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                             $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'],
                             $_SERVER['REMOTE_ADDR'], $openssl));
 } else {
  $response = 'No command recieved from XMLHttpRequest';
 }
 echo $response;
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
 * Create private/public/certificate for referring machine (stored in session)
 */
function create($settings, $openssl)
{
 /* Generate the private key */
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'] = $openssl->genPriv($_SERVER['REMOTE_ADDR']);

 /* Get the public key */
 $k = $openssl->genPub();
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'] = $k['key'];

 /* Create certificate */
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'] = $openssl->createx509($settings,
                                                                          $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                                                                          $_SERVER['REMOTE_ADDR']);
}

/*
 * Sign and send email
 */
function sign($data, $key, $pass, $certificate, $openssl)
{
 $msg = setHeaders('../tmp/msg.txt', $openssl);
 $signed = '../tmp/signed.txt';
 $res = $openssl->signx509($msg, $signed, $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'],
                           array($_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                                 $_SERVER['REMOTE_ADDR']),
                           array("To" => $openssl->privDenc($_POST['email'],
                                                            $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                                                            $_SERVER['REMOTE_ADDR']),
                                 "From" => "jQuery.pidCrypt <jason.gerfen@gmail.com>",
                                 "Subject" => "A test"));
 return force($signed);
}

/* push to client */
function force($file)
{
 header("Cache-Control: public");
 header("Content-Description: File Transfer");
 header("Content-Disposition: attachment; filename=$file");
 header("Content-Type: application/pkcs7-mime");
 header("Content-Transfer-Encoding: binary");
 readfile($file);
}

/* Create mail message */
function setHeaders($file, $openssl) {
 $boundary = md5(uniqid(time()));
 $boddy = "MIME-Version: 1.0\n";
 $boddy .= "Content-Type: multipart/mixed; boundary=\"" . $boundary. "\"\n";
 $boddy .= "Content-Transfer-Encoding: quoted-printable\n\n";
 $boddy .= "This is a multi-part message in MIME format.\n\n";
 $boddy .= "--$boundary\n";
 $boddy .= "Content-Type: text/plain; charset=\"iso-8859-1\"\n";
 $boddy .= "Content-Transfer-Encoding: quoted-printable\n\n";
 $boddy .= combine(helper($_POST['message'], $openssl))."\n\n";
 $boddy .= "--$boundary--\n";
 $fp = fopen($file, "w");
 fwrite($fp, $boddy);
 fclose($fp);
 return $file;
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



?>
