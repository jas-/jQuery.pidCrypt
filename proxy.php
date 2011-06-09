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
$settings['dn']['organizationalUnitName'] = 'Plug-in for easy implementation of RSA public key encryption';
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
     //echo $openssl->aesEnc($_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'], $_POST['u'], $_POST['i'], false, 'aes-256-cbc');
    } else {
     echo $_SESSION[$_SERVER['REMOTE_ADDR'].'-public-key'];
    }
    exit;
   }

   if (!empty($_POST['do'])){
    switch($_POST['do']){
     case 'sign':
      echo response(sign(array('name'=>$_POST['name'],'email'=>$_POST['email'],'message'=>$_POST['message']),
                         $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                         $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'],
                         $_SERVER['REMOTE_ADDR'], $openssl));
      exit;
     case 'sign_encrypt':
      exit;
     default:
      exit;
    }
   }

   /*
    * If you wish to do anything further such as add a response that the data was recieved by the server etc
    * add it here (delete this because it returns the decrypted examples)
    */
   $response = 'Data recieved and processed...<br/>';
   $response .= arr2json(helper(array('name'=>$_POST['name'],
                                      'email'=>$_POST['email'],
                                      'message'=>$_POST['message']),
                                $openssl));
   echo $response;
  }
 }
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
 $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate'] = $openssl->handleCertificate($settings,
                                                                                 $_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'],
                                                                                 $_SERVER['REMOTE_ADDR']);
}

/*
 * Loop over post data and attempt to sign it
 */
function sign($data, $key, $pass, $certificate, $openssl)
{
 $fp = fopen('tmp/cert', 'w');
 fwrite($fp, $_SESSION[$_SERVER['REMOTE_ADDR'].'-certificate']);
 fclose($fp);
 $boundary = md5(uniqid(time()));
 $boddy = "MIME-Version: 1.0\n";
 $boddy .= "Content-Type: multipart/mixed; boundary=\"" . $boundary. "\"\n";
 $boddy .= "Content-Transfer-Encoding: quoted-printable\n\n";
 $boddy .= "This is a multi-part message in MIME format.\n\n";
 $boddy .= "--$boundary\n";
 $boddy .= "Content-Type: text/plain; charset=\"iso-8859-1\"\n";
 $boddy .= "Content-Transfer-Encoding: quoted-printable\n\n";
 $boddy .= $_POST['message']."\n\n";
 $boddy .= "--$boundary--\n";
 $msg = 'msg.txt';
 $signed = 'signed.txt';
 $fp = fopen('tmp/'.$msg, "w");
 fwrite($fp, $boddy);
 fclose($fp);
 if (openssl_pkcs7_sign($msg, 'tmp/'.$signed, 'tmp/cert',
    array($_SESSION[$_SERVER['REMOTE_ADDR'].'-private-key'], $_SERVER['REMOTE_ADDR']),
    array("To" => $_POST['email'],
         "From: jQuery.pidCrypt <jason.gerfen@gmail.com>",
         "Subject" => "A test"), PKCS7_DETACHED)) {
    exec(ini_get('sendmail_path') . ' < ' . 'tmp/'.$signed);
  }
/*
 $data = helper($data, $openssl); $a=array();
 if (count($data)>0){
  foreach($data as $k => $v){
   $a[$k] = $openssl->ssign($v, $key, $pass);
  }
 }
 return $a;
*/
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

/*
 * Use these if json_encode not available
 */
function arr2json( $array )
{
 foreach( $array as $key => $value ) $json[] = $key . ':' . php2js( $value );
 if( count( $json ) > 0 ) return '{' . implode( ',', $json ) . '}';
 else return '';
}

function php2js( $value )
{
 if( is_array( $value ) ) return arr2json( $val );
 if( is_string( $value ) ) return '"' . addslashes( $value ) . '"';
 if( is_bool( $value ) ) return 'Boolean(' . (int) $value . ')';
 if( is_null( $value ) ) return '""';
 return $value;
}

?>
