<?php

class libraries
{
 /**
 * @function _serialize
 * @abstract Perform serialization of sent POST data. This is required for the
 *           jQuery.AJAX plug-in checksum verification as the current PHP
 *           serialize() function will not create an accurate hash
 */
 function _serialize($array)
 {
  $x = '';
  if ((is_array($array))&&(count($array)>0)){
   foreach($array as $key => $value){
    $x .= $key.'='.$value.'&';
   }
   $x = substr($x, 0, -1);
  }
  return (strlen($x)>0) ? $x : false;
 }

 /**
  * @function JSONencode
  * @abstract Primary interface for creating JSON objects
  */
 function JSONencode($array){
  if (!function_exists('json_encode')) {
   return arr2json($array);
  } else {
   return json_encode($array);
  }
 }

 /**
  * @function arr2json
  * @abstract Creates JSON object when json_encode is missing
  */
 function arr2json($array)
 {
  if (is_array($array)) {
   foreach($array as $key => $value) $json[]=$key.':'.php2js($value);
   if(count($json)>0) return '{'.implode(',',$json).'}';
   else return '';
  }
 }

 /**
  * @function php2js
  * @abstract Helper for arr2json. Perofrms typecasting
  */
 function php2js($value)
 {
  if(is_array($value)) return arr2json($val);
  if(is_string($value)) return '"'.$value.'"';
  if(is_bool($value)) return 'Boolean('.(int) $value.')';
  if(is_null($value)) return '""';
  return $value;
 }

 /**
  * @function _uuid()
  * @abstract Generate a unique GUID (per RFC4122)
  */
 function _uuid()
 {
  return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x', mt_rand(0, 0xffff),
                 mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0x0fff) | 0x4000,
                 mt_rand(0, 0x3fff) | 0x8000, mt_rand(0, 0xffff),
                 mt_rand(0, 0xffff), mt_rand(0, 0xffff));
 }

 /**
  * @function _getRealIPv4
  * @abstract Try all methods of obtaining 'real' IP address
  */
 function _getRealIPv4()
 {
  return (getenv('HTTP_CLIENT_IP') && $this->_ip(getenv('HTTP_CLIENT_IP'))) ?
           getenv('HTTP_CLIENT_IP') :
            (getenv('HTTP_X_FORWARDED_FOR') && $this->_forwarded(getenv('HTTP_X_FORWARDED_FOR'))) ?
              $this->_forwarded(getenv('HTTP_X_FORWARDED_FOR')) :
               (getenv('HTTP_X_FORWARDED') && $this->_ip(getenv('HTTP_X_FORWARDED'))) ?
                 getenv('HTTP_X_FORWARDED') :
                  (getenv('HTTP_X_FORWARDED_HOST') && $this->_ip(getenv('HTTP_FORWARDED_HOST'))) ?
                    getenv('HTTP_X_FORWARDED_HOST') :
                     (getenv('HTTP_X_FORWARDED_SERVER') && $this->_ip(getenv('HTTP_X_FORWARDED_SERVER'))) ?
                       getenv('HTTP_X_FORWARDED_SERVER') :
                        (getenv('HTTP_X_CLUSTER_CLIENT_IP') && $this->_ip(getenv('HTTP_X_CLIUSTER_CLIENT_IP'))) ?
                          getenv('HTTP_X_CLUSTER_CLIENT_IP') :
                           getenv('REMOTE_ADDR');
 }

 /**
  * @function _ip
  * @abstract Attempts to determine if IP is non-routeable
  */
 function _ip($ip)
 {
  if (!empty($ip) && ip2long($ip)!=-1 && ip2long($ip)!=false){
   $nr = array(array('0.0.0.0','2.255.255.255'),
               array('10.0.0.0','10.255.255.255'),
               array('127.0.0.0','127.255.255.255'),
               array('169.254.0.0','169.254.255.255'),
               array('172.16.0.0','172.31.255.255'),
               array('192.0.2.0','192.0.2.255'),
               array('192.168.0.0','192.168.255.255'),
               array('255.255.255.0','255.255.255.255'));
   foreach($nr as $r){
    $min = ip2long($r[0]);
    $max = ip2long($r[1]);
    if ((ip2long($ip) >= $min) && (ip2long($ip) <= $max)) return false;
   }
   return true;
  } else {
   return false;
  }
 }

 /**
  * @function _forwarded
  * @abstract A helper for HTTP_X_FORWARDED_FOR, loops over comma
  *           separated list of proxies associated with request
  */
 function _forwarded($l)
 {
  if (!empty($l)){
   foreach (explode(',', $l) as $i){
    if ($this->_ip(trim($i))) {
     return (!$this->_ip(trim($i))) ? false : $i;
    }
   }
  } else {
   return false;
  }
 }
}
?>
