<?php
/**
 * Handle XMLHttpRequests
 * Requires AJAX requests provide Content-MD5, CSRF token (HTTP_X_ALT_REFER),
 * and HTTP_X_REQUESTED_WITH as XMLHttpRequest.
 *
 * This class accompanies the jQuery.AJAX project @https://github.com/jas-jQuery.AJAX
 *
 * LICENSE: This source file is subject to version 3.01 of the GPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/licenses/gpl.html.  If you did not receive a copy of
 * the GPL License and are unable to obtain it through the web, please
 *
 * @author     jason.gerfen@gmail.com
 * @copyright  2008-2012 Jason Gerfen
 * @license    http://www.gnu.org/licenses/gpl.html  GPL License 3
 * @version    0.3
 */

/**
 *! @class ajax
 *  @abstract Handles XMLHttpRequest proxy loading
 */
class ajax
{

 /**
  *  @var private object
  */
 private $libs;

 /**
  *! @function __construct
  *  @abstract Load and return a boolean for the current AJAX request
  */
 public function __construct()
 {
  $this->libs = new libraries;

  $post = (!empty($_POST)) ?
    $this->libs->_serialize($_POST) :
     md5($_SESSION[$this->libs->libs->_getRealIPv4()]['token']);

  if ((!$this->__vRequest(getenv('HTTP_X_REQUESTED_WITH')))||
      (!$this->__vCSRF(getenv('HTTP_X_ALT_REFERER'), $_SESSION[$this->libs->_getRealIPv4()]['token']))||
      (!$this->__vCheckSum(getenv('HTTP_CONTENT_MD5'), $post))){
   return true;
  } else {
   return false;
  }
 }

 /**
  *! @function __vRequest
  *  @abstract Verify the request was valid XMLHttpRequest
  */
 private function __vRequest($request)
 {
  return (strcmp($request, 'XMLHttpRequest')!==0) ? false : true;
 }

 /**
  *! @function __vCSRF
  *  @abstract Verify the CSRF token
  */
 private function __vCSRF($header, $token)
 {
  return (strcmp($header, $token)===0) ? true : false;
 }

 /**
  *! @function __vCheckSum
  *  @abstract Verify the post data contained a valid checksum in the header
  */
 private function __vCheckSum($header, $array)
 {
  return (strcmp(base64_decode($header),
                 md5($this->libs->_serialize($array)))!==0) ? false : true;
 }
}
?>