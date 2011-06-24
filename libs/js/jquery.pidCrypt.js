/**
 *
 * jQuery plugin to impliment RSA public key encryption for
 * form submissions.
 *
 * Utilizes the pidCrypt libraries for client public key
 * encryption while the associated PHP class uses
 * OpenSSL to generate the necessary private/public key pairs used
 * by this plug-in
 *
 * Fork me @ https://www.github.com/jas-/jQuery.pidCrypt
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: GPL (see LICENSE)
 *
 */

(function($){

 /**
  * @function jQuery.pidCrypt
  * @abstract Plug-in to implement pidCrypt RSA and AES
  *           encryption for public key encryption of
  *           web form elements with support for
  *           client storage options
  * @param method string Method to employ for form ID DOM object
  *                      default, sign, verify, encrypt_sign,
  *                      decrypt_verify, authenticate
  * @param options object options object for specific operations
  *                       cache, debug, callback
  */
 $.fn.pidCrypt = function(method) {

  /**
   * @object defaults
   * @abstract Default set of options for plug-in
   */
  var defaults = {
   appID:    'jQuery.pidCrypt',       // Storage key, unique string
   storage:  'localStorage',          // Use localStorage, sessionStorage or cookies
   form:     $(this).attr('id'),      // Place holder for form ID
   proxy:    $(this).attr('action'),  // Place holder for form action
   type:     $(this).attr('method'),  // Place holder for form method
   aes:      '',                      // Place holder for AES object
   cache:    true,                    // Use caching?
   debug:    false,                   // Use debugging?
   config:   {},                      // Object used for configuration settings
   data:     {},                      // Object used for signing methods
   callback: function() {}            // Optional callback once form processed
  };

  /**
   * @object methods
   * @abstract Plug-in methods
   */
  var methods = {

   /**
    * @function init
    * @abstract Default plug-in method. Requests public key, optionally
    *           uses client storage for key, gathers non-null form elements,
    *           encrypts and sends to server for private key decryption
    */
   init: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   },

   /**
    * @function sign
    * @abstract PKCS#7 email signing method. Requests public key, optionally
    *           uses client storage for key, gathers non-null form elements,
    *           encrypts and sends to server for PKCS#7 signing
    */
   sign: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'sign';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   },

   /**
    * @function verify
    * @abstract PKCS#7 email verification method. Requests PKCS#7 signed email,
    *           optionally uses client storage for email, gathers non-null
    *           form elements containing contents of signed email, uses
    *           public key to encrypt contents which the server then decrypts
    *           and performs validation of PKCS#7 signature
    */
   verify: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     hE(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'verify';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   },

   /**
    * @function encrypt_sign
    * @abstract PKCS#7 email encryption & signing method. Requests public key,
    *           optionally uses client storage for key, gathers non-null form
    *           elements, encrypts and sends to server for PKCS#7 encrypting
    *           & signing
    */
   encrypt_sign: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'encrypt_sign';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   },

   /**
    * @function decrypt_verify
    * @abstract PKCS#7 email decryption & verification method. Requests PKCS#7
    *           signed email, optionally uses client storage for email,
    *           gathers non-null form elements containing contents of signed
    *           email, uses public key to encrypt contents which the server
    *           then decrypts and performs validation of PKCS#7 signature
    */
   decrypt_verify: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     hE(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'decrypt_verify';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   },

   /**
    * @function authenticate
    * @abstract PKCS#12 certificate authentication method. Requests PKCS#12
    *           certificate based on private key and PKCS#7 certificate
    *           residing on server. Optionally stores PKCS#12 certificate
    *           in client storage options and attempts to use as authentication
    */
   authenticate: function(o){
    var opts = $.extend({}, defaults, o);
    if (__dependencies(opts)){
     opts.aes = sAES();
     hK(opts);
     hP(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      hC(opts);
      hP(opts, true);
      opts.data['do'] = 'authenticate';
      opts.data['c'] = (gI(opts.storage, 'certificate')) ?
       useCert(opts) : false;
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
     });
    }
    return true;
   }
  };

  /**
   * @function __do
   * @abstract Gathers non-null form values, adds method defined object values,
   *           displays optional debugging data, performs XMLHttpRequest
   *           while setting custom header information and processing response
   *           with user defined callback function
   */
  var __do = function(o){
   var a = eO(o, gE(o));
   a = (szCk(o.data)>0) ? $.extend({}, a, o.data) : a;
   (o.debug) ? _show(o, a) : false;
   $.ajax({
    data: a,
    type: o.type,
    url: o.proxy,
    context: o.id,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(x){
     (o.debug) ?
      $('#'+o.form).append('<b>Server response:</b><br/>&nbsp;'+x) : false;
     ((o.callback)&&($.isFunction(o.callback))) ? o.callback.call(x) : false;
    },
    complete: function(x){
     (!o.cache) ? _remove(o) : '';
    }
   });
   return false;
  }

  /**
   * @function _get
   * @abstract Serializes request options, performs XMLHttpRequest to
   *           retrieve specified data from server while storing specified
   *           item within specified storage mechanism
   */
  var _get = function(o, args, name){
   var x = (typeof args==='object') ? _serialize(args) : args;
   $.ajax({
    data: x,
    type: 'post',
    url: o.proxy,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(response){
     sI(o.storage, name,
             o.aes.encryptText(response,
                               gI(o.storage, 'uuid'),
                                       {nBits:256,salt:gI(o.storage,
                                                               'iv')}));
    }
   });
   return false;
  }

  /**
   * @function __id
   * @abstract Need an id to associate the public key and other
   *           configuration options with a hostname or url
   */
  var __id = function(){
   return (vStr(location.host)) ?
    location.host :
     (vStr(location.hostname)) ?
      location.hostname :
       'localhost';
  }

  /**
   * @function existing
   * @abstract Function used to return configured options
   *           as JSON object
   */
  var existing = function(o) {
   return (gI(o.storage, o.appID)) ?
    JSON.parse(gI(o.storage, o.appID)) : false;
  }

  /**
   * @function _serialize
   * @abstract Create serialized string of object
   */
  var _serialize = function(args){
   if (szCk(args)>0){
    var x='';
    $.each(args, function(a, b){
     if (typeof b==='object'){
      _serialize(b);
     } else {
      x+=a+'='+b+'&';
     }
    });
   } else {
    return false;
   }
   return x;
  }

  /**
   * @function eO
   * @abstract Calls certParser() on public key, intializes results with
   *           external pidCrypt.RSA object, performs public key encryption
   *           on object and returns results as object
   */
  var eO = function(o, obj){
   var x = {}; var y = certParser(usePub(o));
   iP(o, y);
   if (szCk(obj)>0){
    $.each(obj, function(a, b){
     if (typeof b==='object'){
      x[a]={};
      $.each(b, function(k, v){
       x[a][k] = pidCrypt.RSA.prototype.encrypt(v);
      });
     } else {
      x[a] = pidCrypt.RSA.prototype.encrypt(b);
     }
    });
   } else {
    x = 0;
   }
   return x;
  }

  /**
   * @function sAES
   * @abstract Returns pidCrypt.AES.CBC object for client AES storage
   */
  var sAES = function(){
   return new pidCrypt.AES.CBC();
  }

  /**
   * @function iP
   * @abstract Returns external pidCrypt.RSA object once certParse()
   *           generates necessary bytes from public key
   */
  var iP = function(o, pub){
   if (pub.b64){
    var x = pidCryptUtil.decodeBase64(pub.b64);
    var rsa = new pidCrypt();
    var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(x));
    var tree = asn.toHexTree();
    pidCrypt.RSA.prototype.setPublicKeyFromASN(tree);
   }
   return rsa;
  }

  /**
   * @function gUUID
   * @abstract Generate a uuid (RFC-4122) string or optional hex
   *           string of specified length
   */
  var gUUID = function(len){
   var chars = '0123456789abcdef'.split('');
   var uuid = [], rnd = Math.random, r;
   uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
   uuid[14] = '4';
   for (var i = 0; i < 36; i++){
    if (!uuid[i]){
     r = 0 | rnd()*16;
     uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r & 0xf];
    }
   }
   return (len!==null) ? uuid.join('').replace(/-/g, '').split('',len).join('') :
                         uuid.join('');
  }

  /**
   * @function hK
   * @abstract Generates uuid and iv if client storage mechanisms are null
   */
  var hK = function(o){
   (gI(o.storage, 'uuid')&&(o.cache)) ?
    gI(o.storage, 'uuid') : sI(o.storage, 'uuid', gUUID(null));
   ((gI(o.storage, 'iv'))&&(o.cache)) ?
    gI(o.storage, 'iv') : sI(o.storage, 'iv', gUUID(16));
  }

  /**
   * @function hP
   * @abstract Returns public key from server or client storage o
   */
  var hP = function(o, f){
   if (f){
    var a = eO(o, gE(o));
    o.data['k']=true;
    a = (szCk(o.data)>0) ? $.extend({}, a, o.data) : a;
   } else {
    var a = {k:true};
   }
   (gI(o.storage, 'pub')&&(o.cache)) ?
    gI(o.storage, 'pub') : _get(o, _serialize(a), 'pub');
  }

  /**
   * @function hC
   * @abstract Returns PKCS#12 certificate from server or client storage options
   */
  var hC = function(o){
   var a = eO(o, gE(o));
   o.data['c']=true;
   a = (szCk(o.data)>0) ? $.extend({}, a, o.data) : a;
   (gI(o.storage, 'certificate')&&(o.cache)) ?
    gI(o.storage, 'certificate') : _get(o, _serialize(a), 'certificate');
  }

  /**
   * @function hE
   * @abstract Returns PKCS#7 signed email from server or client storage
   */
  var hE = function(o){
   (gI(o.storage, 'signed')&&(o.cache)) ?
    gI(o.storage, 'signed') : _get(o, {e:true}, 'signed');
  }

  /**
   * @function usePub
   * @abstract Returns decrypted public key from clent storage
   */
  var usePub = function(o){
   return o.aes.decryptText(gI(o.storage, 'pub'),
                                    gI(o.storage, 'uuid'),
                                            {nBits:256,salt:gI(o.storage,
                                                                    'iv')});
  }

  /**
   * @function useCert
   * @abstract Returns decrypted PKCS#12 certificate from server or client
   *           storage
   */
  var useCert = function(o){
   return o.aes.decryptText(gI(o.storage, 'certificate'),
                                    gI(o.storage, 'uuid'),
                                            {nBits:256,salt:gI(o.storage,
                                                                    'iv')});
  }

  /**
   * @function useEmail
   * @abstract Returns decrypted PKCS#7 email from server or client storage
   */
  var useEmail = function(o){
   return o.aes.decryptText(gI(o.storage, 'signed'),
                                    gI(o.storage, 'uuid'),
                                            {nBits:256,salt:gI(o.storage,
                                                                    'iv')});
  }

  /**
   * @function _remove
   * @abstract Removes client storage if cache set to false
   */
  var _remove = function(o){
   (gI(o.storage, 'uuid')) ? dI(o.storage, 'uuid') : false;
   (gI(o.storage, 'pub')) ? dI(o.storage, 'pub') : false;
   (gI(o.storage, 'certificate')) ? dI(o.storage, 'certificate') : false;
   (gI(o.storage, 'iv')) ? dI(o.storage, 'iv') : false;
   (gI(o.storage, 'signed')) ? dI(o.storage, 'signed') : false;
  }

  /**
   * @function gE
   * @abstract Generates object of specified DOM form element that are non-null
   */
  var gE = function(opts){
   var obj={};
   $.each($('#'+opts.form+' > :input'), function(k, v){
    if ((vStr(v.value))&&(vStr(v.name))){
     obj[v.name] = (parseInt(v.value.length)>80) ? sSplt(v.value) : v.value;
    }
   });
   return obj;
  }

  /**
   * @function szCk
   * @abstract Performs a check on object sizes
   */
  var szCk = function(obj){
   var n = 0;
   $.each(obj, function(k, v){
    if (obj.hasOwnProperty(k)) n++;
   });
   return n;
  }

  /**
   * @function sSplt
   * @abstract Splits string length helper to overcome limitations with RSA
   *           cipher
   */
  var sSplt = function(str){
   var t = str.length/80;
   var y = {}; var x=0; var z=80;
   for (var i=0; i<t; i++) {
    if (i>0) { x=x+80; z=z+80; }
    if (str.slice(x, z).length>0) {
     y[i] = str.slice(x, z);
    }
   }
   return y;
  }

  /**
   * @function _output
   * @abstract Debugging output helper
   */
  var _output = function(o){
   if (o.debug) {
    $('#'+o.form).append('<b>Processing form contents...</b><br/>');
    $('#'+o.form).append('&nbsp;<i>UUID:</i> '+
                                gI(o.storage, 'uuid')+'<br/>');
    $('#'+o.form).append('&nbsp;<i>IV:</i> '+
                                gI(o.storage, 'iv')+'<br/>');
    $('#'+o.form).append('&nbsp;<i>KEY:</i> '+usePub(o)+'<br/>');
   }
   return true;
  }

  /**
   * @function _show
   * @abstract Additional debugging output helper for various objects and
   *           server responses
   */
  var _show = function(o, data){
   if (szCk(data)>0){
    $('#'+o.form).append('<b>Encrypted data:</b><br/>');
    $.each(data, function(a,b){
     if (typeof b==='object'){
      $('#'+o.form).append('&nbsp;<i>'+a+':</i><br/>');
      $.each(b, function(x,y){
       $('#'+o.form).append('&nbsp;<i>'+x+'</i> = '+y+'<br/>');
      });
     } else {
      $('#'+o.form).append('&nbsp;<i>'+a+'</i> = '+b+'<br/>');
     }
    });
   }
  }

  /**
   * @function sI
   * @abstract Proxy function for setting data with specified client storage
   *           option
   */
  var sI = function(type, k, v){
   var x = false;
   type = (vStore(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = sL(k, v);
     break;
    case 'sessionStorage':
     x = sS(k, v);
     break;
    case 'cookie':
     x = sC(k, v);
     break;
    default:
     x = sL(k, v);
     break;
   }
   return x;
  }

  /**
   * @function gI
   * @abstract Proxy function for getting data with specified client storage
   *           option
   */
  var gI = function(type, k){
   var x = false;
   type = (vStore(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = gL(k);
     break;
    case 'sessionStorage':
     x = gS(k);
     break;
    case 'cookie':
     x = gC(k);
     break;
    default:
     x = gL(k);
     break;
   }
   return x;
  }

  /**
   * @function dI
   * @abstract Proxy function for deleting data with specified client storage
   *           option
   */
  var dI = function(type, k){
   var x = false;
   type = (vStore(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = dL(k);
     break;
    case 'sessionStorage':
     x = dS(k);
     break;
    case 'cookie':
     x = dC(k);
     break;
    default:
     x = dL(k);
     break;
   }
   return x;
  }

  /**
   * @function sL
   * @abstract Function used to set localStorage items
   */
  var sL = function(k, v){
   return (localStorage.setItem(k, v)) ? false : true;
  }

  /**
   * @function sS
   * @abstract Function used to set sessionStorage items
   */
  var sS = function(k, v){
   return (sessionStorage.setItem(k, v)) ? false : true;
  }

  /**
   * @function sC
   * @abstract Function used to set cookie items
   */
  var sC = function(k, v){
   if (typeof $.cookie === 'function') {
    return ($.cookie(k, v, {expires: 7})) ? true : false;
   } else {
    return false;
   }
  }

  /**
   * @function gL
   * @abstract Function used to get localStorage items
   */
  var gL = function(k){
   return (localStorage.getItem(k)) ? localStorage.getItem(k) : false;
  }

  /**
   * @function sS
   * @abstract Function used to get sessionStorage items
   */
  var gS = function(k){
   return (sessionStorage.getItem(k)) ? sessionStorage.getItem(k) : false;
  }

  /**
   * @function sC
   * @abstract Function used to get cookie items
   */
  var gC = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name)) ? $.cookie(name) : false;
   } else {
    return false;
   }
  }

  /**
   * @function dL
   * @abstract Function used to delete localStorage items
   */
  var dL = function(k){
   return (localStorage.removeItem(k)) ? localStorage.removeItem(k) : false;
  }

  /**
   * @function dS
   * @abstract Function used to delete sessionStorage items
   */
  var dS = function(k){
   return (sessionStorage.removeItem(k)) ? sessionStorage.removeItem(k) : false;
  }

  /**
   * @function dC
   * @abstract Function used to delete cookie items
   */
  var dC = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name, '', {expires: -7})) ? true : false;
   } else {
    return false;
   }
  }

  /**
   * @function vStr
   * @abstract Function used combine string checking functions
   */
  var vStr = function(x){
   return ((x===false)||(x.length===0)||(!x)||(x===null)||
           (x==='')||(typeof x==='undefined')) ? false : true;
  }

  /**
   * @function vStore
   * @abstract Function used to validate client storage option
   */
  var vStore = function(type){
   try {
    return ((type in window)&&(window[type])) ? true : false;
   } catch (e) {
    return false;
   }
  }

  /*
   * parse public/private key function
   * (Copyright https://www.pidder.com/pidcrypt/?page=demo_rsa-encryption)
   */
  var certParser = function(cert){
   var lines = cert.split('\n');
   var read = false;
   var b64 = false;
   var end = false;
   var flag = '';
   var retObj = {};
   retObj.info = '';
   retObj.salt = '';
   retObj.iv;
   retObj.b64 = '';
   retObj.aes = false;
   retObj.mode = '';
   retObj.bits = 0;
   for(var i=0; i< lines.length; i++){
    flag = lines[i].substr(0,9);
    if(i==1 && flag != 'Proc-Type' && flag.indexOf('M') == 0)//unencrypted cert?
    b64 = true;
    switch(flag){
     case '-----BEGI':
      read = true;
      break;
     case 'Proc-Type':
      if(read)
       retObj.info = lines[i];
       break;
     case 'DEK-Info:':
      if(read){
       var tmp = lines[i].split(',');
       var dek = tmp[0].split(': ');
       var aes = dek[1].split('-');
       retObj.aes = (aes[0] == 'AES')?true:false;
       retObj.mode = aes[2];
       retObj.bits = parseInt(aes[1]);
       retObj.salt = tmp[1].substr(0,16);
       retObj.iv = tmp[1];
      }
      break;
     case '':
      if(read)
       b64 = true;
       break;
     case '-----END ':
      if(read){
       b64 = false;
       read = false;
      }
      break;
     default:
      if(read && b64)
       retObj.b64 += pidCryptUtil.stripLineFeeds(lines[i]);
    }
   }
   return retObj;
  }

  /**
   * @function __dependencies
   * @abstract Function used to log errors regarding necessary libraries
   */
  var __dependencies = function(opts){
   var ret = true;
   if (!$.isFunction(pidCrypt.RSA.prototype.encrypt)){
    console.log('pidCrypt RSA libraries are missing.'+
                'Please include the pidCrypt RSA libs...');
    console.log('Download them from https://www.pidder.com/pidcrypt/');
    console.log('See README document for necessary includes');
    ret = false;
   }
   if (!$.isFunction(pidCrypt.AES.CBC)){
    console.log('pidCrypt AES-CBC libraries are missing.'+
                'Please include the pidCrypt AES-CBC libs...');
    console.log('Download them from https://www.pidder.com/pidcrypt/');
    console.log('See README document for necessary includes');
    ret = false;
   }
   if (opts.storage==='cookie'){
    if (!$.isFunction($.cookie)){
     console.log('Cookie use specified but required libraries not available.'+
                 'Please include the jQuery cookie plugin...');
     console.log('Download it from https://github.com/carhartl/jquery-cookie');
     ret = false;
    }
   }
   return ret;
  }

  /**
   * @function __recurse
   * @abstract Function used help debug objects recursively
   */
  var __recurse = function(obj){
   $.each(obj, function(x,y){
    if (typeof y==='object'){
     __recurse(y);
    } else {
     console.log(x+' => '+y);
    }
   });
  }

  /* robot, do something */
  if (methods[method]){
   return methods[method].apply(this, Array.prototype.slice.call(arguments, 1));
  } else if ((typeof method==='object')||(!method)){
   return methods.init.apply(this, arguments);
  } else {
   console.log('Method '+method+' does not exist');
  }
 };
})(jQuery);
