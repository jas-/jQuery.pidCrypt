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
  * @param options object Options object for specific operations
  *                       cache, debug, callback
  */
 $.fn.pidCrypt = function(method) {

  /**
   * @object defaults
   * @abstract Default set of options for plug-in
   */
  var defaults = {
   storage:  'localStorage',          // Use localStorage, sessionStorage or cookies
   form:     $(this).attr('id'),      // Place holder for form ID
   proxy:    $(this).attr('action'),  // Place holder for form action
   type:     $(this).attr('method'),  // Place holder for form method
   aes:      '',                      // Place holder for AES object
   cache:    true,                    // Use caching?
   debug:    false,                   // Use debugging?
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
   init: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
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
   sign: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
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
   verify: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     handleEmail(opts);
     setEmail(opts, 'signed');
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
   encrypt_sign: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
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
   decrypt_verify: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     handleEmail(opts);
     setEmail(opts, 'decrypt_verify');
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
   authenticate: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     handleCert(opts);
     opts.data['do'] = 'authenticate';
     opts.data['c'] = useCert(opts);
     (useCert(opts)) ? __do(opts) : false;
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
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
  var __do = function(options){
   var a = encryptObj(options, getElements(options));
   a = (sizeChk(options.data)>0) ? $.extend({}, a, options.data) : a;
   (options.debug) ? _show(options, a) : false;
   $.ajax({
    data: a,
    type: options.type,
    url: options.proxy,
    context: options.id,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(x){
     (options.debug) ?
      $('#'+options.form).append('<b>Server response:</b><br/>&nbsp;'+x) : false;
     //(a['do']==='sign') ? location.href = x : false;
     ((options.callback)&&($.isFunction(options.callback))) ?
      options.callback.call(x) : false;
    },
    complete: function(x){
     (!options.cache) ? _remove(options) : '';
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
  var _get = function(options, args, name){
   var x = _serialize(args);
   $.ajax({
    data: x,
    type: 'post',
    url: options.proxy,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(response){
     setItem(options.storage, name,
             options.aes.encryptText(response,
                                     getItem(options.storage, 'uuid'),
                                     {nBits:256,salt:getItem(options.storage,
                                                             'iv')}));
    }
   });
   return false;
  }

  /**
   * @function _serialize
   * @abstract Create serialized string of object
   */
  var _serialize = function(args){
   if (sizeChk(args)>0){
    var x='';
    $.each(args, function(a, b){
     if (typeof b==='object'){
      _serialize(b);
     } else {
      x+=a+'='+b;
     }
    });
   } else {
    return false;
   }
   return x;
  }

  /**
   * @function encryptObj
   * @abstract Calls certParser() on public key, intializes results with
   *           external pidCrypt.RSA object, performs public key encryption
   *           on object and returns results as object
   */
  var encryptObj = function(options, obj){
   var x = {}; var y = certParser(usePub(options));
   initPub(options, y);
   if (sizeChk(obj)>0){
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
   * @function setupAES
   * @abstract Returns pidCrypt.AES.CBC object for client AES storage
   */
  var setupAES = function(){
   return new pidCrypt.AES.CBC();
  }

  /**
   * @function initPub
   * @abstract Returns external pidCrypt.RSA object once certParse()
   *           generates necessary bytes from public key
   */
  var initPub = function(options, pub){
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
   * @function genUUID
   * @abstract Generate a uuid (RFC-4122) string or optional hex
   *           string of specified length
   */
  var genUUID = function(len){
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
   * @function handleKey
   * @abstract Generates uuid and iv if client storage mechanisms are null
   */
  var handleKey = function(options){
   (getItem(options.storage, 'uuid')&&(options.cache)) ?
    getItem(options.storage, 'uuid') : setItem(options.storage, 'uuid',
                                               genUUID(null));
   ((getItem(options.storage, 'iv'))&&(options.cache)) ?
    getItem(options.storage, 'iv') : setItem(options.storage, 'iv',
                                             genUUID(16));
  }

  /**
   * @function handlePub
   * @abstract Returns public key from server or client storage options
   */
  var handlePub = function(options){
   (getItem(options.storage, 'pub')&&(options.cache)) ?
    getItem(options.storage, 'pub') : _get(options, {k:true}, 'pub');
  }

  /**
   * @function handleCert
   * @abstract Returns PKCS#12 certificate from server or client storage options
   */
  var handleCert = function(options){
   (getItem(options.storage, 'certificate')&&(options.cache)) ?
    getItem(options.storage, 'certificate') : _get(options, {c:true},
                                                   'certificate');
  }

  /**
   * @function handleEmail
   * @abstract Returns PKCS#7 signed email from server or client storage
   */
  var handleEmail = function(options){
   (getItem(options.storage, 'signed')&&(options.cache)) ?
    getItem(options.storage, 'signed') : _get(options, {e:true}, 'signed');
  }

  /**
   * @function usePub
   * @abstract Returns decrypted public key from clent storage
   */
  var usePub = function(options){
   return options.aes.decryptText(getItem(options.storage, 'pub'),
                                  getItem(options.storage, 'uuid'),
                                  {nBits:256,salt:getItem(options.storage,
                                                          'iv')});
  }

  /**
   * @function useCert
   * @abstract Returns decrypted PKCS#12 certificate from server or client
   *           storage
   */
  var useCert = function(options){
   return options.aes.decryptText(getItem(options.storage, 'certificate'),
                                  getItem(options.storage, 'uuid'),
                                  {nBits:256,salt:getItem(options.storage,
                                                          'iv')});
  }

  /**
   * @function useEmail
   * @abstract Returns decrypted PKCS#7 email from server or client storage
   */
  var useEmail = function(options){
   return options.aes.decryptText(getItem(options.storage, 'signed'),
                                  getItem(options.storage, 'uuid'),
                                  {nBits:256,salt:getItem(options.storage,
                                                          'iv')});
  }

  /**
   * @function setEmail
   * @abstract Attempt to set the value of textarea for PKCS#7 verification
   *           with server
   */
  var setEmail = function(options, name){
   $('#'+options.form+' > textarea').val(useEmail(options, name));
  }

  /**
   * @function _remove
   * @abstract Removes client storage if cache set to false
   */
  var _remove = function(options){
   (getItem(options.storage, 'uuid')) ? delItem(options.storage, 'uuid') :
    false;
   (getItem(options.storage, 'pub')) ? delItem(options.storage, 'pub') : false;
   (getItem(options.storage, 'certificate')) ? delItem(options.storage,
                                                       'certificate') : false;
   (getItem(options.storage, 'iv')) ? delItem(options.storage, 'iv') : false;
   (getItem(options.storage, 'signed')) ? delItem(options.storage,
                                                  'signed') : false;
  }

  /**
   * @function getElements
   * @abstract Generates object of specified DOM form element that are non-null
   */
  var getElements = function(opts){
   var obj={};
   $.each($('#'+opts.form+' > :input'), function(k, v){
    if ((validateString(v.value))&&(validateString(v.name))){
     obj[v.name] = (parseInt(v.value.length)>80) ? strSplit(v.value) : v.value;
    }
   });
   return obj;
  }

  /**
   * @function sizeChk
   * @abstract Performs a check on object sizes
   */
  var sizeChk = function(obj){
   var n = 0;
   $.each(obj, function(k, v){
    if (obj.hasOwnProperty(k)) n++;
   });
   return n;
  }

  /**
   * @function strSplit
   * @abstract Splits string length helper to overcome limitations with RSA
   *           cipher
   */
  var strSplit = function(str){
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
  var _output = function(options){
   if (options.debug) {
    $('#'+options.form).append('<b>Processing form contents...</b><br/>');
    $('#'+options.form).append('&nbsp;<i>UUID:</i> '+
                                getItem(options.storage, 'uuid')+'<br/>');
    $('#'+options.form).append('&nbsp;<i>IV:</i> '+
                                getItem(options.storage, 'iv')+'<br/>');
    $('#'+options.form).append('&nbsp;<i>KEY:</i> '+usePub(options)+'<br/>');
   }
   return true;
  }

  /**
   * @function _show
   * @abstract Additional debugging output helper for various objects and
   *           server responses
   */
  var _show = function(options, data){
   if (sizeChk(data)>0){
    $('#'+options.form).append('<b>Encrypted data:</b><br/>');
    $.each(data, function(a,b){
     if (typeof b==='object'){
      $('#'+options.form).append('&nbsp;<i>'+a+':</i><br/>');
      $.each(b, function(x,y){
       $('#'+options.form).append('&nbsp;<i>'+x+'</i> = '+y+'<br/>');
      });
     } else {
      $('#'+options.form).append('&nbsp;<i>'+a+'</i> = '+b+'<br/>');
     }
    });
   }
  }

  /**
   * @function setItem
   * @abstract Proxy function for setting data with specified client storage
   *           option
   */
  var setItem = function(type, k, v){
   var x = false;
   type = (validateStorage(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = setLocal(k, v);
     break;
    case 'sessionStorage':
     x = setSession(k, v);
     break;
    case 'cookie':
     x = setCookie(k, v);
     break;
    default:
     x = setLocal(k, v);
     break;
   }
   return x;
  }

  /**
   * @function getItem
   * @abstract Proxy function for getting data with specified client storage
   *           option
   */
  var getItem = function(type, k){
   var x = false;
   type = (validateStorage(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = getLocal(k);
     break;
    case 'sessionStorage':
     x = getSession(k);
     break;
    case 'cookie':
     x = getCookie(k);
     break;
    default:
     x = getLocal(k);
     break;
   }
   return x;
  }

  /**
   * @function delItem
   * @abstract Proxy function for deleting data with specified client storage
   *           option
   */
  var delItem = function(type, k){
   var x = false;
   type = (validateStorage(type)) ? type : 'cookie';
   switch(type) {
    case 'localStorage':
     x = delLocal(k);
     break;
    case 'sessionStorage':
     x = delSession(k);
     break;
    case 'cookie':
     x = delCookie(k);
     break;
    default:
     x = delLocal(k);
     break;
   }
   return x;
  }

  /**
   * @function setLocal
   * @abstract Function used to set localStorage items
   */
  var setLocal = function(k, v){
   return (localStorage.setItem(k, v)) ? false : true;
  }

  /**
   * @function setSession
   * @abstract Function used to set sessionStorage items
   */
  var setSession = function(k, v){
   return (sessionStorage.setItem(k, v)) ? false : true;
  }

  /**
   * @function setCookie
   * @abstract Function used to set cookie items
   */
  var setCookie = function(k, v){
   if (typeof $.cookie === 'function') {
    return ($.cookie(k, v, {expires: 7})) ? true : false;
   } else {
    return false;
   }
  }

  /**
   * @function getLocal
   * @abstract Function used to get localStorage items
   */
  var getLocal = function(k){
   return (localStorage.getItem(k)) ? localStorage.getItem(k) : false;
  }

  /**
   * @function setSession
   * @abstract Function used to get sessionStorage items
   */
  var getSession = function(k){
   return (sessionStorage.getItem(k)) ? sessionStorage.getItem(k) : false;
  }

  /**
   * @function setCookie
   * @abstract Function used to get cookie items
   */
  var getCookie = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name)) ? $.cookie(name) : false;
   } else {
    return false;
   }
  }

  /**
   * @function delLocal
   * @abstract Function used to delete localStorage items
   */
  var delLocal = function(k){
   return (localStorage.removeItem(k)) ? localStorage.removeItem(k) : false;
  }

  /**
   * @function delSession
   * @abstract Function used to delete sessionStorage items
   */
  var delSession = function(k){
   return (sessionStorage.removeItem(k)) ? sessionStorage.removeItem(k) : false;
  }

  /**
   * @function delCookie
   * @abstract Function used to delete cookie items
   */
  var delCookie = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name, '', {expires: -7})) ? true : false;
   } else {
    return false;
   }
  }

  /**
   * @function validateString
   * @abstract Function used combine string checking functions
   */
  var validateString = function(x){
   return ((x===false)||(x.length===0)||(!x)||(x===null)||
           (x==='')||(typeof x==='undefined')) ? false : true;
  }

  /**
   * @function validateStorage
   * @abstract Function used to validate client storage option
   */
  var validateStorage = function(type){
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
