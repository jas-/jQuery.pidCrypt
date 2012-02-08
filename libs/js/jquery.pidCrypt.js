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
  var defaults = defaults || {
   appID:        'jQuery.pidCrypt',
   storage:      'local',
   formID:       $(this),
   type:         'json',
   aes:          '',
   keys:         {},
   use:          '',
   callback:     function(){},
   preCallback:  function(){},
   errCallback:  function(){}
  };

  /**
   * @object methods
   * @abstract Plug-in methods
   */
  var methods = methods || {

   /**
    * @function init
    * @abstract Default plug-in method. Requests public key, optionally
    *           uses client storage for key, gathers non-null form elements,
    *           encrypts and sends to server for private key decryption
    */
   init: function(o){
    var opts = _main.__setup(o, defaults);
    $('#'+opts.formID.attr('id')).on('submit', function(e){
     e.preventDefault();
     _main.__do(opts, _main.__gF(opts));
    });
    return true;
   }
  };

  /**
   * @object main
   * @abstract Handles primary functions
   */
  var _main = _main || {

   /**
    * @object _do
    * @abstract Performs all AJAX requests. Sets additional CSRF and checksum
    *           header fields which can be verified on server
    */
   __do: function(o, a){
    var _data = (typeof a=='object') ? _strings.__serialize(a) : a;
    $.ajax({
     form: o.formID.attr('id'),
     url: o.formID.attr('action'),
     type: o.formID.attr('method'),
     data: _data,
     crossDomain: (o.type==='jsonp') ? true : false,
     beforeSend: function(xhr){
      xhr.setRequestHeader('X-Alt-Referer', o.appID);
      if (_validation.__vStr(_data)){
       xhr.setRequestHeader('Content-MD5', pidCryptUtil.encodeBase64(pidCrypt.MD5(_data)));
      } else {
       xhr.setRequestHeader('Content-MD5', pidCryptUtil.encodeBase64(pidCrypt.MD5(o.appID)));
      }
      ((o.preCallback)&&($.isFunction(o.preCallback))) ?
        o.preCallback(xhr) : false;
     },
     success: function(x, status, xhr){
      ((o.callback)&&($.isFunction(o.callback))) ?
        o.callback.call(x) : console.log(x);
     },
     error: function(xhr, status, error){
      ((o.errCallback)&&($.isFunction(o.errCallback))) ?
        o.errCallback.call(xhr, status, error) : false;
     }
    });
   },

   /**
    * @function __setup
    * @abstract Performs simple global setup functions
    */
   __setup: function(o, d){
    var opts = $.extend({}, d, o);
    opts.aes = _encrypt.__sAES();
    opts.keys = _keys.__existing(opts);
    if (_validation.__szCk(opts.keys)<=0){
     _keys.__hK(opts);
    }
    opts.use = _keys.__sK(opts);
    return opts;
   },

   /**
    * @function __gF
    * @abstract Performs object creation of non-null form elements
    */
   __gF: function(o){
    var obj={};
    $.each($('#'+o.formID.attr('id')+' :input, input:radio:selected, input:checkbox:checked, textarea'), function(k, v){
     if ((_validation.__vStr(v.value))&&(_validation.__vStr(v.name))){
      obj[v.name] = (parseInt(v.value.length)>80) ? _strings.__sSplt(v.value) : v.value;
     }
    });
    return _encrypt.__eO(o, obj);
   }
  }

  /**
   * @object keys
   * @abstract Object providing interface for key retrieval and storage
   */
  var _keys = _keys || {

   /**
    * @function __hK
    * @abstract Handles retrieval, encryption and storage of key
    */
   __hK: function(o){
    var y = function(){
     var z = (this) ? JSON.parse(this) : false;
     var email = ((z)&&(z.email)) ? z.email : o.appID;
     var key = ((z)&&(z.key)) ? z.key : false;
     if (!key) return false;
     var p = _keys.__gUUID(null); var obj = {}; obj[p] = {};
     obj[p]['email'] = encodeURI(o.aes.encryptText(email, p, {nBits:256, salt:_keys.__strIV(p)}));
     obj[p]['key'] = encodeURI(o.aes.encryptText(key, p, {nBits:256, salt:_keys.__strIV(p)}));
     obj = $.extend({}, obj, _keys.__existing(o));
     _storage.__sI(o.storage, _keys.__id(), JSON.stringify(obj));
    }
    o.callback = y;
    _main.__do(o, {'key': true});
    return true;
   },

   /**
    * @function __sK
    * @abstract Attempts to find email address for user specific key retrieval
    */
   __sK: function(o){
    var _r = false;
    if (_validation.__szCk(o.keys)>0){
     $.each(o.keys, function(a,b){
      var _x = new RegExp('/[0-9a-z-_.]{2,45}\@[0-9a-z-_.]{2,45}\.[a-z]{2,4}/gi');
      var _e = o.aes.decryptText(decodeURI(b['email']), a, {nBits:256, salt:_keys.__strIV(a)});
      if (_x.test(_e)){
       return o.aes.decryptText(decodeURI(b['key']), a, {nBits:256, salt:_keys.__strIV(a)});
      } else {
       _r = o.aes.decryptText(decodeURI(b['key']), a, {nBits:256, salt:_keys.__strIV(a)});
      }
     });
    }
    return _r;
   },

   /**
    * @function existing
    * @abstract Function used to return configured options
    *           as JSON object
    */
   __existing: function(o){
    return (_storage.__gI(o.storage, _keys.__id())) ?
      JSON.parse(_storage.__gI(o.storage, _keys.__id())) : false;
   },

   /**
    * @function __id
    * @abstract Need an id to associate the public key and other
    *           configuration options with a hostname or url
    */
   __id: function(){
    return (_validation.__vStr(location.host)) ?
     location.host :
      (_validation.__vStr(location.hostname)) ?
       location.hostname :
        'localhost';
   },

   /**
    * @function gUUID
    * @abstract Generate a uuid (RFC-4122) string or optional hex
    *           string of specified length
    */
   __gUUID: function(len){
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
   },

   /**
    * @function strIV
    * @abstract Generate IV from string
    */
   __strIV: function(s){
    return (s) ?
     encodeURI(s.replace(/-/gi, '').substring(16,Math.ceil(16*s.length)%s.length)) :
     false;
   }
  }

  /**
   * @object encrypt
   * @abstract Handles encryption functionality
   */
  var _encrypt = _encrypt || {

   /**
    * @function eO
    * @abstract Calls certParser() on public key, intializes results with
    *           external pidCrypt.RSA object, performs public key encryption
    *           on object and returns results as object
    */
   __eO: function(o, obj){
    var x = {}; var y = _encrypt.__certParser(o.use);
    _encrypt.__iP(y);
    if (_validation.__szCk(obj)>0){
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
   },

   /**
    * @function sAES
    * @abstract Returns pidCrypt.AES.CBC object for client AES storage
    */
   __sAES: function(){
    return new pidCrypt.AES.CBC();
   },

   /**
    * @function iP
    * @abstract Returns external pidCrypt.RSA object once certParse()
    *           generates necessary bytes from public key
    */
   __iP: function(pub){
    var rsa = false;
    if (pub.b64){
     var x = pidCryptUtil.decodeBase64(pub.b64);
     rsa = new pidCrypt();
     var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(x));
     var tree = asn.toHexTree();
     pidCrypt.RSA.prototype.setPublicKeyFromASN(tree);
    }
    return rsa;
   },

   /*
    * parse public/private key function
    * (Copyright https://www.pidder.com/pidcrypt/?page=demo_rsa-encryption)
    */
   __certParser: function(cert){
    if (!cert) return false;
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
  }

  /**
   * @object strings
   * @abstract Handles string processing
   */
  var _strings = _strings || {

   /**
    * @function _serialize
    * @abstract Create serialized string of object
    */
   __serialize: function(args){
    if (_validation.__szCk(args)>0){
     var x='';
     $.each(args, function(a, b){
      if (typeof b==='object'){
       $.each(b, function(c, d){
        x+=a+'['+c+']'+'='+d+'&';
       });
      } else {
       x+=a+'='+b+'&';
      }
     });
     x = x.substring(0, x.length-1);
    } else {
     return false;
    }
    return x;
   },

   /**
    * @function sSplt
    * @abstract Splits string length helper to overcome limitations with RSA
    *           cipher and key sizes
    */
   __sSplt: function(str){
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
  }

  /**
   * @object storage
   * @abstract Object to provide interface to key storage options
   */
  var _storage = _storage || {

   /**
    * @function sI
    * @abstract Proxy function for setting data with specified client storage
    *           option
    */
   __sI: function(type, k, v){
    var x = false;
    type = (_validation.__vStore(type+'Storage')) ? type : 'cookie';
    switch(type) {
     case 'local':
      x = this.__sL(k, v);
      break;
     case 'session':
      x = this.__sS(k, v);
      break;
     case 'cookie':
      x = this.__sC(k, v);
      break;
     default:
      x = this.__sL(k, v);
      break;
    }
    return x;
   },

   /**
    * @function gI
    * @abstract Proxy function for getting data with specified client storage
    *           option
    */
   __gI: function(type, k){
    var x = false;
    type = (_validation.__vStore(type+'Storage')) ? type : 'cookie';
    switch(type) {
     case 'local':
      x = this.__gL(k);
      break;
     case 'session':
      x = this.__gS(k);
      break;
     case 'cookie':
      x = this.__gC(k);
      break;
     default:
      x = this.__gL(k);
      break;
    }
    return x;
   },

   /**
    * @function dI
    * @abstract Proxy function for deleting data with specified client storage
    *           option
    */
   __dI: function(type, k){
    var x = false;
    type = (_validation.__vStore(type+'Storage')) ? type : 'cookie';
    switch(type) {
     case 'local':
      x = this.__dL(k);
      break;
     case 'session':
      x = this.__dS(k);
      break;
     case 'cookie':
      x = this.__dC(k);
      break;
     default:
      x = this.__dL(k);
      break;
    }
    return x;
   },

   /**
    * @function sL
    * @abstract Function used to set localStorage items
    */
   __sL: function(k, v){
    return (localStorage.setItem(k, v)) ? false : true;
   },

   /**
    * @function sS
    * @abstract Function used to set sessionStorage items
    */
   __sS: function(k, v){
    return (sessionStorage.setItem(k, v)) ? false : true;
   },

   /**
    * @function sC
    * @abstract Function used to set cookie items
    */
   __sC: function(k, v){
    if (typeof $.cookie === 'function') {
     return ($.cookie(k, v, {expires: 7})) ? true : false;
    } else {
     return false;
    }
   },

   /**
    * @function gL
    * @abstract Function used to get localStorage items
    */
   __gL: function(k){
    return (localStorage.getItem(k)) ? localStorage.getItem(k) : false;
   },

   /**
    * @function sS
    * @abstract Function used to get sessionStorage items
    */
   __gS: function(k){
    return (sessionStorage.getItem(k)) ? sessionStorage.getItem(k) : false;
   },

   /**
    * @function sC
    * @abstract Function used to get cookie items
    */
   __gC: function(name){
    if (typeof $.cookie === 'function') {
     return ($.cookie(name)) ? $.cookie(name) : false;
    } else {
     return false;
    }
   },

   /**
    * @function dL
    * @abstract Function used to delete localStorage items
    */
   __dL: function(k){
    return (localStorage.removeItem(k)) ? localStorage.removeItem(k) : false;
   },

   /**
    * @function dS
    * @abstract Function used to delete sessionStorage items
    */
   __dS: function(k){
    return (sessionStorage.removeItem(k)) ? sessionStorage.removeItem(k) : false;
   },

   /**
    * @function dC
    * @abstract Function used to delete cookie items
    */
   __dC: function(name){
    if (typeof $.cookie === 'function') {
     return ($.cookie(name, '', {expires: -7})) ? true : false;
    } else {
     return false;
    }
   }
  }

  /**
   * @method validation
   * @abstract Provides interface to validation functionality
   */
  var _validation = _validation || {

   /**
    * @function vStr
    * @abstract Function used combine string checking functions
    */
   __vStr: function(x){
    return ((x===false)||(x.length===0)||(!x)||(x===null)||
            (x==='')||(typeof x==='undefined')) ? false : true;
   },

   /**
    * @function vStore
    * @abstract Function used to validate client storage option
    */
   __vStore: function(type){
    try {
     return ((type in window)&&(window[type])) ? true : false;
    } catch (e) {
     return false;
    }
   },

   /**
    * @function szCk
    * @abstract Performs a check on object sizes
    */
   __szCk: function(obj){
    var n = 0;
    $.each(obj, function(k, v){
     if (obj.hasOwnProperty(k)) n++;
    });
    return n;
   }
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
