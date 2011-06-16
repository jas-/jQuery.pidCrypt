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

 /* jQuery.pidCrypt plug-in */
 $.fn.pidCrypt = function(method) {

  /* default options */
  var defaults = {
   storage:  'localStorage',          // Use localStorage, sessionStorage or cookies
   form:     $(this).attr('id'),      // Place holder for form ID
   proxy:    $(this).attr('action'),  // Place holder for form action
   type:     $(this).attr('method'),  // Place holder for form method
   aes:      '',                      // Place holder for AES object
   reset:    false,                   // Store public key (caching)
   debug:    false,                   // Use debugging?
   data:     {},                      // Object used for signing methods
   callback: function() {}            // Optional callback once form processed
  };

  /* define our methods */
  var methods = {

   /* primary method of usage */
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
      __cleanup(opts);
     });
    }
    return true;
   },

   /* method used to sign email using PKCS#7 certificate */
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
      __cleanup(opts);
     });
    }
    return true;
   },

   /* method of verifying PKCS#7 signed email */
   verify: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'verify';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
      __cleanup(opts);
     });
    }
    return true;
   },

   /* method used to encrypt then sign email using PKCS#7 certificate */
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
      __cleanup(opts);
     });
    }
    return true;
   },

   /* method used to decrypt then and verify PKCS#7 email */
   decrypt_verify: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'decrypt_verify';
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
      __cleanup(opts);
     });
    }
    return true;
   },

   /* method to use PKCS#12 certificate for authentication */
   authenticate: function(options){
    var opts = $.extend({}, defaults, options);
    if (__dependencies(opts)){
     opts.aes = setupAES();
     handleKey(opts);
     handlePub(opts);
     handleCert(opts);
     $('#'+opts.form).live('submit', function(e){
      e.preventDefault();
      opts.data['do'] = 'authenticate';
      opts.data['c'] = useCert(opts);
      (opts.debug) ? $('#'+opts.form).append(_output(opts)) : false;
      __do(opts);
      __cleanup(opts);
     });
    }
    return true;
   }
  };

  /* send it off to the server */
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
     ((options.callback)&&($.isFunction(options.callback))) ?
      options.callback.call(x) : false;
    },
    complete: function(x){
     (options.reset) ? _remove(options) : false;
    }
   });
   return false;
  }

  /* handles asymmetric (RSA public key) encryption */
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

  /* initialize public key */
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

  /* generate a uuid (RFC-4122) */
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

  /* initialize AES object */
  var setupAES = function(){
   return new pidCrypt.AES.CBC();
  }

  /* generate or use existing uuid key */
  var handleKey = function(options){
   (getItem(options.storage, 'uuid')) ? getItem(options.storage, 'uuid') :
                                        setItem(options.storage, 'uuid',
                                                genUUID(null));
   (getItem(options.storage, 'iv')) ? getItem(options.storage, 'iv') :
                                      setItem(options.storage, 'iv',
                                              genUUID(16));
  }

  /* ask for public key or use existing */
  var handlePub = function(options){
   (getItem(options.storage, 'pub')&&(!options.reset)) ? getItem(options.storage,
                                                                 'pub') :
                                       getPub(options);
  }

  /* use public key after decrypt */
  var usePub = function(options){
   return options.aes.decryptText(getItem(options.storage, 'pub'),
                                  getItem(options.storage, 'uuid'),
                                  {nBits:256,salt:getItem(options.storage,
                                                          'iv')});
  }

  /* get public key from server */
  var getPub = function(options){
   $.ajax({
    data: 'k=true&u='+getItem(options.storage, 'uuid')+
          '&i='+getItem(options.storage, 'iv'),
    type: 'post',
    url: options.proxy,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(response){
     //setItem(options.storage, 'pub', response);
     setItem(options.storage, 'pub',
             options.aes.encryptText(response,
                                     getItem(options.storage, 'uuid'),
                                     {nBits:256,salt:getItem(options.storage,
                                                             'iv')}));
    }
   });
   return false;
  }

  /* get public key from server */
  var getCert = function(options){
   $.ajax({
    data: 'k=true&u='+getItem(options.storage, 'uuid')+
          '&i='+getItem(options.storage, 'iv'),
    type: 'post',
    url: options.proxy,
    beforeSend: function(xhr) {
     xhr.setRequestHeader('X-Alt-Referer', 'jQuery.pidCrypt');
    },
    success: function(response){
     setItem(options.storage, 'certificate',
             options.aes.encryptText(response,
                                     getItem(options.storage, 'uuid'),
                                     {nBits:256,salt:getItem(options.storage,
                                                             'iv')}));
    }
   });
   return false;
  }

  /* ask for pkcs12 certificate or use existing */
  var handleCert = function(options){
   (getItem(options.storage, 'certificate')&&(!options.reset)) ?
    getItem(options.storage, 'certificate') : getCert(options);
  }

  /* use pkcs12 certificate after decrypt */
  var useCert = function(options){
   return options.aes.decryptText(getItem(options.storage, 'certificate'),
                                  getItem(options.storage, 'uuid'),
                                  {nBits:256,salt:getItem(options.storage,
                                                          'iv')});
  }

  /* remove client storage items */
  var _remove = function(options){
   (getItem(options.storage, 'uuid')) ? delItem(options.storage, 'uuid') : false;
   (getItem(options.storage, 'pub')) ? delItem(options.storage, 'pub') : false;
   (getItem(options.storage, 'certificate')) ? delItem(options.storage, 'certificate') : false;
   (getItem(options.storage, 'iv')) ? delItem(options.storage, 'iv') : false;
  }

  /* get form elements */
  var getElements = function(opts){
   var obj={};//:text, :password, :file, input:hidden, input:checkbox:checked, input:radio:checked, textarea, input[type="email"], input[type="url"], input[type="number"], input[type="range"], input[type="date"], input[type="month"], input[type="week"], input[type="time"], input[type="datetime"], input[type="datetime-local"], input[type="search"], input[type="color"]
   $.each($('#'+opts.form+' > :input'), function(k, v){
    if ((validateString(v.value))&&(validateString(v.name))){
     obj[v.name] = (parseInt(v.value.length)>80) ? strSplit(v.value) : v.value;
    }
   });
   return obj;
  }

  /* associative object size */
  var sizeChk = function(obj){
   var n = 0;
   $.each(obj, function(k, v){
    if (obj.hasOwnProperty(k)) n++;
   });
   return n;
  }

  /* split data for limitations with RSA cipher (see RFC3447) */
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

  /* debugging output */
  var _output = function(options){
   if (options.debug) {
    $('#'+options.form).append('<b>Processing form contents...</b><br/>');
    $('#'+options.form).append('&nbsp;<i>UUID:</i> '+getItem(options.storage, 'uuid')+'<br/>');
    $('#'+options.form).append('&nbsp;<i>IV:</i> '+getItem(options.storage, 'iv')+'<br/>');
    $('#'+options.form).append('&nbsp;<i>KEY:</i> '+usePub(options)+'<br/>');
   }
   return true;
  }

  /* debugging output helper */
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

  /* unset selected form elements */
  var __cleanup = function(options){
   delete options.data;
  }

  /* use storage options to save form data */
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

  /* use storage option to get data */
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

  /* use storage option to delete data */
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

  /* localStorage setter */
  var setLocal = function(k, v){
   return (localStorage.setItem(k, v)) ? false : true;
  }

  /* localSession setter */
  var setSession = function(k, v){
   return (sessionStorage.setItem(k, v)) ? false : true;
  }

  /* cookie setter */
  var setCookie = function(k, v){
   if (typeof $.cookie === 'function') {
    return ($.cookie(k, v, {expires: 7})) ? true : false;
   } else {
    return false;
   }
  }

  /* localStorage getter */
  var getLocal = function(k){
   return (localStorage.getItem(k)) ? localStorage.getItem(k) : false;
  }

  /* sessionStorage getter */
  var getSession = function(k){
   return (sessionStorage.getItem(k)) ? sessionStorage.getItem(k) : false;
  }

  /* cookie getter */
  var getCookie = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name)) ? $.cookie(name) : false;
   } else {
    return false;
   }
  }

  /* localStorage delete */
  var delLocal = function(k){
   return (localStorage.removeItem(k)) ? localStorage.removeItem(k) : false;
  }

  /* sessionStorage delete */
  var delSession = function(k){
   return (sessionStorage.removeItem(k)) ? sessionStorage.removeItem(k) : false;
  }

  /* cookie delete */
  var delCookie = function(name){
   if (typeof $.cookie === 'function') {
    return ($.cookie(name, '', {expires: -7})) ? true : false;
   } else {
    return false;
   }
  }

  /* validate string integrity */
  var validateString = function(x){
   return ((x===false)||(x.length===0)||(!x)||(x===null)||
           (x==='')||(typeof x==='undefined')) ? false : true;
  }

  /* validate localStorage/localSession functionality */
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

  /* dependencies? */
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

  /* object inspector for debugging */
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
