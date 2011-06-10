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

?>
