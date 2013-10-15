ngx_http_extauth_download
=========================

Secure download module for nginx

Based on http://wiki.nginx.org/HttpSecureDownload

<b>Configuration example</b>

    location / {
              root   html;
              index  index.html index.htm;
              #enable module
                  extauth_download on;
              #path mode
                  extauth_download_path_mode file;
              #memcache server address
                  extauth_download_keyserver_ip 127.0.0.1;
              #expired timestamp
              if ($extauth_download = "-1") {
                         return 500;
              }
              #hash mismatch
              if ($extauth_download = "-2") {
                  return 500;
              }
              #module internal error or module not enabled
              #
              if ($extauth_download = "-3") {
                  return 500;
              }
              #couldn't add memcache server
              if ($extauth_download = "-4") {
                  return 500;
                  }
              #memcache error or key not found
              if ($extauth_download = "-5") {
                  return 500;
              }
              rewrite ^(.*)/[0-9a-zA-Z]*/[0-9a-zA-Z]*$ $1 break;
      }
  
  A generated URI must have the following format: \<real_path\>/\<md5_hash\>/\<expiration_timestamp\>
 
        <expiration_timestamp> = timestamp converted to hex
        memcache query key = <real_path>
        fetched value should be equal to <md5_hash>
  
  Valid url example: <i>http://127.0.0.1:81/news.png/86ff173d4fd1307686d25620eae682dc/525d359c</i>

  <b>Requirements</b>
  
  To compile the nginx with this module you will need to have following:

    -The mod_rewrite in the nginx has to be enabled
    -You need the memcached library
    -Tested under nginx-1.4.3

  <b>Bugs/Feedback</b>
  
  Any report about bugs will be appreciated.

  E-mail: arthurtumanyan@gmail.com
  
