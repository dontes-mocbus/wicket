::  /lib/wicket-http: status + header builders for %wicket
::
/+  server, wicket, wicket-tile
|%
++  cors-headers
  |=  =request:http
  ^-  header-list:http
  =/  orig  (header:wicket 'origin' header-list.request)
  :~  ['access-control-allow-origin' (fall orig '*')]
      ['access-control-allow-headers' 'Authorization, Content-Type']
      ['access-control-allow-methods' 'GET, POST, OPTIONS']
      ['access-control-max-age' '86400']
  ==
::
++  with-cors
  |=  [=request:http pay=simple-payload:http]
  ^-  simple-payload:http
  =-  pay(headers.response-header -)
  (weld (cors-headers request) headers.response-header.pay)
::
++  options
  |=  =request:http
  ^-  simple-payload:http
  [[204 (cors-headers request)] ~]
::
++  json-code
  |=  [code=@ud jon=json extra=header-list:http]
  ^-  simple-payload:http
  :-  :-  code
      %+  weld  extra
      ['content-type' 'application/json']~
  `(json-to-octs:server jon)
::
++  json-ok
  |=  jon=json
  (json-code 200 jon ~)
::
++  json-created
  |=  jon=json
  (json-code 201 jon ~)
::
++  oauth-error-headers
  |=  [code=@ud err=@t extra=header-list:http]
  ^-  simple-payload:http
  %+  json-code  code
  :-  (pairs:enjs:format [error+s+err]~)
  (weld extra ['cache-control' 'no-store']~)
::
++  oauth-error
  |=  [code=@ud err=@t]
  ^-  simple-payload:http
  (oauth-error-headers code err ~)
::
++  html-code
  |=  [code=@ud =manx]
  ^-  simple-payload:http
  :-  [code ['content-type' 'text/html; charset=utf-8']~]
  `(manx-to-octs:server manx)
::
++  html-ok
  |=  =manx
  (html-code 200 manx)
::
++  html-private
  |=  [code=@ud =manx]
  ^-  simple-payload:http
  :-  :-  code
      :~  ['content-type' 'text/html; charset=utf-8']
          ['cache-control' 'no-store']
      ==
  `(manx-to-octs:server manx)
::
++  found
  |=  loc=@t
  ^-  simple-payload:http
  [[302 ['location' loc]~] ~]
::
++  see-other
  |=  loc=@t
  ^-  simple-payload:http
  [[303 ['location' loc] ['cache-control' 'no-store'] ~] ~]
::
++  empty-ok
  ^-  simple-payload:http
  [[200 ['content-type' 'application/json']~] ~]
::
++  tile-image
  ^-  simple-payload:http
  :-  :-  200
      :~  ['content-type' 'image/jpeg']
          ['cache-control' 'public, max-age=86400']
      ==
  `(as-octs:mimes:html tile-jpg:wicket-tile)
::
++  not-found  not-found:gen:server
::
++  method-not-allowed
  ^-  simple-payload:http
  [[405 ['allow' 'GET, POST, OPTIONS']~] ~]
::
++  www-authenticate
  |=  [meta=@t scope=(unit @t)]
  ^-  @t
  =/  base=@t
    (rap 3 ['Bearer realm="wicket", resource_metadata="' meta '"' ~])
  ?~  scope  base
  (rap 3 [base ', scope="' u.scope '"' ~])
::
++  bearer-401
  |=  meta=@t
  ^-  simple-payload:http
  %+  json-code  401
  :-  (pairs:enjs:format ['error' s+'invalid_token']~)
  ['www-authenticate' (www-authenticate meta ~)]~
::
++  bearer-403
  |=  [meta=@t scope=@t]
  ^-  simple-payload:http
  %+  json-code  403
  :-  (pairs:enjs:format ['error' s+'insufficient_scope']~)
  ['www-authenticate' (www-authenticate meta `scope)]~
::
++  origin-unset
  ^-  simple-payload:http
  %+  json-code  503
  :-  (pairs:enjs:format ['error' s+'origin_unset']~)
  ~
--
