::  /lib/wicket-dojo: text for the owner generators
::
::    Token lines print the prefix. A revoke thread accepts that prefix
::    or the bearer itself. The MCP returns the same prefix.
::
/-  *wicket
/+  wicket, wicket-html
|%
++  lines
  |=  w=(list tape)
  ^-  wain
  (turn w crip)
::
++  or-empty
  |=  [rows=(list tape) empty=tape]
  ^-  (list tape)
  ?~(rows [empty]~ rows)
::
++  resource-tape
  |=  r=(unit resource)
  ^-  tape
  ?~(r "(no resource)" (trip u.r))
::
++  scope-tape
  |=  s=(list scope)
  ^-  tape
  ?~(s "(none)" (trip (join-space:wicket s)))
::
++  when
  |=  d=@da
  ^-  tape
  ?:  =(d *@da)  "(unset)"
  (fmt-da:wicket-html d)
::
++  client-line
  |=  c=client
  ^-  tape
  ;:  weld
    (trip id.c)
    "  "
    (trip name.c)
    "  "
    (when created.c)
  ==
::
++  redirect-lines
  |=  uris=(set @t)
  ^-  (list tape)
  %+  turn  (sort ~(tap in uris) aor)
  |=  u=@t
  (weld "  redirect  " (trip u))
::
++  client-block
  |=  c=client
  ^-  (list tape)
  [(client-line c) (redirect-lines redirect-uris.c)]
::
++  clients-text
  |=  cs=(list client)
  ^-  (list tape)
  ?:  =(~ cs)  ["no clients"]~
  %+  roll  cs
  |=  [c=client acc=(list tape)]
  (weld acc (welp (client-block c) "" ~))
::
++  grant-line
  |=  a=authorization
  ^-  tape
  ;:  weld
    (trip client.a)
    "  "
    (resource-tape resource.a)
    "  "
    (scope-tape scopes.a)
    "  "
    (when updated.a)
  ==
::
++  grants-text
  |=  as=(list authorization)
  ^-  (list tape)
  (or-empty (turn as grant-line) "no grants")
::
++  token-line
  |=  [kind=tape t=token-info]
  ^-  tape
  ;:  weld
    kind
    "  "
    (trip id-prefix.t)
    "  "
    (trip client.t)
    "  "
    (resource-tape resource.t)
    "  "
    (scope-tape scopes.t)
    "  "
    (when expires.t)
  ==
::
++  tokens-text
  |=  [kind=tape rows=(list token-info)]
  ^-  (list tape)
  (or-empty (turn rows |=(t=token-info (token-line kind t))) "no tokens")
::
++  resource-line
  |=  r=registered-resource
  ^-  tape
  ;:  weld
    (trip url.r)
    "  "
    (trip agent.r)
    "  "
    (scope-tape ~(tap in scopes.r))
  ==
::
++  resources-text
  |=  rs=(list registered-resource)
  ^-  (list tape)
  (or-empty (turn rs resource-line) "no resources")
--
