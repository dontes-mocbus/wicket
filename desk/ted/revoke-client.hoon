::  -wicket!revoke-client: delete a client and its tokens
::
::    Usage: -wicket!revoke-client 'client-id'
::
/-  spider, *wicket
/+  strandio
=,  strand=strand:spider
^-  thread:spider
|=  arg=vase
=/  m  (strand ,vase)
^-  form:m
=/  cid=client-id
  =/  one=(each client-id tang)  (mule |.(!<(client-id arg)))
  ?:  ?=(%& -.one)  p.one
  (need !<((unit client-id) arg))
;<  ~  bind:m  (poke-our:strandio %wicket %wicket-action !>([%revoke-client cid]))
(pure:m !>(leaf+"client revoked"))
