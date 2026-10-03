::  -wicket!revoke-access: revoke one access token
::
::    Usage: -wicket!revoke-access 'prefix'
::    Pass the prefix printed by +wicket/access, or the bearer itself.
::
/-  spider, *wicket
/+  strandio
=,  strand=strand:spider
^-  thread:spider
|=  arg=vase
=/  m  (strand ,vase)
^-  form:m
=/  id=@t
  =/  one=(each @t tang)  (mule |.(!<(@t arg)))
  ?:  ?=(%& -.one)  p.one
  (need !<((unit @t) arg))
;<  ~  bind:m  (poke-our:strandio %wicket %wicket-action !>([%revoke-access id]))
(pure:m !>(leaf+"access token revoked"))
