::  -wicket!revoke-refresh: revoke one refresh token
::
::    Usage: -wicket!revoke-refresh 'prefix'
::    Pass the prefix printed by +wicket/refresh, or the bearer itself.
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
;<  ~  bind:m  (poke-our:strandio %wicket %wicket-action !>([%revoke-refresh id]))
(pure:m !>(leaf+"refresh token revoked"))
