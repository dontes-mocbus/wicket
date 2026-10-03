::  +wicket/refresh: list refresh tokens
::
::    Prints the prefix. -wicket!revoke-refresh accepts that prefix or
::    the bearer itself.
::
/-  *wicket
/+  wicket-dojo
:-  %say
|=  $:  [now=@da eny=@uvJ bec=beak]
        ~
        ~
    ==
=/  run
  %-  mule
  |.  .^((list token-info) %gx /(scot %p p.bec)/wicket/(scot %da now)/refresh/noun)
:-  %txt
?:  ?=(%| -.run)
  ['%wicket is not running']~
(lines:wicket-dojo (tokens-text:wicket-dojo "refresh" p.run))
