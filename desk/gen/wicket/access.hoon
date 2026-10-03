::  +wicket/access: list access tokens
::
::    Prints the prefix. -wicket!revoke-access accepts that prefix or
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
  |.  .^((list token-info) %gx /(scot %p p.bec)/wicket/(scot %da now)/access/noun)
:-  %txt
?:  ?=(%| -.run)
  ['%wicket is not running']~
(lines:wicket-dojo (tokens-text:wicket-dojo "access" p.run))
