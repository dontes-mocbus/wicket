::  -wicket!drop-scopes: remove scopes already granted
::
::    Usage: -wicket!drop-scopes ['client-id' 'resource-url' 'scope scope']
::    A scope that is not on the grant is rejected. This cannot add one.
::
/-  spider, *wicket
/+  strandio, wicket
=,  strand=strand:spider
^-  thread:spider
|=  arg=vase
=/  m  (strand ,vase)
^-  form:m
=/  [cid=@t res=@t raw=@t]
  =/  one=(each [@t @t @t] tang)  (mule |.(!<([@t @t @t] arg)))
  ?:  ?=(%& -.one)  p.one
  (need !<((unit [@t @t @t]) arg))
=/  drop  (split-space:wicket raw)
?~  drop
  (strand-fail:strand %no-scopes ~)
;<  as=(list authorization)  bind:m
  (scry:strandio (list authorization) /gx/wicket/grants/noun)
=/  key  `res
=/  cur
  |-  ^-  (unit authorization)
  ?~  as  ~
  ?:  ?&  =(client.i.as cid)
          =(resource.i.as key)
      ==
    `i.as
  $(as t.as)
?~  cur
  (strand-fail:strand %unknown-grant ~)
?~  (without-scopes:wicket scopes.u.cur drop)
  (strand-fail:strand %scope-not-granted ~)
;<  ~  bind:m
  (poke-our:strandio %wicket %wicket-action !>([%drop-scopes cid key drop]))
(pure:m !>(leaf+"scopes dropped"))
