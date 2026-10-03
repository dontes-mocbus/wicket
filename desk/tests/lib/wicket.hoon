::  PKCE and helper unit tests for %wicket
::
/-  *wicket
/+  *test, server, wicket, wicket-html, wicket-check, wicket-http, wicket-tile
|%
::  RFC 7636 Appendix B
::
++  rfc-verifier   'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
++  rfc-challenge  'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
::
++  test-s256-rfc-7636
  %+  expect-eq
    !>(rfc-challenge)
    !>((s256:wicket rfc-verifier))
::
++  test-verifier-length
  ;:  weld
    (expect !>((valid-verifier:wicket rfc-verifier)))
    (expect !>((valid-challenge:wicket rfc-challenge)))
    (expect !>((nvalid-verifier 'short')))
    (expect !>((nvalid-unreserved 'has space')))
  ==
::
++  nvalid-verifier
  |=  t=@t
  ?!((valid-verifier:wicket t))
++  nvalid-unreserved
  |=  t=@t
  ?!((unreserved-cord:wicket t))
::
++  test-chop-slash
  ;:  weld
    %+  expect-eq
      !>(`@t`'http://127.0.0.1:8080')
      !>((chop-slash:wicket 'http://127.0.0.1:8080/'))
    %+  expect-eq
      !>(`@t`'http://127.0.0.1:8080')
      !>((chop-slash:wicket 'http://127.0.0.1:8080'))
  ==
::
++  test-on-origin
  =/  org  'http://127.0.0.1:8080'
  ;:  weld
    (expect !>((on-origin:wicket org org)))
    (expect !>((on-origin:wicket org 'http://127.0.0.1:8080/mcp/recipe')))
    (expect !>((non-origin org 'http://127.0.0.1:8080.evil/x')))
    (expect !>((non-origin org 'https://127.0.0.1:8080/mcp/recipe')))
  ==
::
++  non-origin
  |=  [org=@t url=@t]
  ?!((on-origin:wicket org url))
::
++  test-redirect-ok
  ;:  weld
    (expect !>((redirect-ok:wicket 'https://example.com/cb')))
    (expect !>((redirect-ok:wicket 'http://127.0.0.1:9876/cb')))
    (expect !>((redirect-ok:wicket 'http://localhost:9876/cb')))
    (expect !>((nredirect 'javascript:alert(1)')))
    (expect !>((nredirect 'data:text/html,x')))
    (expect !>((nredirect 'http://localhost.evil/cb')))
    (expect !>((nredirect '')))
  ==
::
++  nredirect
  |=  uri=@t
  ?!((redirect-ok:wicket uri))
::
++  test-split-space
  %+  expect-eq
    !>  `(list @t)`~['recipe.read' 'recipe.write']
    !>((split-space:wicket 'recipe.read recipe.write'))
::
++  test-join-space
  %+  expect-eq
    !>(`@t`'recipe.read recipe.write')
    !>((join-space:wicket `(list @t)`~['recipe.read' 'recipe.write']))
::
++  test-subset-scopes
  ;:  weld
    (expect !>((subset-scopes:wicket ~['a'] ~['a' 'b'])))
    (expect !>((subset-scopes:wicket ~ ~['a'])))
    (expect !>((nsubset ~['a' 'c'] ~['a' 'b'])))
  ==
::
++  nsubset
  |=  [want=(list @t) have=(list @t)]
  ?!((subset-scopes:wicket want have))
::
++  test-prefix-id
  %+  expect-eq
    !>(`@t`'abcdefgh')
    !>((prefix-id:wicket 'abcdefghijkl'))
::
++  test-secret-hash
  =/  cord  'bearer-cord'
  ;:  weld
    %+  expect-eq
      !>  `@`(shax cord)
      !>((secret-hash:wicket cord))
    (expect !>(!=((secret-hash:wicket cord) (secret-hash:wicket 'other-cord'))))
  ==
::
++  test-prefix-id-long
  =/  cord  'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'
  %+  expect-eq
    !>(`@t`'abcdefgh')
    !>((prefix-id:wicket cord))
::
++  test-clip-scopes
  %+  expect-eq
    !>  `(list @t)`~['a']
    !>((clip-scopes:wicket ~['a' 'b'] ~['a']))
::
++  test-token-edits
  =/  same=logged-token:wicket
    [%access 'SAME-ID' 'cid' ~ ~['read'] ~2026.9.21..16.00.00]
  =/  clip=logged-token:wicket
    [%access 'CLIP-ID' 'cid' ~ ~['read' 'write'] ~2026.9.21..16.01.00]
  =/  gone=logged-token:wicket
    [%refresh 'GONE-ID' 'cid' ~ ~['write'] ~2026.9.21..16.02.00]
  =/  clipped=token-edit:wicket  [clip `~['read']]
  =/  removed=token-edit:wicket  [gone ~]
  =/  want=(list token-edit:wicket)  ~[clipped removed]
  =/  got  (token-edits:wicket ~[same clip gone] ~['read'])
  %+  expect-eq
    !>(want)
    !>(got)
::
++  test-login-target
  ;:  weld
    %+  expect-eq
      !>(`@t`'/oauth/authorize?response_type=code')
      !>((login-target:wicket '/oauth/authorize?response_type=code'))
    %+  expect-eq
      !>(`@t`'/oauth/authorize?x=1')
      !>((login-target:wicket 'http://127.0.0.1:8080/oauth/authorize?x=1'))
    %+  expect-eq
      !>(`@t`'/')
      !>((login-target:wicket '/~/login?redirect=/oauth/authorize'))
  ==
::
++  test-eyre-login-href
  =/  here  '/wicket/oauth/authorize?response_type=code&client_id=abc'
  =/  href  (eyre-login-href:wicket here)
  =/  tail  (slag 18 href)
  =/  abs   (eyre-login-href:wicket 'http://127.0.0.1:8080/oauth/authorize?x=1')
  ;:  weld
    %+  expect-eq
      !>("/~/login?redirect=")
      !>((scag 18 href))
    (expect !>(?=(^ (find "%3F" tail))))
    (expect !>(?=(^ (find "%3D" tail))))
    (expect !>(?=(^ (find "%26" tail))))
    (expect !>(?=(~ (find "?" tail))))
    (expect !>(?=(~ (find "=" tail))))
    (expect !>(?=(~ (find "&" tail))))
    (expect !>(?=(~ (find "127.0.0.1" abs))))
    (expect !>(?=(^ (find "%3D" abs))))
  ==
::
++  test-consent-warn
  =/  who=client
    ['grok' 'Grok' (silt ~['http://127.0.0.1/cb']) ~2026.9.21]
  =/  url  'http://127.0.0.1:8080/pier-mcp'
  =/  notes=(map scope scope-note)
    %-  malt
    :~  :-  'pier-mcp.read'
        `scope-note`['Read this ship.' |]
        :-  'pier-mcp.owner'
        `scope-note`['Full control of this ship.' &]
        :-  'groups-mcp.channels.write'
        `scope-note`['Post where writing is open.' %ask]
    ==
  =/  copies=(map resource scope-copy)
    (malt ~[[url ['Pier MCP' notes]]])
  =/  az=authz
    :*  0v1
        'grok'
        'http://127.0.0.1/cb'
        'st'
        'chal'
        `url
        ~['pier-mcp.read' 'pier-mcp.owner' 'groups-mcp.channels.write']
        ~2026.9.21..15.40.00
    ==
  =/  xml  (en-xml:html (consent-page:wicket-html ~zod who az copies))
  =/  own  (need (find "pier-mcp.owner" xml))
  =/  wr  (need (find "groups-mcp.channels.write" xml))
  =/  rd  (need (find "pier-mcp.read" xml))
  =/  own-tag  (swag [(sub own 90) 120] xml)
  =/  wr-tag  (swag [(sub wr 40) 80] xml)
  ;:  weld
    (expect !>(?=(^ (find "Pier MCP" xml))))
    (expect !>(?=(^ (find "Full control of this ship." xml))))
    (expect !>(?=(^ (find "Post where writing is open." xml))))
    (expect !>(?=(^ (find "Read this ship." xml))))
    (expect !>(?=(^ (find "Controls the ship" xml))))
    (expect !>(?=(^ (find "scope warn" xml))))
    (expect !>(?=(~ (find "checked" own-tag))))
    (expect !>(?=(~ (find "checked" wr-tag))))
    (expect !>(?=(~ (find "Controls the ship" wr-tag))))
    (expect !>(?=(^ (find "checked=\"checked\"" xml))))
    %+  expect-eq
      !>(1)
      !>((times "Controls the ship" xml))
    (expect !>((lth own wr)))
    (expect !>((lth wr rd)))
  ==
::
++  test-scope-label
  ;:  weld
    %+  expect-eq
      !>("List OAuth clients")
      !>((scope-label:wicket-html 'wicket.clients.read'))
    %+  expect-eq
      !>("Remove granted scopes")
      !>((scope-label:wicket-html 'wicket.grants.drop'))
    %+  expect-eq
      !>("unknown.foo")
      !>((scope-label:wicket-html 'unknown.foo'))
    (expect !>((nwarn 'wicket.clients.revoke')))
    (expect !>((nwarn 'wicket.grants.drop')))
  ==
::
++  nwarn
  |=  s=@t
  ?!((scope-warn:wicket-html s))
::
++  test-resource-label
  ;:  weld
    %+  expect-eq
      !>("this ship")
      !>((resource-label:wicket-html ~))
    %+  expect-eq
      !>("Keeper")
      !>((resource-label:wicket-html `'http://127.0.0.1:8080/wicket/mcp'))
    %+  expect-eq
      !>("http://127.0.0.1:8080/other")
      !>((resource-label:wicket-html `'http://127.0.0.1:8080/other'))
  ==
::
++  test-fmt-da
  %+  expect-eq
    !>("2026-09-21 15:30")
    !>((fmt-da:wicket-html ~2026.9.21..15.30.00))
::
++  test-join-labels
  %+  expect-eq
    !>("List OAuth clients · Revoke OAuth clients")
    !>((join-labels:wicket-html ~['wicket.clients.read' 'wicket.clients.revoke'] ~ *(map resource scope-copy)))
::
++  test-issuer
  %+  expect-eq
    !>(`@t`'http://127.0.0.1:8080/wicket')
    !>((issuer:wicket 'http://127.0.0.1:8080/'))
::
++  test-prm-url
  =/  org  'http://127.0.0.1:8080'
  =/  url  'http://127.0.0.1:8080/wicket/mcp'
  =/  want  'http://127.0.0.1:8080/wicket/oauth/protected-resource/wicket/mcp'
  ;:  weld
    %+  expect-eq
      !>(`@t`want)
      !>((prm-url:wicket org url))
    %+  expect-eq
      !>(`@t`want)
      !>((metadata:wicket-check org url))
  ==
::
++  test-without-scopes
  ;:  weld
    %+  expect-eq
      !>(~)
      !>((without-scopes:wicket ~['a' 'b'] ~['c']))
    %+  expect-eq
      !>(~)
      !>((without-scopes:wicket ~['a'] ~))
    %+  expect-eq
      !>  `(unit (list @t))`[~ ~['b']]
      !>((without-scopes:wicket ~['a' 'b'] ~['a']))
    %+  expect-eq
      !>  `(unit (list @t))`[~ ~]
      !>((without-scopes:wicket ~['a'] ~['a']))
  ==
::
++  test-pair-values
  =/  pairs=(list [p=@t q=@t])
    ~[['scope' 'a'] ['id' '1'] ['scope' 'b']]
  %+  expect-eq
    !>  `(list @t)`~['a' 'b']
    !>((pair-values:wicket 'scope' pairs))
::
++  test-match-token
  =/  a  (tok 'abcdefgh' 'one')
  =/  b  (tok 'abcdefgh' 'two')
  =/  c  (tok 'zzzzzzzz' 'three')
  ;:  weld
    %+  expect-eq
      !>(`(unit token-info)`[~ a])
      !>((match-token:wicket 'abcdefgh' ~[a c]))
    %+  expect-eq
      !>(`(unit token-info)`~)
      !>((match-token:wicket 'missing' ~[a]))
    %+  expect-eq
      !>(`(unit token-info)`~)
      !>((match-token:wicket 'abcdefgh' ~[a b]))
    %+  expect-eq
      !>(`(unit token-info)`~)
      !>((match-token:wicket 'abcdefghi' ~[a c]))
  ==
::
++  tok
  |=  [pre=@t who=@t]
  ^-  token-info
  [pre who ~ ~ ~2026.1.1]
::
++  test-posted-from-origin
  =/  org  'http://127.0.0.1:8080'
  =/  local  'http://localhost:8080'
  =/  path  (cat 3 org '/wicket/manage')
  =/  both  ~[org local]
  ;:  weld
    (expect !>((posted-from-origin:wicket both ~[['origin' org]])))
    (expect !>((posted-from-origin:wicket both ~[['Origin' org]])))
    (expect !>((posted-from-origin:wicket both ~[['origin' local]])))
    (expect !>((posted-from-origin:wicket both ~[['referer' path]])))
    (expect !>((posted-from-origin:wicket both ~[['referer' org]])))
    (expect !>((posted-from-origin:wicket both ~[['origin' org] ['referer' 'http://evil/x']])))
    (expect !>((norigin both ~[['origin' 'http://127.0.0.1:8080.evil']])))
    (expect !>((norigin both ~[['referer' 'http://127.0.0.1:8080.evil/x']])))
    (expect !>((norigin both ~)))
    (expect !>((norigin ~[''] ~[['origin' org]])))
    (expect !>((norigin ~[org] ~[['origin' 'http://evil'] ['referer' path]])))
    (expect !>((norigin ~[org] ~[['origin' local]])))
  ==
::
++  norigin
  |=  [allowed=(list @t) headers=(list [key=@t value=@t])]
  ?!((posted-from-origin:wicket allowed headers))
::
++  test-request-origin
  ;:  weld
    %+  expect-eq
      !>(`@t`'http://localhost:8080')
      !>((request-origin:wicket %.n ~[['host' 'localhost:8080']]))
    %+  expect-eq
      !>(`@t`'https://localhost:8080')
      !>((request-origin:wicket %.y ~[['Host' 'localhost:8080']]))
    %+  expect-eq
      !>(`@t`'')
      !>((request-origin:wicket %.n ~))
  ==
::
++  test-manage-href
  ;:  weld
    %+  expect-eq
      !>("/wicket/manage")
      !>((manage-href:wicket-html ~ ~))
    %+  expect-eq
      !>("/wicket/manage?done=scope")
      !>((manage-href:wicket-html `'scope' ~))
    %+  expect-eq
      !>("/wicket/manage?done=scope&open=client-one")
      !>((manage-href:wicket-html `'scope' `'client-one'))
    %+  expect-eq
      !>("/wicket/manage?open=client-one")
      !>((manage-href:wicket-html ~ `'client-one'))
  ==
::
++  test-manage-page
  =/  cid  'client-one'
  =/  full  'SECRET-TOKEN-VALUE-0123456789abcdef'
  =/  pre  'SECRET-T'
  =/  who=client
    [cid 'Grok' (silt ~['https://example.com/cb']) ~2026.9.21..15.30.00]
  =/  idle=client
    ['other-client' '' *(set @t) ~2026.9.21..12.00.00]
  =/  res  `'http://127.0.0.1:8080/wicket/mcp'
  =/  other  `'https://example.com/mcp'
  =/  grant=authorization
    [cid res ~['wicket.clients.read'] ~2026.9.21..15.30.00]
  =/  grant2=authorization
    [cid other ~['recipe.read'] ~2026.9.21..16.00.00]
  =/  tok=token-info
    [pre cid res ~['wicket.clients.read'] ~2026.9.21..15.00.00]
  =/  dead-ref=token-info
    ['DEAD-REF' cid res ~['wicket.clients.read'] ~2026.9.21..14.00.00]
  =/  exact=token-info
    ['EXACTNOW' cid res ~['wicket.clients.read'] ~2026.9.21..15.45.00]
  =/  live-acc=token-info
    ['LIVE-ACC' cid res ~['wicket.clients.read'] ~2026.9.21..18.05.00]
  =/  live-ref=token-info
    ['LIVE-REF' cid res ~['wicket.clients.read'] ~2026.9.22..09.15.00]
  =/  rec=registered-resource
    :-  'http://127.0.0.1:8080/wicket/mcp'
    [%keeper (silt ~['wicket.clients.read']) 'http://127.0.0.1:8080/wicket/mcp']
  =/  v=manage-view:wicket-html
    :*  ~zod
        ~2026.9.21..15.45.00
        ~[who idle]
        ~[grant grant2]
        ~[tok exact live-acc]
        ~[dead-ref live-ref]
        ~[rec]
        [~ "Scope removed."]
        ~
        |
        (silt ~[cid 'other-client'])
        ~
        *(map resource scope-copy)
    ==
  =/  xml  (en-xml:html (manage-page:wicket-html v))
  =/  opened  (en-xml:html (manage-page:wicket-html v(open `cid)))
  =/  tile  (cut-between "<summary>" "</summary>" xml)
  =/  idle-tile  (cut-between "<summary>" "</summary>" (slag (add 1 (need (find "<summary>" xml))) xml))
  ;:  weld
    (expect !>(?=(^ (find "Clients on ~zod" xml))))
    (expect !>(?=(^ (find "Scope removed." xml))))
    (expect !>(?=(^ (find "List OAuth clients" xml))))
    (expect !>(?=(^ (find "wicket.clients.read" xml))))
    (expect !>(?=(^ (find "class=\"pair\"" xml))))
    (expect !>(?=(^ (find "Remove List OAuth clients" xml))))
    (expect !>(?=(^ (find "Revoke access token LIVE-ACC" xml))))
    (expect !>(?=(^ (find "Revoke refresh token LIVE-REF" xml))))
    (expect !>(?=(^ (find "2026-09-21 18:05" xml))))
    (expect !>(?=(^ (find "2026-09-22 09:15" xml))))
    (expect !>(?=(~ (find "SECRET-T" xml))))
    (expect !>(?=(~ (find "DEAD-REF" xml))))
    (expect !>(?=(~ (find "EXACTNOW" xml))))
    (expect !>(?=(~ (find "expired" xml))))
    (expect !>(?=(~ (find "2026-09-21 15:00" xml))))
    (expect !>(?=(~ (find "2026-09-21 14:00" xml))))
    (expect !>(?=(~ (find "2026-09-21 15:45" xml))))
    %+  expect-eq
      !>(2)
      !>((times "No tokens." xml))
    (expect !>(?=(^ (find "Keeper" xml))))
    (expect !>(?=(^ (find "<h2>Clients</h2>" xml))))
    (expect !>(?=(^ (find "Registered, no access" xml))))
    (expect !>(?=(^ (find "other-client" xml))))
    (expect !>(?=(^ (find "Removing this scope ends the grant" xml))))
    (expect !>(?=(^ (find "<details class=\"client\">" xml))))
    (expect !>(?=(^ (find "Grok" tile))))
    (expect !>(?=(^ (find "client-one" tile))))
    (expect !>(?=(^ (find "2026-09-21 15:30" tile))))
    (expect !>(?=(^ (find "Keeper · https://example.com/mcp" tile))))
    (expect !>(?=(~ (find "List OAuth clients" tile))))
    (expect !>(?=(~ (find "LIVE-ACC" tile))))
    (expect !>(?=(~ (find "LIVE-REF" tile))))
    (expect !>(?=(~ (find "SECRET-T" tile))))
    (expect !>(?=(~ (find "Revoke client" tile))))
    (expect !>(?=(^ (find "No access" idle-tile))))
    (expect !>(?=(^ (find "2026-09-21 12:00" idle-tile))))
    (expect !>(?=(~ (find "open=\"open\"" xml))))
    (expect !>(?=(^ (find "open=\"open\"" opened))))
    (expect !>(?=(~ (find (trip full) xml))))
    (expect !>(?=(~ (find "DEAD-REFRESH-TOKEN-VALUE-abcdef" xml))))
    (expect !>(?=(~ (find "EXACT-NOW-TOKEN-VALUE-0123456789ab" xml))))
    (expect !>(?=(~ (find "LIVE-ACCESS-TOKEN-VALUE-0123456789" xml))))
    (expect !>(?=(~ (find "LIVE-REFRESH-TOKEN-VALUE-0123456789" xml))))
    (expect !>(?=(~ (find "revoke-client" xml))))
    (expect !>(?=(^ (find "Open registration" xml))))
    (expect !>(?=(^ (find ">Closed<" xml))))
    (expect !>(?=(^ (find "href=\"/wicket/manage/log\"" xml))))
    (expect !>(?=(~ (find "<script" xml))))
  ==
::
++  test-registration-open
  =/  cid  'client-one'
  =/  idle=client
    ['waiting' 'Cursor' *(set @t) ~2026.9.21..12.00.00]
  =/  v=manage-view:wicket-html
    :*  ~zod
        ~2026.9.21..15.45.00
        ~[idle]
        ~
        ~
        ~
        ~
        ~
        ~
        &
        *(set client-id)
        ~['203.0.113.4']
        *(map resource scope-copy)
    ==
  =/  xml  (en-xml:html (manage-page:wicket-html v))
  ;:  weld
    (expect !>(?=(^ (find "Close registration" xml))))
    (expect !>(?=(^ (find ">Open<" xml))))
    (expect !>(?=(^ (find "5 clients an hour" xml))))
    (expect !>(?=(^ (find "24 hours" xml))))
    (expect !>(?=(^ (find "1 waiting" xml))))
    (expect !>(?=(^ (find "203.0.113.4" xml))))
    (expect !>(?=(^ (find "Block address" xml))))
    (expect !>(?=(^ (find "Removed 2026-09-22 12:00 if not approved." xml))))
    (expect !>(?=(~ (find "<script" xml))))
    (expect !>(?=(~ (find "No access granted." xml))))
  ==
::
++  test-admit-registration
  =/  now  ~2026.9.21..12.00.00
  =/  who  [%ipv4 .203.0.113.4]
  =/  local  [%ipv4 .127.0.0.1]
  =/  denied  (silt ~[who])
  =/  recent=rate-map:wicket
    (malt ~[[local [5 now]]])
  =/  closed  (admit-registration:wicket | who now denied 0 ~)
  =/  blocked  (admit-registration:wicket & who now denied 0 ~)
  =/  full  (admit-registration:wicket & local now ~ unapproved-cap:wicket ~)
  =/  room  (admit-registration:wicket & local now ~ (dec unapproved-cap:wicket) ~)
  =/  limited  (admit-registration:wicket & local now ~ 0 recent)
  =/  fresh  (admit-registration:wicket & who now ~ 0 recent)
  ;:  weld
    (expect-eq !>([%closed ~]) !>(closed))
    (expect-eq !>([%denied ~]) !>(blocked))
    (expect-eq !>([%full ~]) !>(full))
    (expect-eq !>([%ok ~]) !>(room))
    (expect-eq !>([%limited 3.600]) !>(limited))
    (expect-eq !>([%ok ~]) !>(fresh))
  ==
::
++  test-admit-rate-map-cap
  =/  now  ~2026.9.21..12.00.00
  =/  who  [%ipv4 .203.0.113.50]
  =/  fill
    |=  since=@da
    =/  i  0
    =|  acc=(list [address:eyre rate-hit:wicket])
    |-  ^-  rate-map:wicket
    ?:  =(rate-map-cap:wicket i)
      (malt acc)
    $(i +(i), acc [[[%ipv4 `@if`i] [1 since]] acc])
  =/  live  (admit-registration:wicket & who now ~ 0 (fill now))
  =/  stale  (admit-registration:wicket & who now ~ 0 (fill (sub now ~h2)))
  =/  held  (admit-registration:wicket & [%ipv4 `@if`0] now ~ 0 (fill now))
  ;:  weld
    (expect !>(?=(%limited -.live)))
    (expect-eq !>([%ok ~]) !>(stale))
    (expect-eq !>([%ok ~]) !>(held))
  ==
::
++  test-note-registration
  =/  now  ~2026.9.21..15.00.00
  =/  who  [%ipv4 .127.0.0.1]
  =/  old  [%ipv4 .198.51.100.4]
  =/  live  [%ipv4 .203.0.113.4]
  =/  once  (note-registration:wicket now who ~)
  =/  twice  (note-registration:wicket now who once)
  =/  later  (add now ~h1)
  =/  reset  (note-registration:wicket later who twice)
  =/  mixed
    %-  malt
    :~  [old [1 (sub now ~h1)]]
        [live [2 now]]
        [who [4 now]]
    ==
  =/  pruned  (note-registration:wicket now who mixed)
  ;:  weld
    (expect-eq !>((malt ~[[who [1 now]]])) !>(once))
    (expect-eq !>((malt ~[[who [2 now]]])) !>(twice))
    (expect-eq !>((malt ~[[who [1 later]]])) !>(reset))
    (expect-eq !>((malt ~[[live [2 now]] [who [5 now]]])) !>(pruned))
  ==
::
++  test-sweep-idle
  =/  now  ~2026.9.21..12.00.00
  =/  old=client  ['old' 'n' *(set @t) (sub now ~d2)]
  =/  young=client  ['young' 'n' *(set @t) (sub now ~h1)]
  =/  kept=client  ['kept' 'n' *(set @t) (sub now ~d2)]
  =/  approved  (silt ~['kept'])
  =/  got  (sweep-idle:wicket now ~[old young kept] approved)
  =/  only  (sweep-idle:wicket now ~[old] ~)
  ;:  weld
    (expect-eq !>(~['old']) !>(dead.got))
    (expect-eq !>((add created.young idle-ttl:wicket)) !>(`@da`(need next.got)))
    (expect-eq !>(~['old']) !>(dead.only))
    (expect-eq !>(`(unit @da)`~) !>(next.only))
  ==
::
++  test-parse-address
  =/  v4  [%ipv4 .127.0.0.1]
  =/  v6  [%ipv6 .2001.db8.0.0.0.0.0.1]
  =/  loop  [%ipv6 .0.0.0.0.0.0.0.1]
  ;:  weld
    (expect-eq !>(`v4) !>((parse-address:wicket '127.0.0.1')))
    (expect-eq !>(`v6) !>((parse-address:wicket '2001:db8::1')))
    (expect-eq !>(`v6) !>((parse-address:wicket '[2001:DB8::1]')))
    (expect-eq !>(`loop) !>((parse-address:wicket '::1')))
    (expect-eq !>(`loop) !>((parse-address:wicket '0:0:0:0:0:0:0:1')))
    (expect !>(?=(~ (parse-address:wicket 'example.com'))))
    (expect !>(?=(~ (parse-address:wicket ''))))
    (expect !>(?=(~ (parse-address:wicket '999.0.0.1'))))
    (expect-eq !>(`v4) !>((parse-address:wicket (crip (render-address:wicket v4)))))
    (expect-eq !>(`v6) !>((parse-address:wicket (crip (render-address:wicket v6)))))
    (expect-eq !>("127.0.0.1") !>((render-address:wicket v4)))
    (expect-eq !>("2001:db8::1") !>((render-address:wicket v6)))
    (expect-eq !>("::1") !>((render-address:wicket loop)))
  ==
::
++  test-resource-scopes
  =/  pier=registered-resource
    :*  'http://127.0.0.1:8080/pier-mcp'
        %pier-mcp
        (silt ~['pier-mcp.read' 'pier-mcp.owner'])
        'http://127.0.0.1:8080/pier-aud'
    ==
  =/  keeper=registered-resource
    :*  'http://127.0.0.1:8080/wicket/mcp'
        %keeper
        (silt ~['wicket.clients.read'])
        'http://127.0.0.1:8080/wicket/mcp'
    ==
  =/  bare=registered-resource
    :*  'http://127.0.0.1:8080/empty'
        %bare
        *(set scope)
        'http://127.0.0.1:8080/empty'
    ==
  =/  odd=registered-resource
    :*  'http://127.0.0.1:8080/odd'
        %odd
        *(set scope)
        'http://127.0.0.1:8080/odd'
    ==
  =/  notes=(map scope scope-note)
    %-  malt
    :~  ['pier-mcp.read' ['Read this ship.' |]]
        ['pier-mcp.owner' ['Full control of this ship.' &]]
        ['pier-mcp.extra' ['Not a grant.' |]]
    ==
  =/  copies=(map resource scope-copy)
    %-  malt
    :~  :-  'http://127.0.0.1:8080/pier-mcp'
        ['Pier MCP' notes]
        :-  'http://127.0.0.1:8080/odd'
        ['Odd' (malt ~[['odd.extra' ['Left behind.' &]]])]
    ==
  =/  part  (resource-section:wicket-html ~[pier keeper bare odd] copies)
  =/  xml
    %-  en-xml:html
    ;div
      ;*  part
    ==
  =/  bare-xml
    (cut-between "http://127.0.0.1:8080/empty" "http://127.0.0.1:8080/odd" xml)
  =/  odd-xml
    (cut-between "http://127.0.0.1:8080/odd" "http://127.0.0.1:8080/pier-mcp" xml)
  =/  pier-xml
    (cut-between "http://127.0.0.1:8080/pier-mcp" "http://127.0.0.1:8080/wicket/mcp" xml)
  =/  pier-sum
    (cut-between "<span class=\"name\">Pier MCP</span>" "http://127.0.0.1:8080/pier-mcp" xml)
  =/  own  (need (find "pier-mcp.owner" pier-xml))
  =/  flag  (need (find "Controls the ship" pier-xml))
  =/  rd  (need (find "pier-mcp.read" pier-xml))
  =/  mark  (need (find "Not registered" pier-xml))
  =/  extra  (need (find "pier-mcp.extra" pier-xml))
  ;:  weld
    (expect !>(?=(^ (find "Resource servers" xml))))
    (expect !>(?=(^ (find "<span class=\"name\">Pier MCP</span>" xml))))
    (expect !>(?=(^ (find "<span class=\"name\">Odd</span>" xml))))
    (expect !>(?=(^ (find "<span class=\"name\">Keeper</span>" xml))))
    (expect !>(?=(^ (find "<span class=\"name\">bare</span>" xml))))
    (expect !>(?=(^ (find "class=\"url\"" pier-sum))))
    (expect !>(?=(~ (find "pier-mcp.owner" pier-sum))))
    (expect !>(?=(~ (find "Full control" pier-sum))))
    (expect !>(?=(^ (find "<details class=\"resource\">" xml))))
    (expect !>(?=(~ (find "open=\"open\"" xml))))
    (expect !>(?=(^ (find "Audience http://127.0.0.1:8080/pier-aud" pier-xml))))
    (expect !>(?=(~ (find "Audience http://127.0.0.1:8080/wicket/mcp" xml))))
    (expect !>(?=(~ (find "Audience http://127.0.0.1:8080/empty" xml))))
    (expect !>(?=(~ (find "Audience http://127.0.0.1:8080/odd" xml))))
    (expect !>(?=(^ (find "Full control of this ship." pier-xml))))
    (expect !>(?=(^ (find "Read this ship." pier-xml))))
    (expect !>(?=(^ (find "List OAuth clients" xml))))
    (expect !>(?=(^ (find "wicket.clients.read" xml))))
    (expect !>(?=(^ (find "Not a grant." pier-xml))))
    (expect !>(?=(^ (find "Left behind." odd-xml))))
    (expect !>(?=(^ (find "No scopes." bare-xml))))
    (expect !>(?=(~ (find "No scopes." odd-xml))))
    (expect !>(?=(~ (find "No scopes." pier-xml))))
    (expect !>(?=(^ (find "class=\"reg warn\"" pier-xml))))
    (expect !>(?=(^ (find "class=\"reg warn\"" odd-xml))))
    (expect !>(?=(^ (find ">Agent pier-mcp<" xml))))
    (expect !>(?=(^ (find ">Agent keeper<" xml))))
    (expect !>(?=(^ (find ">Agent bare<" xml))))
    (expect !>(?=(~ (find " · " xml))))
    %+  expect-eq
      !>(4)
      !>((times "<details class=\"resource\">" xml))
    %+  expect-eq
      !>(1)
      !>((times ">Keeper<" xml))
    (expect !>((lth own flag)))
    (expect !>((lth flag rd)))
    (expect !>((lth rd mark)))
    (expect !>((lth mark extra)))
    (expect !>((lth (need (find "Not registered" odd-xml)) (need (find "odd.extra" odd-xml)))))
    %+  expect-eq
      !>(1)
      !>((times "Controls the ship" pier-xml))
    %+  expect-eq
      !>(1)
      !>((times "Controls the ship" odd-xml))
    %+  expect-eq
      !>(1)
      !>((times "No scopes." xml))
    %+  expect-eq
      !>(1)
      !>((times "http://127.0.0.1:8080/wicket/mcp" xml))
  ==
::
++  times
  |=  [nedl=tape hay=tape]
  ^-  @ud
  =/  at  (find nedl hay)
  ?~  at  0
  +($(hay (slag (add u.at (lent nedl)) hay)))
::
++  cut-between
  |=  [a=tape b=tape xml=tape]
  ^-  tape
  =/  i  (find a xml)
  ?~  i  ""
  =/  rest  (slag (add u.i (lent a)) xml)
  =/  j  (find b rest)
  ?~  j  ""
  (scag u.j rest)
::
++  test-revoke-client-page
  =/  who=client
    ['client-one' 'Grok' *(set @t) ~2026.9.21..15.30.00]
  =/  xml  (en-xml:html (revoke-client-page:wicket-html who 2 3))
  ;:  weld
    (expect !>(?=(^ (find "Revoke Grok?" xml))))
    (expect !>(?=(^ (find "client-one" xml))))
    (expect !>(?=(^ (find "2 grants and 3 tokens" xml))))
    (expect !>(?=(^ (find "revoke-client" xml))))
    (expect !>(?=(^ (find "/wicket/manage?open=client-one" xml))))
  ==
::
++  test-log-filter
  =/  none=(unit log-kind:wicket-html)  ~
  =/  tokens=(unit log-kind:wicket-html)  `%tokens
  ;:  weld
    %+  expect-eq
      !>(none)
      !>((log-filter:wicket-html ~))
    %+  expect-eq
      !>(tokens)
      !>((log-filter:wicket-html `'tokens'))
    %+  expect-eq
      !>(none)
      !>((log-filter:wicket-html `'nope'))
  ==
::
++  log-xml
  |=  [events=(list log-event:wicket) kind=(unit log-kind:wicket-html)]
  ^-  tape
  (en-xml:html (log-page:wicket-html ~zod events kind))
::
++  test-log-page
  =/  keeper  `'http://127.0.0.1:8080/wicket/mcp'
  =/  other  `'https://example.com/mcp'
  =/  cursor=client
    ['cursor-id' 'Cursor' (silt ~['https://example.com/cb']) ~2026.9.21..12.00.00]
  =/  reg=log-body:wicket
    [%registered [%ipv4 .203.0.113.4] cursor ~['authorization_code' 'refresh_token'] 'none']
  =/  reg-ev=log-event:wicket  [~2026.9.21..15.30.00 reg]
  =/  deny=log-body:wicket
    :*  %authorized
        %deny
        'deny-id'
        'DenyApp'
        ~
        'https://example.com/deny-cb'
        'deny-oauth-state'
        'deny-challenge'
        ~['only-deny-scope']
        *(list scope)
        *(unit (list scope))
        0v1
        ~2026.9.21..15.41.00
        *(unit [id=@t expires=@da])
        %.n
        *(list token-edit:wicket)
    ==
  =/  approve=log-body:wicket
    :*  %authorized
        %approve
        'approve-id'
        'ApproveApp'
        keeper
        'https://example.com/approve-cb'
        'approve-oauth-state'
        'approve-challenge'
        ~['wicket.clients.read' 'wicket.clients.revoke']
        ~['wicket.clients.read']
        *(unit (list scope))
        0v2
        ~2026.9.21..15.51.00
        `['APPROVE-' ~2026.9.21..16.01.00]
        %.y
        *(list token-edit:wicket)
    ==
  =/  dropped=logged-token:wicket
    :*  %access
        'DROPPED-'
        'drop-id'
        keeper
        ~['drop-scope']
        ~2026.9.21..17.00.00
    ==
  =/  drop-edit=token-edit:wicket  [dropped ~]
  =/  drop=log-body:wicket
    :*  %revoked-scopes
        %poke
        'drop-id'
        'DropApp'
        keeper
        ~['drop-scope']
        ~['drop-scope']
        *(list scope)
        ~[drop-edit]
    ==
  =/  rev-cli=client
    ['revoke-id' 'RevokeApp' (silt ~['https://example.com/rv']) ~2026.9.21..11.00.00]
  =/  grant=authorization
    ['revoke-id' keeper ~['client-grant-scope'] ~2026.9.21..15.00.00]
  =/  ctok=logged-token:wicket
    :*  %access
        'CLIENT-T'
        'revoke-id'
        keeper
        ~['client-grant-scope']
        ~2026.9.21..18.00.00
    ==
  =/  pend=authz
    :*  0v3
        'revoke-id'
        'https://example.com/rv'
        'pending-oauth-state'
        'pend-challenge'
        keeper
        ~['client-grant-scope']
        ~2026.9.21..15.10.00
    ==
  =/  cod=code
    :*  'REVOKED-'
        'revoke-id'
        'https://example.com/rv'
        'code-challenge'
        keeper
        ~['client-grant-scope']
        ~2026.9.21..15.20.00
        |
    ==
  =/  revoked=log-body:wicket
    [%revoked-client %page rev-cli & ~[grant] ~[ctok] ~[pend] ~[cod]]
  =/  idle=client
    ['idle-id' 'IdleApp' *(set @t) ~2026.9.21..10.00.00]
  =/  sweep=log-body:wicket
    :*  %revoked-client
        %sweep
        idle
        |
        *(list authorization)
        *(list logged-token:wicket)
        *(list authz)
        *(list code)
    ==
  =/  acc=logged-token:wicket
    :*  %access
        'ISSUED-A'
        'issue-id'
        other
        ~['recipe.read']
        ~2026.9.21..16.04.00
    ==
  =/  ref=logged-token:wicket
    :*  %refresh
        'ISSUED-R'
        'issue-id'
        other
        ~['recipe.read']
        ~2026.10.21..14.04.00
    ==
  =/  how=redeemed:wicket
    [%refresh 'OLD-REFR' ~2026.9.20..14.04.00]
  =/  issued=log-body:wicket
    :*  %issued
        'issue-id'
        'IssueApp'
        other
        ~['recipe.read']
        acc
        ref
        how
    ==
  =/  rtok=logged-token:wicket
    :*  %refresh
        'REVOKED-'
        'rtok-id'
        other
        ~['recipe.read']
        ~2026.9.22..09.15.00
    ==
  =/  rbody=log-body:wicket
    [%revoked-token %endpoint 'RevokeTok' rtok]
  =/  events=(list log-event:wicket)
    :~  [~2026.9.22..09.16.00 rbody]
        [~2026.9.21..16.20.00 issued]
        [~2026.9.21..16.10.00 sweep]
        [~2026.9.21..16.00.00 revoked]
        [~2026.9.21..15.55.00 drop]
        [~2026.9.21..15.50.00 approve]
        [~2026.9.21..15.40.00 deny]
        reg-ev
    ==
  =/  xml  (log-xml events ~)
  =/  tokens-xml  (log-xml events `%tokens)
  =/  issued-xml  (log-xml ~[[~2026.9.21..16.20.00 issued]] ~)
  =/  deny-xml  (log-xml ~[[~2026.9.21..15.40.00 deny]] ~)
  =/  drop-xml  (log-xml ~[[~2026.9.21..15.55.00 drop]] ~)
  =/  empty  (log-xml ~ ~)
  =/  none-xml  (log-xml ~[reg-ev] `%tokens)
  =/  first  (cut-between "First approval" "Pending id" xml)
  ;:  weld
    (expect !>(?=(^ (find "Log on ~zod" xml))))
    (expect !>(?=(^ (find "class=\"event\"" xml))))
    (expect !>(?=(~ (find "open=\"open\"" xml))))
    (expect !>(?=(~ (find "<script" xml))))
    (expect !>(?=(~ (find "No events yet." xml))))
    %+  expect-eq
      !>(8)
      !>((times "<details class=\"event\">" xml))
    (expect !>(?=(^ (find "Registered · Cursor" xml))))
    (expect !>(?=(^ (find "203.0.113.4" xml))))
    (expect !>(?=(^ (find "https://example.com/cb" xml))))
    (expect !>(?=(^ (find "authorization_code" xml))))
    (expect !>(?=(^ (find "refresh_token" xml))))
    (expect !>(?=(^ (find "2026-09-21 12:00" xml))))
    (expect !>(?=(^ (find "Denied · DenyApp · this ship" xml))))
    (expect !>(?=(^ (find "only-deny-scope" xml))))
    (expect !>(?=(^ (find "0v1" xml))))
    (expect !>(?=(^ (find "Approved · ApproveApp · Keeper · wicket.clients.read" xml))))
    (expect !>(?=(^ (find "APPROVE-" xml))))
    (expect !>(?=(^ (find "approve-oauth-state" xml))))
    (expect !>(?=(^ (find "approve-challenge" xml))))
    (expect !>(?=(^ (find "0v2" xml))))
    (expect !>(?=(^ (find "Yes" first))))
    (expect !>(?=(^ (find "Removed scope · DropApp · drop-scope" xml))))
    (expect !>(?=(^ (find "DROPPED-" xml))))
    (expect !>(?=(^ (find "Local action" xml))))
    (expect !>(?=(^ (find "Revoked client · RevokeApp" xml))))
    (expect !>(?=(^ (find "CLIENT-T" xml))))
    (expect !>(?=(^ (find "pending-oauth-state" xml))))
    (expect !>(?=(^ (find "REVOKED-" xml))))
    (expect !>(?=(^ (find "client-grant-scope" xml))))
    (expect !>(?=(^ (find "Owner page" xml))))
    (expect !>(?=(^ (find "Removed client · IdleApp · not approved" xml))))
    (expect !>(?=(^ (find "Not approved within 24 hours" xml))))
    (expect !>(?=(^ (find "Issued tokens · IssueApp · access expires 2026-09-21 16:04" xml))))
    (expect !>(?=(^ (find "ISSUED-A" xml))))
    (expect !>(?=(^ (find "ISSUED-R" xml))))
    (expect !>(?=(^ (find "2026-10-21 14:04" xml))))
    (expect !>(?=(^ (find "Replaced refresh token" xml))))
    (expect !>(?=(^ (find "OLD-REFR" xml))))
    (expect !>(?=(~ (find "ISSUED-ACCESS-ID" xml))))
    (expect !>(?=(~ (find "ISSUED-REFRESH-ID" xml))))
    (expect !>(?=(~ (find "OLD-REFRESH-ID" xml))))
    (expect !>(?=(~ (find "APPROVE-CODE-ID" xml))))
    (expect !>(?=(~ (find "DROPPED-TOKEN-ID" xml))))
    (expect !>(?=(~ (find "CLIENT-TOKEN-ID" xml))))
    (expect !>(?=(~ (find "REVOKED-CLIENT-CODE" xml))))
    (expect !>(?=(~ (find "REVOKED-REFRESH-ID" xml))))
    (expect !>(?=(^ (find "https://example.com/mcp" xml))))
    (expect !>(?=(^ (find "Revoked refresh token · RevokeTok · expires 2026-09-22 09:15" xml))))
    (expect !>(?=(^ (find "REVOKED-" xml))))
    (expect !>(?=(^ (find "Revocation endpoint" xml))))
    (expect !>(?=(~ (find "Revoked access token" xml))))
    (expect !>(?=(^ (find "<strong>All</strong>" xml))))
    (expect !>(?=(^ (find "href=\"/wicket/manage/log?kind=tokens\"" xml))))
    (expect !>(?=(^ (find "href=\"/wicket/manage\">Clients" xml))))
    (expect !>(?=(^ (find "ISSUED-A" issued-xml))))
    (expect !>(?=(^ (find "ISSUED-R" issued-xml))))
    (expect !>(?=(^ (find "2026-09-21 16:04" issued-xml))))
    (expect !>(?=(^ (find "2026-10-21 14:04" issued-xml))))
    (expect !>(?=(^ (find "Replaced refresh token" issued-xml))))
    (expect !>(?=(^ (find "OLD-REFR" issued-xml))))
    (expect !>(?=(~ (find "Revoked refresh token" issued-xml))))
    (expect !>(?=(^ (find "only-deny-scope" deny-xml))))
    (expect !>(?=(^ (find "this ship" deny-xml))))
    (expect !>(?=(~ (find "Code expires" deny-xml))))
    (expect !>(?=(~ (find "APPROVE-" deny-xml))))
    (expect !>(?=(~ (find "Scopes granted" deny-xml))))
    (expect !>(?=(^ (find "DROPPED-" drop-xml))))
    (expect !>(?=(^ (find ">Removed<" drop-xml))))
    (expect !>(?=(~ (find "Revoked access token" drop-xml))))
    (expect !>(?=(~ (find "Revoked refresh token" drop-xml))))
    (expect !>(?=(^ (find "ISSUED-A" tokens-xml))))
    (expect !>(?=(^ (find "REVOKED-" tokens-xml))))
    (expect !>(?=(^ (find "Revoked refresh token" tokens-xml))))
    (expect !>(?=(~ (find "cursor-id" tokens-xml))))
    (expect !>(?=(~ (find "https://example.com/cb" tokens-xml))))
    (expect !>(?=(~ (find "Registered ·" tokens-xml))))
    (expect !>(?=(^ (find "<strong>Tokens</strong>" tokens-xml))))
    (expect !>(?=(~ (find "<strong>All</strong>" tokens-xml))))
    (expect !>(?=(^ (find "No events yet." empty))))
    (expect !>(?=(~ (find "class=\"event\"" empty))))
    (expect !>(?=(~ (find "<script" empty))))
    (expect !>(?=(^ (find "No events of this kind." none-xml))))
    (expect !>(?=(~ (find "cursor-id" none-xml))))
    (expect !>(?=(~ (find "No events yet." none-xml))))
  ==
::
++  test-tile-image
  =/  pay  tile-image:wicket-http
  =/  lin  (parse-request-line:server '/wicket/tile.jpg')
  =/  bare  (parse-request-line:server '/wicket/tile')
  ?>  ?=(^ data.pay)
  ;:  weld
    %+  expect-eq
      !>(0xff.d8ff)
      !>((end [3 3] tile-jpg:wicket-tile))
    %+  expect-eq
      !>(0xd9ff)
      !>((end [3 2] (rsh [3 (sub (met 3 tile-jpg:wicket-tile) 2)] tile-jpg:wicket-tile)))
    %+  expect-eq
      !>(117.534)
      !>((met 3 tile-jpg:wicket-tile))
    %+  expect-eq
      !>(117.534)
      !>(p.u.data.pay)
    %+  expect-eq
      !>(200)
      !>(status-code.response-header.pay)
    %+  expect-eq
      !>(`@ta`%jpg)
      !>((need ext.lin))
    %+  expect-eq
      !>(~['wicket' 'tile'])
      !>(site.lin)
    %+  expect-eq
      !>(*(unit @ta))
      !>(ext.bare)
    %+  expect-eq
      !>  :~  ['content-type' 'image/jpeg']
              ['cache-control' 'public, max-age=86400']
          ==
      !>(headers.response-header.pay)
  ==
--
