-- Run with Lua 5.4. Tests the real plugin, replacing only its MUC/HTTP boundary.
local plugin = assert(arg[1], 'plugin path required')
local hooks, requests, sent, replies, options, gate, rooms
local NS = 'urn:cloudmeet:host-control:1'
local function stanza(name, attrs)
    local node = {name=name, attr=attrs or {}, children={}}
    function node:tag(n,a) local c=stanza(n,a); c.parent=self; self.children[#self.children+1]=c; return c end
    function node:up() return self.parent or self end
    function node:get_child(n,ns)
        for _,c in ipairs(self.children) do if c.name==n and c.attr.xmlns==ns then return c end end
    end
    return node
end
package.preload['util.stanza'] = function() return {
    message=function(a) return stanza('message',a) end,
    reply=function(iq) return stanza('iq',{type='result',to=iq.attr.from,from=iq.attr.to}) end,
    error_reply=function(iq,_,condition) local s=stanza('iq',{type='error'}); s.condition=condition; return s end,
} end
package.preload['util.json'] = function() return {encode=function(t) return t end,decode=function(t) return t end} end
package.preload['util.uuid'] = function() return {generate=function() return 'unique-room-instance' end} end
package.preload['net.http'] = function() return {request=function(url, request, callback)
    requests[#requests+1]={url=url,request=request,callback=callback}
end} end
local function setup(enabled)
    hooks,requests,sent,replies,gate,rooms={},{},{},{},{},{}
    options={host_transfer_enabled=enabled,host_role_check_secret=string.rep('x',32),
        host_role_check_url='https://control/check',host_transfer_participant_domain='meet.jitsi'}
    for _,n in ipairs({'url','complete_url','status_url','rebind_url','claim_url'}) do
        options['host_transfer_'..n]='https://control/'..n
    end
    local api={could=function(_,_,jid) return jid:match('^focus@') ~= nil end}
    _G.module={host='muc.meet.jitsi',get_option_boolean=function(_,k,d) if options[k]==nil then return d end return options[k] end,
        get_option_string=function(_,k) return options[k] end,shared=function() return gate end,
        depends=function() return {module=api,get_room_from_jid=function(j) return rooms[j] end} end,
        hook=function(_,n,f) hooks[n]=f end,send=function(_,s) sent[#sent+1]=s end}
    assert(loadfile(plugin))()
    local room={jid='123456789@muc.meet.jitsi',affiliations={['source@meet.jitsi']='owner',['focus@auth.meet.jitsi']='owner'},members={}}
    rooms[room.jid]=room
    function room:each_affiliation(a)
        local list={}; for j,v in pairs(self.affiliations) do if v==a then list[#list+1]=j end end
        local i=0; return function() i=i+1;return list[i] end
    end
    function room:get_affiliation(j) return self.affiliations[j] end
    function room:get_occupant_by_real_jid(j) return self.members[j] end
    function room:get_occupant_by_nick(n) for _,m in pairs(self.members) do if m.nick==n then return m end end end
    function room:set_affiliation(_,bare,a)
        assert(not bare:match('^focus@'),'system owner must never be revoked')
        self.affiliations[bare]=a
        for _,m in pairs(self.members) do if m.bare_jid==bare then m.role=a=='owner' and 'moderator' or 'participant' end end
        return true
    end
    local origins={}
    for _,id in ipairs({'source','target','other'}) do
        local from=id..'@meet.jitsi/resource'
        local origin={full_jid=from,jitsi_meet_context_user={id='host-v1-'..string.rep('a',43)},send=function(s) replies[#replies+1]=s end}
        local member={bare_jid=id..'@meet.jitsi',nick=room.jid..'/'..id,role=id=='source' and 'moderator' or 'participant'}
        room.members[from]=member; origins[id]=origin
        if enabled then hooks['muc-occupant-joined']({room=room,occupant=member,origin=origin,stanza={attr={from=from}}}) end
    end
    local function command(actor,name,attrs)
        local iq=stanza('iq',{from=origins[actor].full_jid,to=room.jid,type='set'})
        attrs=attrs or {};attrs.xmlns=NS;iq:tag(name,attrs)
        return hooks['iq-set/bare/'..NS..':'..name]({origin=origins[actor],stanza=iq})
    end
    return room,origins,command
end
local total=0
local function test(name,f) f(); total=total+1; print('PASS '..name) end
test('disabled feature installs no protocol handlers',function() setup(false);assert(next(hooks)==nil) end)
test('participant cannot initiate rotation',function()
    local r,o,c=setup(true); c('other','transfer',{operationId='op1',target=r.jid..'/target'})
    assert(#requests==0 and replies[1].condition=='not-allowed')
end)
test('authenticated origin cannot spoof source JID',function()
    local r,o,c=setup(true); o.source.full_jid='forged@meet.jitsi/r'
    c('source','transfer',{operationId='op1',target=r.jid..'/target'});assert(#requests==0)
end)
test('other business owner blocks transfer but automatic focus owner does not',function()
    local r,o,c=setup(true);r.affiliations['other@meet.jitsi']='owner'
    c('source','transfer',{operationId='op1',target=r.jid..'/target'});assert(#requests==0 and replies[1].condition=='conflict')
end)
test('rotation revokes source before target grant; ack opens fence and system owner survives',function()
    local r,o,c=setup(true);c('source','transfer',{operationId='op1',target=r.jid..'/target'})
    assert(#requests==1 and requests[1].request.body.targetSession==o.target.full_jid)
    assert(requests[1].request.headers['X-Role-Check-Secret']==options.host_role_check_secret)
    requests[1].callback({hostKey='rotated-secret',identity='host-v1-'..string.rep('b',43)},200)
    assert(r.affiliations['source@meet.jitsi']=='none' and r.affiliations['target@meet.jitsi']=='owner')
    assert(r.affiliations['focus@auth.meet.jitsi']=='owner' and gate[r].busy and gate[r].awaiting_ack)
    assert(sent[1].attr.to==o.target.full_jid and sent[1]:get_child('credential',NS).attr.hostKey=='rotated-secret')
    assert(not replies[1]:get_child('credential',NS))
    c('other','ack',{operationId='op1'});assert(#requests==1)
    c('target','ack',{operationId='op1'});assert(#requests==2)
    requests[2].callback('',204);assert(not gate[r].busy and not gate[r].operation)
end)
test('ambiguous API failure retains authority fence and never grants recipient',function()
    local r,o,c=setup(true);c('source','transfer',{operationId='op1',target=r.jid..'/target'})
    requests[1].callback('',0);assert(gate[r].busy and #sent==0 and r.affiliations['target@meet.jitsi']==nil)
    local event={room=r};hooks['muc-pre-set-affiliation'](event);assert(event.allowed==false)
end)
test('departed target after rotate cannot receive a credential or gain owner',function()
    local r,o,c=setup(true);c('source','transfer',{operationId='op1',target=r.jid..'/target'})
    r.members[o.target.full_jid]=nil
    requests[1].callback({hostKey='rotated-secret',identity='host-v1-'..string.rep('b',43)},200)
    assert(gate[r].blocked and #sent==0 and r.affiliations['target@meet.jitsi']==nil)
end)
test('duplicate transfer while rotate is inflight makes no second API request',function()
    local r,o,c=setup(true);for _=1,2 do c('source','transfer',{operationId='op1',target=r.jid..'/target'}) end
    assert(#requests==1 and replies[1].condition=='conflict')
end)
print(total..' executable Lua protocol tests passed')
