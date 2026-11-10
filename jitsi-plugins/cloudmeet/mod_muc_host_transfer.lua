-- Opt-in production transport. Do not enable until API write fencing and client
-- receipt acknowledgement/reconnect recovery have been deployed together.
if not module:get_option_boolean("host_transfer_enabled", false) then return; end
local url = assert(module:get_option_string("host_transfer_url"));
local complete_url = assert(module:get_option_string("host_transfer_complete_url"));
local status_url = assert(module:get_option_string("host_transfer_status_url"));
local rebind_url = assert(module:get_option_string("host_transfer_rebind_url"));
local claim_url = assert(module:get_option_string("host_transfer_claim_url"));
local secret = assert(module:get_option_string("host_role_check_secret"));
local domain = assert(module:get_option_string("host_transfer_participant_domain"));
assert(url:match("^https://") and complete_url:match("^https://")
    and status_url:match("^https://") and rebind_url:match("^https://")
    and claim_url:match("^https://") and #secret >= 32,
    "HTTPS transfer endpoints and service secret required");
assert(module:get_option_string("host_role_check_url"), "online JWT revocation gate required");
local st = require "util.stanza";
local json = require "util.json";
local http = require "net.http";
local uuid = require "util.uuid";
local muc = module:depends("muc");
local gate = module:shared("/" .. module.host .. "/muc_host_transfer/gate");
local sessions = setmetatable({}, {__mode="k"});
local recovery_challenges = setmetatable({}, {__mode="k"});
local status_requests = setmetatable({}, {__mode="k"});
local claim_requests = setmetatable({}, {__mode="k"});
local namespace = "urn:cloudmeet:host-control:1";

-- Fence other role writers (including delayed JWT grants) while an operation is
-- pending or uncertain. Only synchronous changes made below bypass this fence.
module:hook("muc-pre-set-affiliation", function(event)
    local state = gate[event.room];
    if state and (state.busy or state.blocked) and not state.changing then
        event.allowed=false; event.error={type="cancel",condition="conflict"};
    end
end, -200);
module:hook("muc-pre-set-role", function(event)
    local state = gate[event.room];
    if state and (state.busy or state.blocked) and not state.changing then
        event.allowed=false; event.error="cancel"; event.condition="conflict";
    end
end, -200);

module:hook("muc-occupant-joined", function(event)
    local from = event.stanza and event.stanza.attr.from;
    if not from or not event.origin or event.origin.full_jid ~= from then return; end
    local by_room = sessions[event.room] or {}; sessions[event.room] = by_room;
    by_room[from] = {origin=event.origin, nick=event.occupant.nick, bare=event.occupant.bare_jid};
end);
module:hook("muc-occupant-left", function(event)
    local by_room = sessions[event.room];
    if by_room then
        for from, binding in pairs(by_room) do
            if binding.nick == event.occupant.nick then by_room[from] = nil; end
        end
    end
    local challenges = recovery_challenges[event.room];
    if challenges then
        for from, challenge in pairs(challenges) do
            if challenge.nick == event.occupant.nick then challenges[from] = nil; end
        end
    end
    local requests = status_requests[event.room];
    if requests then
        for from, request in pairs(requests) do
            if request.nick == event.occupant.nick then requests[from] = nil; end
        end
    end
    local claims = claim_requests[event.room];
    if claims then
        for from, claim in pairs(claims) do
            if claim.nick == event.occupant.nick then claims[from] = nil; end
        end
    end
end);
module:hook("muc-room-destroyed", function(event)
    sessions[event.room] = nil;
    recovery_challenges[event.room] = nil;
    status_requests[event.room] = nil;
    claim_requests[event.room] = nil;
    gate[event.room] = nil;
end);

local function system_owner(jid)
    return muc.module:could(":automatic-ownership", jid);
end
-- Core automatic owners are infrastructure, not transferable host authority.
-- Consult the same permission provider as MUC core; never whitelist nicknames.
local function business_owners(room)
    local owners = {};
    for owner in room:each_affiliation("owner") do
        if not system_owner(owner) then owners[#owners+1] = owner; end
    end
    local index = 0;
    return function() index=index+1; return owners[index]; end;
end
local function sole_business_owner(room, bare)
    local count=0;
    for owner in business_owners(room) do
        if owner ~= bare then return false; end
        count=count+1;
    end
    return count==1 and not system_owner(bare);
end
local function binding(room, from)
    local saved = sessions[room] and sessions[room][from];
    local occupant = saved and room:get_occupant_by_real_jid(from);
    if not occupant or occupant.nick ~= saved.nick or occupant.bare_jid ~= saved.bare
        or occupant.bare_jid:match("@(.+)$") ~= domain
        or system_owner(from) or system_owner(occupant.bare_jid) then return; end
    local count=0;
    for candidate, other in pairs(sessions[room]) do
        if other.bare == saved.bare and room:get_occupant_by_real_jid(candidate) then count=count+1; end
    end
    if count ~= 1 then return; end
    return saved, occupant;
end
local function role(room, bare, nick, affiliation, expected)
    local occupant = room:get_occupant_by_nick(nick);
    return occupant and occupant.bare_jid == bare and occupant.role == expected
        and (room:get_affiliation(bare) or "none") == affiliation;
end
local function change(room, state, bare, nick, affiliation, expected)
    state.changing = true;
    local ok, result = pcall(room.set_affiliation, room, true, bare, affiliation, "host-transfer");
    state.changing = false;
    return ok and result == true and role(room, bare, nick, affiliation, expected);
end

local function transfer(event)
    local origin, iq = event.origin, event.stanza;
    local function deny(condition) origin.send(st.error_reply(iq, "cancel", condition or "not-allowed")); return true; end
    if not origin or origin.full_jid ~= iq.attr.from then return deny(); end
    local room = muc.get_room_from_jid(iq.attr.to);
    if not room or room.jid ~= iq.attr.to then return deny(); end
    local source, actor = binding(room, iq.attr.from);
    if not source or source.origin ~= origin then return deny(); end
    local command = iq:get_child("transfer", namespace);
    local op, nick = command and command.attr.operationId, command and command.attr.target;
    if type(op) ~= "string" or #op > 64 or not op:match("^[%w_-]+$")
        or type(nick) ~= "string" or nick:sub(1,#room.jid+1) ~= room.jid .. "/" then return deny(); end
    local state = gate[room];
    local pending = state and state.operation;
    if state and not pending and (state.busy or state.blocked or state.creator_reclaim) then return deny("conflict"); end
    if pending then
        if pending.op ~= op or pending.from ~= iq.attr.from or pending.nick ~= nick
            or pending.origin ~= origin or state.inflight or state.blocked or state.awaiting_ack then return deny("conflict"); end
    else
        if not role(room, actor.bare_jid, actor.nick, "owner", "moderator") then return deny(); end
        if not sole_business_owner(room, actor.bare_jid) then return deny("conflict"); end
        local target_from, target_binding;
        for from, saved in pairs(sessions[room] or {}) do
            if saved.nick == nick then
                if target_from then return deny("conflict"); end
                target_from, target_binding = from, saved;
            end
        end
        local target = target_from and select(2,binding(room,target_from));
        if not target or target.bare_jid == actor.bare_jid
            or not role(room,target.bare_jid,nick,"none","participant") then return deny(); end
        local user = state and state.holder == source and {id=state.identity} or origin.jitsi_meet_context_user;
        if not user or type(user.id) ~= "string" or #user.id ~= 51 then return deny(); end
        state = state or {instance=uuid.generate(),epoch=0}; gate[room]=state;
        state.epoch=state.epoch+1; state.busy=true;
        pending={op=op,from=iq.attr.from,origin=origin,nick=nick,target=target_from,
            target_origin=target_binding.origin,source_bare=actor.bare_jid,source_nick=actor.nick,
            target_bare=target.bare_jid,identity=user.id};
        state.operation=pending;
    end
    local room_name = room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
    if not room_name then state.blocked=true; return deny(); end
    state.inflight=true;
    local completed=false;
    http.request(url, {method="POST",body=json.encode({roomName=room_name,identity=pending.identity,
        operationId=pending.op,targetSession=pending.target,roomInstance=state.instance}),
        headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(body,code)
        if completed then return; end; completed=true; state.inflight=false;
        if gate[room] ~= state or muc.get_room_from_jid(room.jid) ~= room then return; end
        -- Ambiguous transport failures retain the lock and permit only same-op recovery.
        if code ~= 200 then deny("remote-server-timeout"); return; end
        local ok, result = pcall(json.decode,body);
        local current_source = binding(room,pending.from);
        local current_target = binding(room,pending.target);
        if not ok or type(result) ~= "table" or type(result.hostKey) ~= "string" or #result.hostKey == 0 or #result.hostKey > 128
            or type(result.identity) ~= "string" or #result.identity ~= 51
            or not current_source or current_source.origin ~= pending.origin
            or not current_target or current_target.origin ~= pending.target_origin then
            state.blocked=true; deny("conflict"); return;
        end
        if not change(room,state,pending.source_bare,pending.source_nick,"none","participant") then
            state.blocked=true; deny("conflict"); return;
        end
        -- Revoke first: even a transient second owner can act before the next
        -- affiliation write. A failed grant leaves the room locked with no
        -- owner until the durable receipt is recovered.
        if not change(room,state,pending.target_bare,pending.nick,"owner","moderator") then
            state.blocked=true; deny("conflict"); return;
        end
        if not sole_business_owner(room,pending.target_bare) then state.blocked=true; return deny("conflict"); end
        -- No room broadcast and no credential in the actor's IQ response.
        module:send(st.message({from=room.jid,to=pending.target,type="normal"})
            :tag("credential",{xmlns=namespace,operationId=pending.op,hostKey=result.hostKey,identity=result.identity}):up());
        state.holder=current_target; state.identity=result.identity;
        -- The API write fence remains closed until the target's authenticated
        -- session explicitly acknowledges receiving the credential.
        origin.send(st.reply(iq):tag("transfer",{xmlns=namespace,state="roles-committed",operationId=pending.op}):up());
        state.awaiting_ack=true;
    end);
    return true;
end
module:hook("iq-set/bare/" .. namespace .. ":transfer", transfer, 100);

local function acknowledge(event)
    local origin, iq = event.origin, event.stanza;
    local function deny(condition) origin.send(st.error_reply(iq, "cancel", condition or "not-allowed")); return true; end
    if not origin or origin.full_jid ~= iq.attr.from then return deny(); end
    local room = muc.get_room_from_jid(iq.attr.to);
    if not room or room.jid ~= iq.attr.to then return deny(); end
    local state = gate[room];
    local pending = state and state.operation;
    local command = iq:get_child("ack", namespace);
    if not pending or not state.awaiting_ack or state.inflight or state.blocked
        or not command or command.attr.operationId ~= pending.op
        or iq.attr.from ~= pending.target or origin ~= pending.target_origin then return deny("conflict"); end
    local saved, occupant = binding(room, iq.attr.from);
    if not saved or saved.origin ~= origin or occupant.bare_jid ~= pending.target_bare
        or not role(room, pending.target_bare, pending.nick, "owner", "moderator")
        or not sole_business_owner(room,pending.target_bare) then return deny(); end
    local room_name = room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
    if not room_name then state.blocked=true; return deny(); end
    state.inflight=true;
    local completed=false;
    http.request(complete_url, {method="POST", body=json.encode({roomName=room_name,
        operationId=pending.op,targetSession=pending.target,roomInstance=state.instance}),
        headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(_,code)
        if completed then return; end; completed=true; state.inflight=false;
        if gate[room] ~= state or muc.get_room_from_jid(room.jid) ~= room then return; end
        if state.operation ~= pending or not state.awaiting_ack then return; end
        if code ~= 204 then deny("remote-server-timeout"); return; end
        state.busy=false; state.awaiting_ack=nil; state.operation=nil; state.creator_reclaim=nil;
        origin.send(st.reply(iq):tag("ack",{xmlns=namespace,state="complete",operationId=pending.op}):up());
    end);
    return true;
end
module:hook("iq-set/bare/" .. namespace .. ":ack", acknowledge, 100);

-- The original private credential message can be lost. The exact current
-- target session may ask for another copy while the durable receipt is open.
-- A request never creates a transfer and never sends the key in an IQ result.
local function claim(event)
    local origin, iq = event.origin, event.stanza;
    local function deny(condition) origin.send(st.error_reply(iq, "cancel", condition or "not-allowed")); return true; end
    if not origin or origin.full_jid ~= iq.attr.from then return deny(); end
    local room = muc.get_room_from_jid(iq.attr.to);
    if not room or room.jid ~= iq.attr.to then return deny(); end
    local function sole_owner(bare)
        return sole_business_owner(room,bare);
    end
    local saved, occupant = binding(room, iq.attr.from);
    if not saved or saved.origin ~= origin
        or not role(room, occupant.bare_jid, occupant.nick, "owner", "moderator")
        or not sole_owner(occupant.bare_jid) then return deny(); end
    local state = gate[room];
    if state and (state.blocked or state.inflight or (state.operation
        and (state.operation.target ~= iq.attr.from or state.operation.target_origin ~= origin))) then
        return deny("conflict");
    end
    local room_name = room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
    if not room_name then return deny(); end
    local claims = claim_requests[room] or {}; claim_requests[room]=claims;
    local prior = claims[iq.attr.from];
    if prior and (prior.inflight or os.time()-prior.at < 5) then return deny("resource-constraint"); end
    local request={origin=origin,nick=occupant.nick,at=os.time(),inflight=true};
    claims[iq.attr.from]=request;
    local function current()
        local active, member = binding(room,iq.attr.from);
        return claim_requests[room] and claims[iq.attr.from] == request
            and muc.get_room_from_jid(room.jid) == room and gate[room] == state
            and active and active.origin == origin and member.nick == request.nick
            and role(room,member.bare_jid,member.nick,"owner","moderator")
            and sole_owner(member.bare_jid);
    end
    http.request(status_url, {method="POST",body=json.encode({roomName=room_name}),
        headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(body,code)
        if request.status_done then return; end; request.status_done=true;
        if not current() then return; end
        local ok, result = pcall(json.decode,body);
        if code ~= 200 or not ok or type(result) ~= "table" or result.state ~= "TRANSFERRING"
            or result.targetSession ~= iq.attr.from or type(result.operationId) ~= "string"
            or type(result.roomInstance) ~= "string" or type(result.expiresAt) ~= "number"
            or result.expiresAt <= os.time()
            or (state and (state.instance ~= result.roomInstance or not state.operation
                or state.operation.op ~= result.operationId)) then
            request.inflight=false; deny("conflict"); return;
        end
        http.request(claim_url, {method="POST",body=json.encode({roomName=room_name,
            operationId=result.operationId,targetSession=iq.attr.from,roomInstance=result.roomInstance}),
            headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(credential,claim_code)
            if request.claim_done then return; end; request.claim_done=true;
            if not current() then return; end
            request.inflight=false;
            local parsed, secret_result = pcall(json.decode,credential);
            if claim_code ~= 200 or not parsed or type(secret_result) ~= "table"
                or type(secret_result.hostKey) ~= "string" or #secret_result.hostKey == 0
                or #secret_result.hostKey > 128 or type(secret_result.identity) ~= "string"
                or #secret_result.identity ~= 51 then deny("remote-server-timeout"); return; end
            module:send(st.message({from=room.jid,to=iq.attr.from,type="normal"})
                :tag("credential",{xmlns=namespace,operationId=result.operationId,
                    hostKey=secret_result.hostKey,identity=secret_result.identity,
                    previousOperationId=type(secret_result.previousOperationId)=="string"
                        and secret_result.previousOperationId or nil}):up());
            origin.send(st.reply(iq):tag("claim",{xmlns=namespace,state="sent"}):up());
        end);
    end);
    return true;
end
module:hook("iq-set/bare/" .. namespace .. ":claim", claim, 100);

-- A restarted Prosody process has lost its local transfer operation. The API
-- receipt is durable, but a new XMPP session must prove it holds the rotated
-- key before the room owner can be reconstructed. A challenge never unlocks
-- the API fence or grants any role by itself.
local function recoverable(room, state, op, challenge)
    if not state then return true; end
    if state.inflight or (state.blocked and state.recovery ~= challenge) then return false; end
    local pending = state.operation;
    if pending then
        -- An absent target cannot acknowledge. Keep the old operation fenced
        -- until the API verifies the rotated-key proof and replaces its binding.
        return not state.blocked and state.awaiting_ack and pending.op == op
            and not binding(room, pending.target);
    end
    return not state.busy;
end

local function recover(event)
    local origin, iq = event.origin, event.stanza;
    local function deny(condition) origin.send(st.error_reply(iq, "cancel", condition or "not-allowed")); return true; end
    if not origin or origin.full_jid ~= iq.attr.from then return deny(); end
    local room = muc.get_room_from_jid(iq.attr.to);
    if not room or room.jid ~= iq.attr.to then return deny(); end
    local saved, occupant = binding(room, iq.attr.from);
    if not saved or saved.origin ~= origin or occupant.role ~= "participant" then return deny(); end
    local command = iq:get_child("recover", namespace);
    local op = command and command.attr.operationId;
    local room_name = room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
    if not room_name or type(op) ~= "string" or not op:match("^[%w_-]+$") or #op > 64 then return deny(); end
    local state = gate[room];
    if not recoverable(room,state,op) then return deny("conflict"); end
    local challenges = recovery_challenges[room] or {}; recovery_challenges[room] = challenges;
    local count = 0;
    for from, challenge in pairs(challenges) do
        if challenge.expires <= os.time() then challenges[from] = nil;
        elseif from ~= iq.attr.from then count = count + 1; end
    end
    if count >= 8 or (challenges[iq.attr.from] and challenges[iq.attr.from].inflight) then return deny("resource-constraint"); end
    local requests = status_requests[room] or {}; status_requests[room] = requests;
    local in_flight = 0;
    for _ in pairs(requests) do in_flight = in_flight + 1; end
    if requests[iq.attr.from] or in_flight >= 8 then return deny("resource-constraint"); end
    local request = {origin=origin,nick=occupant.nick}; requests[iq.attr.from]=request;
    local completed = false;
    http.request(status_url, {method="POST",body=json.encode({roomName=room_name}),
        headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(body,code)
        if completed then return; end; completed=true;
        if not status_requests[room] or status_requests[room][iq.attr.from] ~= request then return; end
        requests[iq.attr.from]=nil;
        local current = binding(room,iq.attr.from);
        if not current or current.origin ~= origin or gate[room] ~= state
            or muc.get_room_from_jid(room.jid) ~= room then return; end
        local ok, result = pcall(json.decode,body);
        if code ~= 200 or not ok or type(result) ~= "table" or result.state ~= "TRANSFERRING"
            or result.operationId ~= op or type(result.roomInstance) ~= "string"
            or not result.roomInstance:match("^[%w_-]+$") or #result.roomInstance > 128
            or type(result.expiresAt) ~= "number" or result.expiresAt <= os.time() then
            deny("conflict"); return;
        end
        local challenge = {origin=origin, nick=occupant.nick, op=op, room=room_name,
            target=iq.attr.from, expected=result.roomInstance, instance=uuid.generate(),
            nonce=uuid.generate(), expires=math.min(result.expiresAt,os.time()+45),
            state=state, pending=state and state.operation};
        challenges[iq.attr.from] = challenge;
        origin.send(st.reply(iq):tag("challenge",{xmlns=namespace,operationId=op,
            roomName=room_name,targetSession=challenge.target,
            expectedRoomInstance=challenge.expected,roomInstance=challenge.instance,
            nonce=challenge.nonce,expiresAt=tostring(challenge.expires)}):up());
    end);
    return true;
end
module:hook("iq-set/bare/" .. namespace .. ":recover", recover, 100);

local function rebind(event)
    local origin, iq = event.origin, event.stanza;
    local function deny(condition) origin.send(st.error_reply(iq, "cancel", condition or "not-allowed")); return true; end
    if not origin or origin.full_jid ~= iq.attr.from then return deny(); end
    local room = muc.get_room_from_jid(iq.attr.to);
    if not room or room.jid ~= iq.attr.to then return deny(); end
    local challenge = recovery_challenges[room] and recovery_challenges[room][iq.attr.from];
    local command = iq:get_child("rebind", namespace);
    if not challenge or challenge.origin ~= origin or challenge.expires <= os.time()
        or challenge.inflight or not command or command.attr.operationId ~= challenge.op
        or command.attr.nonce ~= challenge.nonce or type(command.attr.proof) ~= "string"
        or not command.attr.proof:match("^[%w_-]+$") or #command.attr.proof ~= 43 then return deny("conflict"); end
    local saved, occupant = binding(room, iq.attr.from);
    if not saved or saved.origin ~= origin or occupant.nick ~= challenge.nick
        or occupant.role ~= "participant" then return deny(); end
    local state = gate[room];
    if state ~= challenge.state or (state and state.operation ~= challenge.pending)
        or not recoverable(room,state,challenge.op,challenge) then return deny("conflict"); end
    challenge.inflight=true;
    local completed=false;
    http.request(rebind_url, {method="POST",body=json.encode({roomName=challenge.room,
        operationId=challenge.op,targetSession=challenge.target,roomInstance=challenge.instance,
        expectedRoomInstance=challenge.expected,nonce=challenge.nonce,proof=command.attr.proof}),
        headers={["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}}, function(body,code)
        if completed then return; end; completed=true; challenge.inflight=false;
        if not recovery_challenges[room] or recovery_challenges[room][iq.attr.from] ~= challenge
            or muc.get_room_from_jid(room.jid) ~= room then return; end
        local ok, result = pcall(json.decode,body);
        if code ~= 200 or not ok or type(result) ~= "table" or type(result.identity) ~= "string"
            or #result.identity ~= 51 then deny("remote-server-timeout"); return; end
        local current_saved, current = binding(room,iq.attr.from);
        if not current_saved or current_saved.origin ~= origin or current.nick ~= challenge.nick then return; end
        if gate[room] ~= challenge.state or (state and state.operation ~= challenge.pending)
            or not recoverable(room,state,challenge.op,challenge) then return; end
        state = state or {epoch=0}; gate[room]=state;
        state.operation=nil; state.awaiting_ack=nil;
        state.blocked=true; state.recovery=challenge; state.instance=challenge.instance;
        state.epoch=state.epoch+1;
        local owners = {};
        for owner in business_owners(room) do owners[#owners+1]=owner; end
        for _, owner in ipairs(owners) do
            state.changing=true;
            local changed_ok, changed = pcall(room.set_affiliation,room,true,owner,"none","host-transfer-recovery");
            state.changing=false;
            if not changed_ok or changed ~= true or room:get_affiliation(owner) == "owner" then
                deny("conflict"); return;
            end
        end
        if not change(room,state,current.bare_jid,current.nick,"owner","moderator") then
            deny("conflict"); return;
        end
        if not sole_business_owner(room,current.bare_jid) then deny("conflict"); return; end
        state.holder=current_saved; state.identity=result.identity;
        state.operation={op=challenge.op,target=challenge.target,target_origin=origin,
            target_bare=current.bare_jid,nick=current.nick};
        state.awaiting_ack=true; state.busy=true; state.blocked=false; state.recovery=nil;
        recovery_challenges[room][iq.attr.from]=nil;
        origin.send(st.reply(iq):tag("rebind",{xmlns=namespace,state="roles-committed",
            operationId=challenge.op}):up());
    end);
    return true;
end
module:hook("iq-set/bare/" .. namespace .. ":rebind", rebind, 100);

-- Creator capability is independent of host identity. No target supplied by the
-- client is used: only the authenticated origin may receive reclaimed authority.
if module:get_option_boolean("host_reclaim_enabled", false) then
    local reclaim_url = assert(module:get_option_string("host_reclaim_url"));
    assert(reclaim_url:match("^https://"), "HTTPS creator reclaim endpoint required");
    local limits=setmetatable({}, {__mode="k"});
    module:hook("iq-set/bare/" .. namespace .. ":reclaim", function(event)
        local origin,iq=event.origin,event.stanza;
        if not origin or not iq or origin.full_jid ~= iq.attr.from then return true; end
        local function deny(condition)
            origin.send(st.error_reply(iq,"cancel",condition or "conflict")); return true;
        end
        local room=muc.get_room_from_jid(iq.attr.to);
        if not room or room.jid ~= iq.attr.to then return deny(); end
        local saved,occupant=binding(room,iq.attr.from);
        if not saved or saved.origin ~= origin or (occupant.role ~= "participant" and occupant.role ~= "moderator") then return deny(); end
        local command=iq:get_child("reclaim",namespace);
        local op=command and command.attr.operationId;
        local proof=command and command.attr.creatorCredential;
        local function token(value,max)
            return type(value)=="string" and #value>0 and #value<=max and value:match("^[%w_-]+$");
        end
        local room_name=room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
        if not room_name or not token(op,64) or not token(proof,43) or #proof~=43 then return deny("bad-request"); end
        local old=gate[room];
        local attempt=old and old.creator_reclaim;
        local retry=attempt and attempt.op==op and attempt.origin==origin and attempt.target==iq.attr.from;
        if retry and old.inflight then return deny("resource-constraint"); end
        if attempt and attempt.inflight then return deny("resource-constraint"); end
        if not retry and limits[room] and os.time()-limits[room]<5 then return deny("resource-constraint"); end
        limits[room]=os.time();
        local state;
        if retry then state=old; state.blocked=true; state.busy=true;
        else
            state={epoch=(old and old.epoch or 0)+1,busy=true,blocked=true};
            attempt={op=op,origin=origin,target=iq.attr.from,instance=uuid.generate(),previous_state=old};
            state.creator_reclaim=attempt; gate[room]=state;
        end
        attempt.inflight=true;
        local function live()
            local active,member=binding(room,iq.attr.from);
            return gate[room]==state and state.creator_reclaim==attempt
                and muc.get_room_from_jid(room.jid)==room and active==saved
                and active.origin==origin and member.nick==occupant.nick;
        end
        local function fail(condition,restore)
            attempt.inflight=false;
            if gate[room]==state and restore and not attempt.uncertain then gate[room]=attempt.previous_state; end
            return deny(condition);
        end
        local function submit()
            local snapshot=attempt.snapshot;
            local done=false;
            http.request(reclaim_url,{method="POST",body=json.encode({roomName=room_name,creatorCredential=proof,
                expectedState=snapshot.state,expectedOperationId=snapshot.operationId,
                expectedRoomInstance=snapshot.roomInstance,expectedIdentity=snapshot.identity,
                operationId=op,targetSession=iq.attr.from,roomInstance=attempt.instance}),headers={
                    ["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}},function(body,code)
                if done then return; end; done=true;
                if not live() then attempt.inflight=false; return; end
                if code~=200 then
                    local rejected=code==403 or code==400 or code==409;
                    if not rejected then attempt.uncertain=true; end
                    return fail("remote-server-timeout",rejected);
                end
                attempt.uncertain=true; -- Commit may have happened; no later failure restores old authority.
                local ok,result=pcall(json.decode,body);
                if not ok or type(result)~="table" or result.operationId~=op
                    or not token(result.identity,51) or #result.identity~=51 then return fail(); end
                local claimed=false;
                http.request(claim_url,{method="POST",body=json.encode({roomName=room_name,operationId=op,
                    targetSession=iq.attr.from,roomInstance=attempt.instance}),headers={
                        ["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}},function(body,code)
                    if claimed then return; end; claimed=true;
                    if not live() then attempt.inflight=false; return; end
                    local ok,key=pcall(json.decode,body);
                    if code~=200 or not ok or type(key)~="table" or key.identity~=result.identity
                        or key.previousOperationId~=snapshot.operationId or type(key.hostKey)~="string"
                        or #key.hostKey==0 or #key.hostKey>128 then return fail(); end
                    local owners={};
                    for owner in business_owners(room) do owners[#owners+1]=owner; end
                    for _,owner in ipairs(owners) do
                        state.changing=true;
                        local ok,changed=pcall(room.set_affiliation,room,true,owner,"none","creator-reclaim");
                        state.changing=false;
                        if not ok or changed~=true or room:get_affiliation(owner)=="owner" then return fail(); end
                    end
                    if not change(room,state,occupant.bare_jid,occupant.nick,"owner","moderator") then return fail(); end
                    local count=0;
                    for owner in business_owners(room) do
                        if owner~=occupant.bare_jid then return fail(); end; count=count+1;
                    end
                    if count~=1 then return fail(); end
                    state.instance=attempt.instance; state.holder=saved; state.identity=key.identity;
                    state.operation={op=op,target=iq.attr.from,target_origin=origin,
                        target_bare=occupant.bare_jid,nick=occupant.nick};
                    state.awaiting_ack=true; state.blocked=false; attempt.inflight=false;
                    module:send(st.message({from=room.jid,to=iq.attr.from,type="normal"})
                        :tag("credential",{xmlns=namespace,operationId=op,hostKey=key.hostKey,
                            identity=key.identity,previousOperationId=key.previousOperationId}):up());
                    -- Retire only the superseded receipt on its original live
                    -- connection. Never broadcast keys or revoke a replacement.
                    local prior=attempt.previous_state and attempt.previous_state.operation;
                    if prior and prior.op==snapshot.operationId and prior.target~=iq.attr.from then
                        local previous=binding(room,prior.target);
                        if previous and previous.origin==prior.target_origin then
                            module:send(st.message({from=room.jid,to=prior.target,type="normal"})
                                :tag("revoked",{xmlns=namespace,operationId=prior.op}):up());
                        end
                    end
                    origin.send(st.reply(iq):tag("reclaim",{xmlns=namespace,operationId=op,state="roles-committed"}):up());
                end);
            end);
        end
        if retry and attempt.snapshot then submit(); return true; end
        local done=false;
        http.request(status_url,{method="POST",body=json.encode({roomName=room_name}),headers={
            ["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}},function(body,code)
            if done then return; end; done=true;
            if not live() then attempt.inflight=false; return; end
            local ok,snapshot=pcall(json.decode,body);
            if code~=200 or not ok or type(snapshot)~="table"
                or (snapshot.state~="ACTIVE" and snapshot.state~="TRANSFERRING")
                or not token(snapshot.identity,51) or #snapshot.identity~=51
                or (snapshot.operationId and (not token(snapshot.operationId,64) or not token(snapshot.roomInstance,128)))
                or (snapshot.state=="TRANSFERRING" and not snapshot.operationId)
                or snapshot.operationId==op then return fail("conflict",true); end
            attempt.snapshot=snapshot; submit();
        end);
        return true;
    end,100);
end

-- Trusted server-local event only. Never map this event to a participant IQ or
-- an unauthenticated HTTP route. An operator adapter must authenticate separately.
if module:get_option_boolean("host_transfer_admin_recovery_enabled", false) then
    local admin_url = assert(module:get_option_string("host_transfer_admin_recovery_url"));
    local admin_secret = assert(module:get_option_string("host_transfer_admin_recovery_secret"));
    local admin_resume_url = module:get_option_string("host_transfer_admin_recovery_resume_url");
    assert(not admin_resume_url or admin_resume_url:match("^https://"), "HTTPS admin resume endpoint required");
    assert(admin_url:match("^https://") and #admin_secret >= 32 and #admin_secret <= 256
        and admin_secret ~= secret, "independent HTTPS administrator recovery channel required");
    module:hook("cloudmeet-admin-host-recovery", function(event)
        local replied=false;
        local function reply(state)
            if not replied and type(event.reply) == "function" then
                replied=true; event.reply({state=state,operationId=event.operationId});
            end
            return true;
        end
        local room = type(event.room) == "string" and muc.get_room_from_jid(event.room);
        if not room or room.jid ~= event.room then return reply("rejected"); end
        local room_name = room.jid:match("^(%d%d%d%d%d%d%d%d%d)@");
        local function token(value,max)
            return type(value) == "string" and #value > 0 and #value <= max and value:match("^[%w_-]+$");
        end
        if not room_name or not token(event.operationId,64) or not token(event.expectedOperationId,64)
            or event.operationId == event.expectedOperationId or not token(event.expectedRoomInstance,128)
            or type(event.expectedIdentity) ~= "string" or not event.expectedIdentity:match("^host%-v1%-[%w_-]+$")
            or #event.expectedIdentity ~= 51 or type(event.operatorId) ~= "string" or #event.operatorId > 128
            or not event.operatorId:match("^[%w_.@-]+$") or type(event.reason) ~= "string"
            or #event.reason == 0 or #event.reason > 256 or not event.reason:match("^[%w_.:/ %-]+$")
            or type(event.targetSession) ~= "string" then return reply("rejected"); end
        local target=event.targetSession;
        local saved, occupant = binding(room,target);
        if not saved or not occupant or (occupant.role ~= "participant" and occupant.role ~= "moderator") then
            return reply("rejected");
        end
        local state=gate[room];
        if state and (state.inflight or (state.operation and state.operation.op ~= event.expectedOperationId
            and not (event.resume and state.operation.op == event.operationId))) then
            return reply("rejected");
        end
        if event.resume and (not admin_resume_url or not token(event.roomInstance,128)) then
            return reply("rejected");
        end
        state=state or {epoch=0}; gate[room]=state;
        state.epoch=state.epoch+1; state.busy=true; state.blocked=true; state.inflight=true;
        local attempt={}; state.admin_recovery=attempt;
        local instance=event.resume and event.roomInstance or uuid.generate();
        local op=event.operationId;
        local function current()
            local active, member=binding(room,target);
            return gate[room] == state and state.admin_recovery == attempt
                and muc.get_room_from_jid(room.jid) == room and active == saved
                and active.origin == saved.origin and member.nick == occupant.nick;
        end
        local completed=false;
        http.request(event.resume and admin_resume_url or admin_url,{method="POST",body=json.encode({roomName=room_name,
            expectedOperationId=event.expectedOperationId,expectedRoomInstance=event.expectedRoomInstance,
            previousOperationId=event.expectedOperationId,
            expectedIdentity=event.expectedIdentity,operationId=op,targetSession=target,roomInstance=instance,
            operatorId=event.operatorId,reason=event.reason}),headers={
                ["Content-Type"]="application/json",["X-Host-Recovery-Secret"]=admin_secret}},function(body,code)
            if completed then return; end; completed=true;
            if not current() then
                if gate[room] == state and state.admin_recovery == attempt then state.inflight=false; end
                reply("uncertain"); return;
            end
            local ok,result=pcall(json.decode,body);
            if code ~= 200 or not ok or type(result) ~= "table" or result.operationId ~= op
                or type(result.identity) ~= "string" or #result.identity ~= 51 then
                state.inflight=false; reply("uncertain"); return;
            end
            local identity=result.identity;
            local claimed=false;
            http.request(claim_url,{method="POST",body=json.encode({roomName=room_name,
                operationId=op,targetSession=target,roomInstance=instance}),headers={
                    ["Content-Type"]="application/json",["X-Role-Check-Secret"]=secret}},function(body,code)
                if claimed then return; end; claimed=true;
                if not current() then
                    if gate[room] == state and state.admin_recovery == attempt then state.inflight=false; end
                    reply("uncertain"); return;
                end
                state.inflight=false;
                local ok,credential=pcall(json.decode,body);
                if code ~= 200 or not ok or type(credential) ~= "table" or credential.identity ~= identity
                    or credential.previousOperationId ~= event.expectedOperationId
                    or type(credential.hostKey) ~= "string" or #credential.hostKey == 0 or #credential.hostKey > 128 then
                    reply("uncertain"); return;
                end
                local owners={};
                for owner in business_owners(room) do owners[#owners+1]=owner; end
                for _,owner in ipairs(owners) do
                    state.changing=true;
                    local ok,changed=pcall(room.set_affiliation,room,true,owner,"none","host-admin-recovery");
                    state.changing=false;
                    if not ok or changed ~= true or room:get_affiliation(owner) == "owner" then reply("uncertain"); return; end
                end
                if not change(room,state,occupant.bare_jid,occupant.nick,"owner","moderator") then
                    reply("uncertain"); return;
                end
                local owners_count=0;
                for owner in business_owners(room) do
                    if owner ~= occupant.bare_jid then reply("uncertain"); return; end
                    owners_count=owners_count+1;
                end
                if owners_count ~= 1 then reply("uncertain"); return; end
                state.instance=instance; state.holder=saved; state.identity=identity;
                state.operation={op=op,target=target,target_origin=saved.origin,
                    target_bare=occupant.bare_jid,nick=occupant.nick};
                state.awaiting_ack=true; state.blocked=false; state.admin_recovery=nil;
                module:send(st.message({from=room.jid,to=target,type="normal"})
                    :tag("credential",{xmlns=namespace,operationId=op,hostKey=credential.hostKey,identity=identity,
                        previousOperationId=credential.previousOperationId}):up());
                reply("awaiting-ack");
            end);
        end);
        return true;
    end);
end
