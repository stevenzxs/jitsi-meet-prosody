-- Because we deal with pre-authed sessions and streams we can't be host-specific
module:set_global();

local it = require "prosody.util.iterators";
local filters = require "prosody.util.filters";
local throttle = require "prosody.util.throttle";
local timer = require "prosody.util.timer";

local pton = require "prosody.util.net".pton;

local ceil = math.ceil;

local limits_cfg = module:get_option("limits", {});
local limits_resolution = module:get_option_period("limits_resolution", 1);

local default_bytes_per_second = 3000;
local default_burst = 2;

local rate_units = { b = 1, k = 3, m = 6, g = 9, t = 12 } -- Plan for the future.
local function parse_rate(rate, sess_type)
	local quantity, unit, exp;
	if rate then
		quantity, unit = rate:match("^(%d+) ?([^/]+)/s$");
		exp = quantity and rate_units[unit:sub(1,1):lower()];
	end
	if not exp then
		module:log("error", "Error parsing rate for %s: %q, using default rate (%d bytes/s)", sess_type, rate, default_bytes_per_second);
		return default_bytes_per_second;
	end
	return quantity*(10^exp);
end

local function parse_burst(burst, sess_type)
	if type(burst) == "string" then
		burst = burst:match("^(%d+) ?s$");
	end
	local n_burst = tonumber(burst);
	if burst and not n_burst then
		module:log("error", "Unable to parse burst for %s: %q, using default burst interval (%ds)", sess_type, burst, default_burst);
	end
	return n_burst or default_burst;
end

-- Process config option into limits table:
-- limits = { c2s = { bytes_per_second = X, burst_seconds = Y } }
local limits = {
	c2s = {
		bytes_per_second = 10 * 1024;
		burst_seconds = 2;
	};
	s2s = {
		bytes_per_second = 30 * 1024;
		burst_seconds = 2;
	};
};

local function get_truncated_ip(conn)
	local session_ip = pton(conn:ip());
	if #session_ip == 128 then
		-- Use /64 for IPv6
		session_ip = session_ip:sub(1, 8);
	end
	return session_ip;
end

local function limit_ip_sessions(session_type, max_sessions)
	-- [packed_truncated_ip] = count
	local current_ips = module:shared("ips."..session_type);
	module:hook(session_type.."-connected", function (event)
		if not event.session then return; end
		local session_ip = get_truncated_ip(event.conn);
		local new_count = (current_ips[session_ip] or 0) + 1;
		current_ips[session_ip] = new_count;
		module:log("debug", "Connection from IP %s opened, total now %d", event.conn:ip(), new_count);
		if new_count > max_sessions then
			module:log("warn", "Rejecting stream from %s (%d of %d current connections)", event.conn:ip(), new_count, max_sessions);
			event.session:close({ condition = "policy-violation", text = "too many connections" });
		end
	end);

	module:hook(session_type.."-closed", function (event)
		if not event.session then return; end
		local session_ip = get_truncated_ip(event.conn);
		local new_count = (current_ips[session_ip] or 0) - 1;
		if new_count < 0 then
			module:log("warn", "IP counting failure");
			new_count = 0;
		end
		module:log("debug", "Connection from IP %s closed, total now %d", event.conn:ip(), new_count);
		if new_count == 0 then
			current_ips[session_ip] = nil;
		else
			current_ips[session_ip] = new_count;
		end
	end);
end

for sess_type, sess_limits in pairs(limits_cfg) do
	limits[sess_type] = {
		bytes_per_second = parse_rate(sess_limits.rate, sess_type);
		burst_seconds = parse_burst(sess_limits.burst, sess_type);
	};
	if sess_limits.max_connections_per_ip then
		limit_ip_sessions(sess_type, sess_limits.max_connections_per_ip);
	end
end

if not limits.s2sin and limits.s2s then
	limits.s2sin = limits.s2s;
end
if not limits.s2sout then
	limits.s2sout = limits.s2s or limits.s2sin;
end

local default_filter_set = {};

function default_filter_set.bytes_in(bytes, session)
	local sess_throttle = session.throttle;
	if sess_throttle then
		local ok, _, outstanding = sess_throttle:poll(#bytes, true);
		if not ok then
			session.log("debug", "Session over rate limit (%d) with %d (by %d), pausing", sess_throttle.max, #bytes, outstanding);
			outstanding = ceil(outstanding);
			session.conn:pause(); -- Read no more data from the connection until there is no outstanding data
			local outstanding_data = bytes:sub(-outstanding);
			bytes = bytes:sub(1, #bytes-outstanding);
			timer.add_task(limits_resolution, function ()
				if not session.conn then return; end
				if sess_throttle:peek(#outstanding_data) then
					session.log("debug", "Resuming paused session");
					session.conn:resume();
				end
				-- Handle what we can of the outstanding data
				session.data(outstanding_data);
			end);
		end
	end
	return bytes;
end

local type_filters = {
	c2s = default_filter_set;
	s2sin = default_filter_set;
	s2sout = default_filter_set;
};

local function filter_hook(session)
	local session_type = session.type:match("^[^_]+");
	local filter_set, opts = type_filters[session_type], limits[session_type];
	if opts then
		if session.conn and session.conn.setlimit then
			session.conn:setlimit(opts.bytes_per_second);
			-- Currently no burst support
		else
			session.throttle = throttle.create(opts.bytes_per_second * opts.burst_seconds, opts.burst_seconds);
			filters.add_filter(session, "bytes/in", filter_set.bytes_in, 1000);
		end
	end
end

function module.load()
	filters.add_filter_hook(filter_hook);
end

function module.unload()
	filters.remove_filter_hook(filter_hook);
end

function unlimited(session)
	local session_type = session.type:match("^[^_]+");
	if session.conn and session.conn.setlimit then
		session.conn:setlimit(0);
		-- Currently no burst support
	else
		local filter_set = type_filters[session_type];
		filters.remove_filter(session, "bytes/in", filter_set.bytes_in);
		session.throttle = nil;
	end
end

function module.add_host(module)
	local unlimited_jids = module:get_option_inherited_set("unlimited_jids", {});

	if not unlimited_jids:empty() then
		module:hook("authentication-success", function (event)
			local session = event.session;
			local jid = session.username .. "@" .. session.host;
			if unlimited_jids:contains(jid) then
				unlimited(session);
			end
		end);

		module:hook("s2sout-established", function (event)
			local session = event.session;
			if unlimited_jids:contains(session.to_host) then
				unlimited(session);
			end
		end);

		module:hook("s2sin-established", function (event)
			local session = event.session;
			if session.from_host and unlimited_jids:contains(session.from_host) then
				unlimited(session);
			end
		end);

	end
end

module:add_item("shell-command", {
	section = "limits";
	section_desc = "Commands to inspect rate-limiting state";
	name = "connections";
	desc = "View per-IP connection limit status";
	args = {
		{ name = "ip", type = "string" };
	};
	handler = function(self, ip_str) -- luacheck: ignore 212/self
		local check_ip = pton(ip_str);
		if not check_ip then
			return false, "Unable to parse IP address: "..ip_str;
		end
		if #check_ip == 128 then
			check_ip = check_ip:sub(1, 8);
		end

		local found, any_limits = 0;

		for sess_type, sess_limits in it.sorted_pairs(limits_cfg) do
			if sess_limits.max_connections_per_ip then
				any_limits = true;
				local current_ips = module:shared("ips."..sess_type);
				local count = current_ips[check_ip] or 0;
				self.session.print(("%s: %d (limit %d)"):format(sess_type, count or 0, sess_limits.max_connections_per_ip));
				found = found + count;
			end
		end

		if not any_limits then
			return false, "No per-IP limits are configured";
		end

		return true, ("Total of %d tracked connections with this IP"):format(found);
	end;
});


