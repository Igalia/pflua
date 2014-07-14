module(...,package.seeall)

local bit = require('bit')

verbose = os.getenv("PF_VERBOSE");

local expand_arith, expand_relop, expand_bool

local function set(...)
   local ret = {}
   for k, v in pairs({...}) do ret[v] = true end
   return ret
end
local function concat(a, b)
   local ret = {}
   for _, v in ipairs(a) do table.insert(ret, v) end
   for _, v in ipairs(b) do table.insert(ret, v) end
   return ret
end

local ether_protos = set(
   'ip', 'ip6', 'arp', 'rarp', 'atalk', 'aarp', 'decnet', 'sca', 'lat',
   'mopdl', 'moprc', 'iso', 'stp', 'ipx', 'netbeui'
)

local ip_protos = set(
   'icmp', 'icmp6', 'igmp', 'igrp', 'pim', 'ah', 'esp', 'vrrp', 'udp', 'tcp'
)

local llc_types = set(
   'i', 's', 'u', 'rr', 'rnr', 'rej', 'ui', 'ua',
   'disc', 'sabme', 'test', 'xis', 'frmr'
)

local pf_reasons = set(
   'match', 'bad-offset', 'fragment', 'short', 'normalize', 'memory'
)

local pf_actions = set(
   'pass', 'block', 'nat', 'rdr', 'binat', 'scrub'
)

local wlan_frame_types = set('mgt', 'ctl', 'data')
local wlan_frame_mgt_subtypes = set(
   'assoc-req', 'assoc-resp', 'reassoc-req', 'reassoc-resp',
   'probe-req', 'probe-resp', 'beacon', 'atim', 'disassoc', 'auth', 'deauth'
)
local wlan_frame_ctl_subtypes = set(
   'ps-poll', 'rts', 'cts', 'ack', 'cf-end', 'cf-end-ack'
)
local wlan_frame_data_subtypes = set(
   'data', 'data-cf-ack', 'data-cf-poll', 'data-cf-ack-poll', 'null',
   'cf-ack', 'cf-poll', 'cf-ack-poll', 'qos-data', 'qos-data-cf-ack',
   'qos-data-cf-poll', 'qos-data-cf-ack-poll', 'qos', 'qos-cf-poll',
   'quos-cf-ack-poll'
)

local wlan_directions = set('nods', 'tods', 'fromds', 'dstods')

local iso_proto_types = set('clnp', 'esis', 'isis')

local function unimplemented(expr, dlt)
   error("not implemented: "..expr[1])
end

local function has_ether_protocol(proto)
   return { '=', { '[ether]', 12, 2 }, proto }
end
local function has_ipv4_protocol(proto)
   return { '=', { '[ip]', 9, 1 }, proto }
end
local function is_first_ipv4_fragment()
   return { '=', { '&', { '[ip]', 6, 2 }, 0x1fff }, 0 }
end
local function has_ipv6_protocol(proto)
   return { 'or',
            { '=', { '[ip6]', 6, 1 }, 6 },
            { 'and',
              { '=', { '[ip6]', 6, 1 }, 44 },
              { '=', { '[ip6]', 40, 1 }, 6 } } }
end
local function has_ip_protocol(proto)
   return { 'if', { 'ip' },
            has_ipv4_protocol(proto),
            { 'and', { 'ip6' }, has_ipv6_protocol(proto) } }
end

local primitive_expanders = {
   dst_host = unimplemented,
   dst_net = unimplemented,
   dst_port = unimplemented,
   dst_portrange = unimplemented,
   src_host = unimplemented,
   src_net = unimplemented,
   src_port = unimplemented,
   src_portrange = unimplemented,
   host = unimplemented,
   ether_src = unimplemented,
   ether_dst = unimplemented,
   ether_host = unimplemented,
   ether_broadcast = unimplemented,
   ether_multicast = unimplemented,
   ether_proto = unimplemented,
   gateway = unimplemented,
   net = unimplemented,
   port = function(expr)
      local port = expr[2]
      return { 'if', { 'ip' },
               { 'and',
                 { 'or', has_ipv4_protocol(6),
                   { 'or', has_ipv4_protocol(17), has_ipv4_protocol(132) } },
                 { 'or',
                   { '=', { '[ip*]', 0, 2 }, port },
                   { '=', { '[ip*]', 2, 2 }, port } } },
               { 'and',
                 { 'or', has_ipv6_protocol(6),
                   { 'or', has_ipv6_protocol(17), has_ipv6_protocol(132) } },
                 { 'or',
                   { '=', { '[ip6*]', 0, 2 }, port },
                   { '=', { '[ip6*]', 2, 2 }, port } } } }
   end,
   portrange = function(expr)
      local lo, hi = expr[2][1], expr[2][2]
      print('ohai', lo, hi)
      return { 'if', { 'ip' },
               { 'and',
                 { 'or', has_ipv4_protocol(6),
                   { 'or', has_ipv4_protocol(17), has_ipv4_protocol(132) } },
                 { 'or',
                   { 'and',
                     { '<=', { '[ip*]', 0, 2 }, lo },
                     { '<=', hi, { '[ip*]', 0, 2 } } },
                   { 'and',
                     { '<=', { '[ip*]', 0, 2 }, lo },
                     { '<=', hi, { '[ip*]', 0, 2 } } } } },
               { 'and',
                 { 'or', has_ipv6_protocol(6),
                   { 'or', has_ipv6_protocol(17), has_ipv6_protocol(132) } },
                 { 'or',
                   { 'and',
                     { '<=', { '[ip6*]', 0, 2 }, lo },
                     { '<=', hi, { '[ip6*]', 0, 2 } } },
                   { 'and',
                     { '<=', { '[ip6*]', 0, 2 }, lo },
                     { '<=', hi, { '[ip6*]', 0, 2 } } } } } }
   end,
   less = unimplemented,
   greater = unimplemented,
   ip = function(expr) return has_ether_protocol(2048) end,
   ip_proto = unimplemented,
   ip_protochain = unimplemented,
   ip_broadcast = unimplemented,
   ip_multicast = unimplemented,
   ip6 = function(expr) return has_ether_protocol(34525) end,
   ip6_proto = unimplemented,
   ip6_protochain = unimplemented,
   ip6_multicast = unimplemented,
   proto = unimplemented,
   tcp = function(expr) return has_ip_protocol(6) end,
   udp = function(expr) return has_ip_protocol(17) end,
   icmp = function(expr) return has_ip_protocol(1) end,
   protochain = unimplemented,
   arp = function(expr) return has_ether_protocol(2054) end,
   rarp = function(expr) return has_ether_protocol(32821) end,
   atalk = unimplemented,
   aarp = unimplemented,
   decnet_src = unimplemented,
   decnet_dst = unimplemented,
   decnet_host = unimplemented,
   iso = unimplemented,
   stp = unimplemented,
   ipx = unimplemented,
   netbeui = unimplemented,
   lat = unimplemented,
   moprc = unimplemented,
   mopdl = unimplemented,
   llc = unimplemented,
   ifname = unimplemented,
   on = unimplemented,
   rnr = unimplemented,
   rulenum = unimplemented,
   reason = unimplemented,
   rset = unimplemented,
   ruleset = unimplemented,
   srnr = unimplemented,
   subrulenum = unimplemented,
   action = unimplemented,
   wlan_ra = unimplemented,
   wlan_ta = unimplemented,
   wlan_addr1 = unimplemented,
   wlan_addr2 = unimplemented,
   wlan_addr3 = unimplemented,
   wlan_addr4 = unimplemented,
   type = unimplemented,
   type_subtype = unimplemented,
   subtype = unimplemented,
   dir = unimplemented,
   vlan = unimplemented,
   mpls = unimplemented,
   pppoed = unimplemented,
   pppoes = unimplemented,
   iso_proto = unimplemented,
   clnp = unimplemented,
   esis = unimplemented,
   isis = unimplemented,
   l1 = unimplemented,
   l2 = unimplemented,
   iih = unimplemented,
   lsp = unimplemented,
   snp = unimplemented,
   csnp = unimplemented,
   psnp = unimplemented,
   vpi = unimplemented,
   vci = unimplemented,
   lane = unimplemented,
   oamf4s = unimplemented,
   oamf4e = unimplemented,
   oamf4 = unimplemented,
   oam = unimplemented,
   metac = unimplemented,
   bcc = unimplemented,
   sc = unimplemented,
   ilmic = unimplemented,
   connectmsg = unimplemented,
   metaconnect = unimplemented
}

local relops = set('<', '<=', '=', '!=', '>=', '>')

local addressables = set(
   'arp', 'rarp', 'wlan', 'ether', 'fddi', 'tr', 'ppp',
   'slip', 'link', 'radio', 'ip', 'ip6', 'tcp', 'udp', 'icmp'
)

local binops = set(
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||', '<<', '>>'
)
local associative_binops = set(
   '+', '*', '&', '|', '^'
)
local bitops = set('&', '|', '^')
local unops = set('ntohs', 'ntohl')
local leaf_primitives = set(
   'true', 'false', 'fail'
)

local function expand_offset(level, dlt)
   assert(dlt == "EN10MB", "Encapsulation other than EN10MB unimplemented")
   local function assert_expr(expr)
      local test, asserts = expand_relop(expr, dlt)
      return concat(asserts, { test })
   end
   local function assert_ether_protocol(proto)
      return assert_expr(has_ether_protocol(proto))
   end
   function assert_ipv4_protocol(proto)
      return assert_expr(has_ipv4_protocol(proto))
   end
   function assert_ipv6_protocol(proto)
      return assert_expr(has_ipv6_protocol(proto))
   end
   function assert_first_ipv4_fragment()
      return assert_expr(is_first_ipv4_fragment())
   end
   function ipv4_payload_offset(proto)
      local ip_offset, asserts = expand_offset('ip', dlt)
      if proto then
         asserts = concat(asserts, assert_ipv4_protocol(proto))
      end
      asserts = concat(asserts, assert_first_ipv4_fragment())
      local res = { '+',
                    { '<<', { '&', { '[]', ip_offset, 1 }, 0xf }, 2 },
                    ip_offset }
      return res, asserts
   end
   function ipv6_payload_offset(proto)
      local ip_offset, asserts = expand_offset('ip6', dlt)
      if proto then
         asserts = concat(asserts, assert_ipv6_protocol(proto))
      end
      return { '+', ip_offset, 40 }, asserts
   end

   -- Note that unlike their corresponding predicates which detect
   -- either IPv4 or IPv6 traffic, [icmp], [udp], and [tcp] only work
   -- for IPv4.
   if level == 'ether' then
      return 0, {}
   elseif level == 'arp' then
      return 14, assert_ether_protocol(2054)
   elseif level == 'rarp' then
      return 14, assert_ether_protocol(32821)
   elseif level == 'ip' then
      return 14, assert_ether_protocol(2048)
   elseif level == 'ip6' then
      return 14, assert_ether_protocol(34525)
   elseif level == 'ip*' then
      return ipv4_payload_offset()
   elseif level == 'ip6*' then
      return ipv6_payload_offset()
   elseif level == 'icmp' then
      return ipv4_payload_offset(1)
   elseif level == 'udp' then
      return ipv4_payload_offset(17)
   elseif level == 'tcp' then
      return ipv4_payload_offset(6)
   end
   error('invalid level '..level)
end

function expand_arith(expr, dlt)
   assert(expr)
   if type(expr) == 'number' or expr == 'len' then return expr, {} end

   local op = expr[1]
   if binops[op] then
      local lhs, lhs_assertions = expand_arith(expr[2], dlt)
      local rhs, rhs_assertions = expand_arith(expr[3], dlt)
      return { op, lhs, rhs}, concat(lhs_assertions, rhs_assertions)
   end

   assert(op ~= '[]', "expr has already been expanded?")
   local addressable = assert(op:match("^%[(.+)%]$"), "bad addressable")
   local offset, offset_asserts = expand_offset(addressable, dlt)
   local lhs, lhs_asserts = expand_arith(expr[2], dlt)
   local size = expr[3]
   local len_assert = { '<=', { '+', { '+', offset, lhs }, size }, 'len' }
   local asserts = concat(concat(offset_asserts, lhs_asserts), { len_assert })
   local ret =  { '[]', { '+', offset, lhs }, size }
   if size == 1 then return ret, asserts end
   if size == 2 then return { 'ntohs', ret }, asserts end
   if size == 4 then return { 'ntohl', ret }, asserts end
   error('unreachable')
end

function expand_relop(expr, dlt)
   local lhs, lhs_assertions = expand_arith(expr[2], dlt)
   local rhs, rhs_assertions = expand_arith(expr[3], dlt)
   return { expr[1], lhs, rhs }, concat(lhs_assertions, rhs_assertions)
end

function expand_bool(expr, dlt)
   assert(type(expr) == 'table', 'logical expression must be a table')
   if expr[1] == 'not' or expr[1] == '!' then
      return { 'not', expand_bool(expr[2], dlt) }
   elseif expr[1] == 'and' or expr[1] == '&&' then
      return { 'if', expand_bool(expr[2], dlt),
               expand_bool(expr[3], dlt),
               { 'false' } }
   elseif expr[1] == 'or' or expr[1] == '||' then
      return { 'if', expand_bool(expr[2], dlt),
               { 'true' },
               expand_bool(expr[3], dlt) }
   elseif relops[expr[1]] then
      -- An arithmetic relop.
      local res, assertions = expand_relop(expr, dlt)
      while #assertions ~= 0 do
         res = { 'assert', table.remove(assertions), res }
      end
      return res
   elseif expr[1] == 'if' then
      return { 'if',
               expand_bool(expr[2], dlt),
               expand_bool(expr[3], dlt),
               expand_bool(expr[4], dlt) }
   elseif leaf_primitives[expr[1]] then
      return expr
   else
      -- A logical primitive.
      local expander = primitive_expanders[expr[1]]
      assert(expander, "unimplemented primitive: "..expr[1])
      local expanded = expander(expr, dlt)
      return expand_bool(expander(expr, dlt), dlt)
   end
end

local folders = {
   ['+'] = function(a, b) return a + b end,
   ['-'] = function(a, b) return a - b end,
   ['*'] = function(a, b) return a * b end,
   ['/'] = function(a, b) return math.floor(a / b) end,
   ['%'] = function(a, b) return a % b end,
   ['&'] = function(a, b) return bit.band(a, b) end,
   ['^'] = function(a, b) return bit.bxor(a, b) end,
   ['|'] = function(a, b) return bit.bor(a, b) end,
   ['<<'] = function(a, b) return bit.lshift(a, b) end,
   ['>>'] = function(a, b) return bit.rshift(a, b) end,
   ['ntohs'] = function(a) return bit.rshift(bit.bswap(a), 16) end,
   ['ntohl'] = function(a) return bit.bswap(a) end,
   ['='] = function(a, b) return a == b end,
   ['!='] = function(a, b) return a ~= b end,
   ['<'] = function(a, b) return a < b end,
   ['<='] = function(a, b) return a <= b end,
   ['>='] = function(a, b) return a >= b end,
   ['>'] = function(a, b) return a > b end
}

local function cfkey(expr)
   if type(expr) == 'table' then
      local ret = 'table('..cfkey(expr[1])
      for i=2,#expr do ret = ret..' '..cfkey(expr[i]) end
      return ret..')'
   else
      return type(expr)..'('..tostring(expr)..')'
   end
end

local simple = set('true', 'false', 'fail')

function try_invert(expr)
   local op = expr[1]
   if unops[op] then
      return assert(folders[op]), expr[2]
   elseif bitops[op] then
      local lhs, rhs = expr[2], expr[3]
      if type(lhs) == 'number' and unops[rhs[1]] then
         local fold =  assert(folders[rhs[1]])
         return fold, { op, fold(lhs), rhs[2] }
      elseif type(rhs) == 'number' and unops[lhs[1]] then
         local fold =  assert(folders[lhs[1]])
         return fold, { op, lhs[2], fold(rhs) }
      end
   end
end

function simplify(expr)
   if type(expr) ~= 'table' then return expr end
   local op = expr[1]
   if binops[op] then
      local lhs = simplify(expr[2])
      local rhs = simplify(expr[3])
      if type(lhs) == 'number' and type(rhs) == 'number' then
         return assert(folders[op])(lhs, rhs)
      elseif associative_binops[op] then
         if type(rhs) == 'table' and rhs[1] == op and type(lhs) == 'number' then
            lhs, rhs = rhs, lhs
         end
         if type(lhs) == 'table' and lhs[1] == op and type(rhs) == 'number' then
            if type(lhs[2]) == 'number' then
               return { op, assert(folders[op])(lhs[2], rhs), lhs[3] }
            elseif type(lhs[3]) == 'number' then
               return { op, lhs[2], assert(folders[op])(lhs[3], rhs) }
            end
         end
      end
      return { op, lhs, rhs }
   elseif unops[op] then
      local rhs = simplify(expr[2])
      if type(rhs) == 'number' then return assert(folders[op])(rhs) end
      return { op, rhs }
   elseif relops[op] then
      local lhs = simplify(expr[2])
      local rhs = simplify(expr[3])
      if type(lhs) == 'number' then
         if type(rhs) == 'number' then
            return { assert(folders[op])(lhs, rhs) and 'true' or 'false' }
         end
         invert_lhs, inverted_rhs = try_invert(rhs)
         if invert_lhs then lhs, rhs = invert_lhs(lhs), inverted_rhs end
      elseif type(rhs) == 'number' then
         invert_rhs, inverted_lhs = try_invert(lhs)
         if invert_rhs then lhs, rhs = inverted_lhs, invert_rhs(rhs) end
      end
      return { op, lhs, rhs }
   elseif op == 'not' then
      local rhs = simplify(expr[2])
      if rhs[1] == 'true' then return { 'false' }
      elseif rhs[1] == 'false' then return { 'true' }
      else return { op, rhs } end
   elseif op == 'if' then
      local test = simplify(expr[2])
      local kt = simplify(expr[3])
      local kf = simplify(expr[4])
      if test[1] == 'assert' then
         return simplify({ 'assert', test[2], { op, test[3], kt, kf } })
      elseif test[1] == 'true' then return kt
      elseif test[1] == 'false' then return kf
      elseif test[1] == 'not' then return simplify({op, test[2], kf, kt })
      elseif kt[1] == 'true' and kf[1] == 'false' then return test
      elseif kt[1] == 'false' and kf[1] == 'true' then return { 'not', test }
      -- FIXME: Memoize cfkey to avoid O(n^2) badness.
      elseif (test[1] == 'if' and kt[1] == 'if'
              and cfkey(test[2]) == cfkey(kt[2])) then
         if kf[1] == 'if' and cfkey(test[2]) == cfkey(kf[2]) then
            -- if (if A B C) (if A D E) (if A F G)
            -- -> if A (if B D F) (if C E G)
            return { 'if', test[2],
                     { 'if', test[3], kt[3], kf[3] },
                     { 'if', test[4], kt[4], kf[4] } }
         elseif simple[kf[1]] then
            -- if (if A B C) (if A D E) F
            -- -> if A (if B D F) (if C E F)
            return { 'if', test[2],
                     { 'if', test[3], kt[3], kf },
                     { 'if', test[4], kt[4], kf } }
         else
            return { 'if', test, kt, kf }
         end
      elseif (test[1] == 'if' and kf[1] == 'if'
              and cfkey(test[2]) == cfkey(kf[2]) and simple[kt[1]]) then
         -- if (if A B C) D (if A E F)
         -- -> if A (if B D E) (if C D F)
         return { 'if', test[2],
                  { 'if', test[3], kt, kf[3] },
                  { 'if', test[4], kt, kf[4] } }
      else return { op, test, kt, kf } end
   elseif op == 'assert' then
      local lhs = simplify(expr[2])
      local rhs = simplify(expr[3])
      if lhs[1] == 'true' then return rhs
      elseif lhs[1] == 'false' then return { 'fail' }
      else return { 'assert', lhs, rhs } end
   else
      local res = { op }
      for i=2,#expr do table.insert(res, simplify(expr[i])) end
      return res
   end
end

local function dup(db)
   local ret = {}
   for k, v in pairs(db) do ret[k] = v end
   return ret
end

-- Conditional folding.
local function cfold(expr, db)
   if type(expr) ~= 'table' then return expr end
   local op = expr[1]
   if binops[op] then return expr
   elseif unops[op] then return expr
   elseif relops[op] then
      local key = cfkey(expr)
      if db[key] ~= nil then
         return { db[key] and 'true' or 'false' }
      else
         return expr
      end
   elseif op == 'assert' then
      local test = cfold(expr[2], db)
      local key = cfkey(test)
      if db[key] ~= nil then
         if db[key] then return cfold(expr[3], db) end
         return { 'fail' }
      else
         db[key] = true
         return { op, test, cfold(expr[3], db) }
      end
   elseif expr[2] and type(expr[2]) == 'table' and expr[2][1] == 'assert' then
      local ret = { 'assert', expr[2][2], { op, expr[2][3] } }
      for i = 3, #expr do table.insert(ret[3], expr[i]) end
      return cfold(ret, db)
   elseif op == 'not' then
      local rhs = cfold(expr[2], db)
      local key = cfkey(rhs)
      if db[key] ~= nil then return { db[key] and 'false' or 'true' }
      elseif rhs[1] == 'true' then return { 'false' }
      elseif rhs[1] == 'false' then return { 'true' }
      else return { op, rhs } end
   elseif op == 'if' then
      local test = cfold(expr[2], db)
      local key = cfkey(test)
      if db[key] ~= nil then
         if db[key] then return cfold(expr[3], db) end
         return cfold(expr[4], db)
      else
         local db_kt = dup(db)
         local db_kf = dup(db)
         db_kt[key] = true
         db_kf[key] = false
         return { op, test, cfold(expr[3], db_kt), cfold(expr[4], db_kf) }
      end
   else
      return expr
   end
end

-- Range inference.
local function infer_ranges(expr)
   local function cons(car, cdr) return { car, cdr } end
   local function car(pair) return pair[1] end
   local function cdr(pair) return pair[2] end
   local function cadr(pair) return car(cdr(pair)) end
   local function push(db)
      return cons({ len={}, [1]={}, [2]={}, [4]={} }, db)
   end
   local function lookup(db, pos, size)
      while db do
         local pair = car(db)[size][cfkey(pos)]
         if pair then return pair[1], pair[2] end
         db = cdr(db)
      end
      if size == 1 then return 0, 0xff end
      if size == 2 then return 0, 0xffff end
      assert(size == 4)
      return 0, 0xffffffff
   end
   local function intern(db, pos, size, min, max)
      car(db)[size][cfkey(pos)] = { min, max }
   end
   local function merge(db, head)
      for size, tab in pairs(head) do
         for key, pair in pairs(tab) do
            car(db)[size][key] = pair
         end
      end
   end
   local function union(db, h1, h2)
      for size, tab in pairs(h1) do
         for key, pair in pairs(tab) do
            local min2, max2 = h2[size][key]
            if min2 then
               local min1, max1 = pair
               car(db)[size][key] = { math.min(min1, min2), math.ax(max1, max2) }
            end
         end
      end
   end

   local function eta(expr, kt, kf)
      if expr[1] == 'true' then return kt end
      if expr[1] == 'false' then return kf end
      if expr[1] == 'fail' then return 'REJECT' end
      return nil
   end

   local function restrict_range(min, max, op, val)
      if op == '<=' then
         return min, math.min(max, val), math.max(min, val + 1), max
      elseif op == '=' then
         return val, val, min, max
      elseif op == '~=' then
         return min, max, val, val
      else
         print('implement me', op)
         return min, max, min, max
      end
   end

   local function visit(expr, db_t, db_f, kt, kf)
      if type(expr) ~= 'table' then return expr end
      local op = expr[1]

      -- Arithmetic ops just use the store for lookup, so we can just
      -- use db_t and not worry about continuations.
      if op == '[]' then
         local pos, size = visit(expr[2], db_t), expr[3]
         local min, max = lookup(db_t, pos, size)
         if min == max then return min end
         return { op, pos, size }
      elseif unops[op] then
         local rhs = visit(expr[2], db_t)
         if type(rhs) == 'number' then
            return assert(folders[op])(rhs)
         end
         return { op, rhs }
      elseif binops[op] then
         local lhs, rhs = visit(expr[2], db_t), visit(expr[3], db_t)
         if type(lhs) == 'number' and type(rhs) == 'number' then
            return assert(folders[op])(lhs, rhs)
         end
         return { op, lhs, rhs }
      end

      -- Logical ops add to their db_t and db_f stores.
      if relops[op] then
         local lhs, rhs = visit(expr[2], db_t), visit(expr[3], db_t)
         if type(lhs) == 'number' and type(rhs) == 'number' then
            return { assert(folders[op])(lhs, rhs) and 'true' or 'false' }
         end
         if (type(lhs) == 'table' and lhs[1] == '[]'
             and type(rhs) == 'number') then
             local pos, size, val = lhs[2], lhs[3], rhs
             local min, max = lookup(db_t, pos, size)
             -- TODO: fold
             min_t, max_t, min_f, max_f = restrict_range(min, max, op, val)
             intern(db_t, pos, size, min_t, max_t)
             intern(db_f, pos, size, min_f, max_f)
         end
         return { op, lhs, rhs }
      elseif op == 'assert' then
         local test_db_t, test_db_f = push(db_t), push(db_t)
         local test_kt = eta(expr[3], kt, kf)
         local test = visit(expr[2], test_db_t, test_db_f, test_kt, 'REJECT')
         -- test_db_f is garbage, as this is an assertion.
         merge(db_t, car(test_db_t))
         merge(db_f, car(test_db_t))
         return { op, test, visit(expr[3], db_t, db_f, kt, kf) }
      elseif op == 'not' then
         return { op, visit(expr[2], db_f, db_t, kf, kt) }
      elseif op == 'if' then
         local test, t, f = expr[2], expr[3], expr[4]

         local test_db_t, test_db_f = push(db_t), push(db_t)
         local test_kt, test_kf = eta(t, kt, kf), eta(f, kt, kf)
         test = visit(test, test_db_t, test_db_f, test_kt, test_kf)

         local kt_db_t, kt_db_f = push(test_db_t), push(test_db_t)
         local kf_db_t, kf_db_f = push(test_db_f), push(test_db_f)
         t = visit(t, kt_db_t, kt_db_f, kt, kf)
         f = visit(f, kf_db_t, kf_db_f, kt, kf)

         if test_kt == 'fail' then
            local head_t, head_f = car(kf_db_t), car(kf_db_f)
            local assertions = cadr(kf_db_t)
            merge(db_t, assertions)
            merge(db_t, head_t)
            merge(db_f, assertions)
            merge(db_f, head_f)
         elseif test_kf == 'fail' then
            local head_t, head_f = car(kt_db_t), car(kt_db_f)
            local assertions = cadr(kt_db_t)
            merge(db_t, assertions)
            merge(db_t, head_t)
            merge(db_f, assertions)
            merge(db_f, head_f)
         else
            local head_t_t, head_t_f = car(kt_db_t), car(kt_db_f)
            local head_f_t, head_f_f = car(kf_db_t), car(kf_db_f)
            union(db_t, head_t_t, head_f_t)
            union(db_f, head_t_f, head_f_f)
         end
         return { op, test, t, f }
      else
         return expr
      end
   end
   return visit(expr, push(), push(), 'ACCEPT', 'REJECT')
end

-- Length assertion hoisting.
local function lhoist(expr, db)
   local function eta(expr, kt, kf)
      if expr[1] == 'true' then return kt end
      if expr[1] == 'false' then return kf end
      if expr[1] == 'fail' then return 'REJECT' end
      return nil
   end
   local function annotate(expr, kt, kf)
      local op = expr[1]
      if (op == '<=' and kf == 'REJECT'
          and type(expr[2]) == 'number' and expr[3] == 'len') then
         return { expr[2], expr }
      elseif op == 'assert' then
         local t, rhs = expr[2], expr[3]
         local t_a, rhs_a =
            annotate(t, eta(rhs, kt, kf), 'REJECT'), annotate(rhs, kt, kf)
         return { math.max(t_a[1], rhs_a[1]), { op, t_a, rhs_a } }
      elseif op == 'if' then
         local test, t, f = expr[2], expr[3], expr[4]
         local test_a = annotate(test, eta(t, kt, kf), eta(f, kt, kf))
         local t_a, f_a =  annotate(t, kt, kf), annotate(f, kt, kf)
         local rhs_min
         if eta(t, kt, kf) == 'REJECT' then rhs_min = f_a[1]
         elseif eta(f, kt, kf) == 'REJECT' then rhs_min = t_a[1]
         else rhs_min = math.min(t_a[1], f_a[1]) end
         return { math.max(test_a[1], rhs_min), { op, test_a, t_a, f_a } }
      else
         return { 0, expr }
      end
   end

   local function reduce(aexpr, min)
      if min < aexpr[1] then
         return { 'assert', { '<=', aexpr[1], 'len' }, reduce(aexpr, aexpr[1]) }
      end
      local expr = aexpr[2]
      local op = expr[1]
      if op == 'assert' then
         local t, rhs = reduce(expr[2], min), reduce(expr[3], min)
         if t[1] == '<=' and type(t[2]) == 'number' and t[3] == 'len' then
            if t[2] <= min then return rhs end
         end
         return { op, t, rhs }
      elseif op == 'if' then
         local t, kt, kf =
            reduce(expr[2], min), reduce(expr[3], min), reduce(expr[4], min)
         if t[1] == '<=' and type(t[2]) == 'number' and t[3] == 'len' then
            if t[2] <= min then return kt else return kf end
         end
         return { op, t, kt, kf }
      else
         return expr
      end
   end
      
   return reduce(annotate(expr, 'ACCEPT', 'REJECT'), 0)
end

function pp(expr, indent, suffix)
   indent = indent or ''
   suffix = suffix or ''
   if type(expr) == 'number' then
      print(indent..expr..suffix)
   elseif type(expr) == 'string' then
      print(indent..'"'..expr..'"'..suffix)
   elseif type(expr) == 'boolean' then
      print(indent..(expr and 'true' or 'false')..suffix)
   elseif type(expr) == 'table' then
      if #expr == 1 then
         print(indent..'{ "'..expr[1]..'" }'..suffix)
      else
         print(indent..'{ "'..expr[1]..'",')
         indent = indent..'  '
         for i=2,#expr-1 do pp(expr[i], indent, ',') end
         pp(expr[#expr], indent, ' }'..suffix)
      end
   else
      error("unsupported type "..type(expr))
   end
end

function expand(expr, dlt)
   dlt = dlt or 'RAW'
   expr = simplify(expand_bool(expr, dlt))
   expr = simplify(cfold(expr, {}))
   expr = simplify(infer_ranges(expr))
   expr = simplify(lhoist(expr))
   if verbose then pp(expr) end
   return expr
end

function selftest ()
   print("selftest: pf.expand")
   local parse = require('pf.parse').parse
   local function equals(expected, actual)
      if type(expected) ~= type(actual) then return false end
      if type(expected) == 'table' then
         for k, v in pairs(expected) do
            if not equals(v, actual[k]) then return false end
         end
         return true
      else
         return expected == actual
      end
   end
   local function check(expected, actual)
      if not equals(expected, actual) then
         pp(expected)
         pp(actual)
         error('not equal')
      end
   end
   check({ 'false' },
      expand(parse("1 = 2"), 'EN10MB'))
   check({ '=', 1, len },
      expand(parse("1 = len"), 'EN10MB'))
   check({ 'assert', { '<=', 1, 'len'}, { '=', { '[]', 0, 1 }, 2 } },
      expand(parse("ether[0] = 2"), 'EN10MB'))
   -- Could check this, but it's very large
   expand(parse("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"),
          "EN10MB")
   print("OK")
end
