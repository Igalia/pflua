module(...,package.seeall)

local utils = require('pf.utils')

verbose = os.getenv("PF_VERBOSE");

local expand_arith, expand_relop, expand_bool

local set, concat, pp = utils.set, utils.concat, utils.pp

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

-- Port operations
--
local function has_ipv4_src_port(port)
   return { '=', { '[ip*]', 0, 2 }, port }
end
local function has_ipv4_dst_port(port)
   return { '=', { '[ip*]', 2, 2 }, port }
end
local function has_ipv4_port(port)
   return { 'or', has_ipv4_src_port(port), has_ipv4_dst_port(port) }
end
local function has_ipv6_src_port(port)
   return { '=', { '[ip6*]', 0, 2 }, port }
end
local function has_ipv6_dst_port(port)
   return { '=', { '[ip6*]', 2, 2 }, port }
end
local function has_ipv6_port(port)
   return { 'or', has_ipv6_src_port(port), has_ipv6_dst_port(port) }
end
local function expand_port(expr)
   local port = expr[2]
   return { 'if', { 'ip' },
            { 'and',
              { 'or', has_ipv4_protocol(6),
                { 'or', has_ipv4_protocol(17), has_ipv4_protocol(132) } },
              has_ipv4_port(port) },
            { 'and',
              { 'or', has_ipv6_protocol(6),
                { 'or', has_ipv6_protocol(17), has_ipv6_protocol(132) } },
              has_ipv6_port(port) } }
end

local function expand_proto_port(expr, proto)
   local port = expr[2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_port(port) },
            { 'and',
              has_ipv6_protocol(proto),
              has_ipv6_port(port) } }
end
local function expand_tcp_port(expr)
   return expand_proto_port(expr, 6)
end
local function expand_udp_port(expr)
   return expand_proto_port(expr, 17)
end

local function expand_proto_src_port(expr, proto)
   local port = expr[2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_src_port(port) },
            { 'and',
              has_ipv6_protocol(proto),
              has_ipv6_src_port(port) } }
end
local function expand_tcp_src_port(expr)
   return expand_proto_src_port(expr, 6)
end
local function expand_udp_src_port(expr)
   return expand_proto_src_port(expr, 17)
end

local function expand_proto_dst_port(expr, proto)
   local port = expr[2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_dst_port(port) },
            { 'and',
              has_ipv6_protocol(proto),
              has_ipv6_dst_port(port) } }
end
local function expand_tcp_dst_port(expr)
   return expand_proto_dst_port(expr, 6)
end
local function expand_udp_dst_port(expr)
   return expand_proto_dst_port(expr, 17)
end

-- Portrange operations
--
local function has_ipv4_src_portrange(lo, hi)
   return { 'and',
            { '<=', lo, { '[ip*]', 0, 2 } },
            { '<=', { '[ip*]', 0, 2 }, hi } }
end
local function has_ipv4_dst_portrange(lo, hi)
   return { 'and',
            { '<=', lo, { '[ip*]', 2, 2 } },
            { '<=', { '[ip*]', 2, 2 }, hi } }
end
local function has_ipv4_portrange(lo, hi)
   return { 'or', has_ipv4_src_portrange(lo, hi), has_ipv4_dst_portrange(lo, hi) }
end
local function has_ipv6_src_portrange(lo, hi)
   return { 'and',
            { '<=', lo, { '[ip*]', 0, 2 } },
            { '<=', { '[ip*]', 0, 2 }, hi } }
end
local function has_ipv6_dst_portrange(lo, hi)
   return { 'and',
            { '<=', lo, { '[ip*]', 2, 2 } },
            { '<=', { '[ip*]', 2, 2 }, hi } }
end
local function has_ipv6_portrange(lo, hi)
   return { 'or', has_ipv6_src_portrange(lo, hi), has_ipv6_dst_portrange(lo, hi) }
end
local function expand_portrange(expr)
   local lo, hi = expr[2][1], expr[2][2]
   return { 'if', { 'ip' },
            { 'and',
              { 'or', has_ipv4_protocol(6), 
                { 'or', has_ipv4_protocol(17), has_ipv4_protocol(132) } },
              has_ipv4_portrange(lo, hi) },
            { 'and',
              { 'or', has_ipv6_protocol(6),
                { 'or', has_ipv6_protocol(17), has_ipv6_protocol(132) } },
              has_ipv6_portrange(lo, hi) } }
end

local function expand_proto_portrange(expr, proto)
   local lo, hi = expr[2][1], expr[2][2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_portrange(lo, hi) },
            { 'and',
              has_ipv6_protocol(proto),
              has_ipv6_portrange(lo, hi) } }
end
local function expand_tcp_portrange(expr)
   return expand_proto_portrange(expr, 6)
end
local function expand_udp_portrange(expr)
   return expand_proto_portrange(expr, 17)
end

local function expand_proto_src_portrange(expr, proto)
   local lo, hi = expr[2][1], expr[2][2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_src_portrange(lo, hi) },
            { 'and',
              has_ipv6_protocol(proto),
              has_ipv6_src_portrange(lo, hi) } }
end
local function expand_tcp_src_portrange(expr)
   return expand_proto_src_portrange(expr, 6)
end
local function expand_udp_src_portrange(expr)
   return expand_proto_src_portrange(expr, 17)
end

local function expand_proto_dst_portrange(expr, proto)
   local lo, hi = expr[2][1], expr[2][2]
   return { 'if', { 'ip' },
            { 'and',
              has_ipv4_protocol(proto),
              has_ipv4_dst_portrange(lo, hi) },
            { 'and', 
              has_ipv6_protocol(proto),
              has_ipv6_dst_portrange(lo, hi) } }
end
local function expand_tcp_dst_portrange(expr)
   return expand_proto_dst_portrange(expr, 6)
end
local function expand_udp_dst_portrange(expr)
   return expand_proto_dst_portrange(expr, 17)
end

-- Network-byte-order 4 byte word to host-network-order uint32
local function host_uint32(a, b, c, d)
   return d * 2^24 + c * 2^16 + b * 2^8 + a
end

-- Network-byte-order 2 byte word to host-network-order uint16
local function host_uint16(a, b)
   return b * 2^8 + a
end

local function ipv4_to_int(addr)
   assert(addr[1] == 'ipv4', "Not an IPV4 address")
   return host_uint32(addr[2], addr[3], addr[4], addr[5])
end

-- IP protocol

local function is_ip_protocol()
   return has_ether_protocol(2048)
end
local function expand_ip_src_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_ip_protocol(), { '=', { '[ip]', 12, 4 }, host } }
end
local function expand_ip_dst_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_ip_protocol(), { '=', { '[ip]', 16, 4 }, host } }
end
local function expand_ip_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'or', expand_ip_src_host(expr), expand_ip_dst_host(expr) }
end

-- ARP protocol

local function is_arp_protocol()
   return has_ether_protocol(2054)
end
local function expand_arp_src_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_arp_protocol(), { '=', { '[arp]', 14, 4 }, host } }
end
local function expand_arp_dst_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_arp_protocol(), { '=', { '[arp]', 24, 4 }, host } }
end
local function expand_arp_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'or', expand_arp_src_host(expr), expand_arp_dst_host(expr) }
end

-- RARP protocol

local function is_rarp_protocol()
   return has_ether_protocol(32821)
end
local function expand_rarp_src_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_rarp_protocol(), { '=', { '[rarp]', 14, 4 }, host } }
end
local function expand_rarp_dst_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'and', is_rarp_protocol(), { '=', { '[rarp]', 24, 4 }, host } }
end
local function expand_rarp_host(expr)
   local host = ipv4_to_int(expr[2])
   return { 'or', expand_rarp_src_host(expr), expand_rarp_dst_host(expr) }
end

-- Host

local function expand_src_host(expr)
   return { 'or', expand_ip_src_host(expr),
            { 'or', expand_arp_src_host(expr), expand_rarp_src_host(expr) } }
end
local function expand_dst_host(expr)
   return { 'or', expand_ip_dst_host(expr),
            { 'or', expand_arp_dst_host(expr), expand_rarp_dst_host(expr) } }
end
local function expand_host(expr)
   return { 'and', expand_src_host(expr), expand_dst_host(expr) }
end

-- Ether

-- In host-byte-order (little endian)
local function ehost_to_int(addr)
   assert(addr[1] == 'ehost', "Not a valid ehost address")
   return host_uint16(addr[2], addr[3]), host_uint32(addr[4], addr[5], addr[6], addr[7])
end
local function expand_ether_src_host(expr)
   local hi, lo = ehost_to_int(expr[2])
   return { 'and',
            { '=', { '[ether]', 6, 2 }, hi },
            { '=', { '[ether]', 8, 4 }, lo } }
end
local function expand_ether_dst_host(expr)
   local hi, lo = ehost_to_int(expr[2])
   return { 'and',
            { '=', { '[ether]', 0, 2 }, hi },
            { '=', { '[ether]', 2, 4 }, lo } }
end
local function expand_ether_host(expr)
   return { 'or', expand_ether_src_host(expr), expand_ether_dst_host(expr) }
end

local primitive_expanders = {
   dst_host = expand_dst_host,
   dst_net = unimplemented,
   dst_port = unimplemented,
   dst_portrange = unimplemented,
   src_host = expand_src_host,
   src_net = unimplemented,
   src_port = unimplemented,
   src_portrange = unimplemented,
   host = expand_host,
   ether_src = expand_ether_src_host,
   ether_src_host = expand_ether_src_host,
   ether_dst = expand_ether_dst_host,
   ether_dst_host = expand_ether_dst_host,
   ether_host = expand_ether_host,
   ether_broadcast = unimplemented,
   ether_multicast = unimplemented,
   ether_proto = unimplemented,
   gateway = unimplemented,
   net = unimplemented,
   port = expand_port,
   portrange = expand_portrange,
   less = unimplemented,
   greater = unimplemented,
   ip = is_ip_protocol,
   ip_proto = unimplemented,
   ip_protochain = unimplemented,
   ip_host = expand_ip_host,
   ip_src = expand_ip_src_host,
   ip_src_host = expand_ip_src_host,
   ip_dst = expand_ip_dst_host,
   ip_dst_host = expand_ip_dst_host,
   ip_broadcast = unimplemented,
   ip_multicast = unimplemented,
   ip6 = function(expr) return has_ether_protocol(34525) end,
   ip6_proto = unimplemented,
   ip6_protochain = unimplemented,
   ip6_multicast = unimplemented,
   proto = unimplemented,
   tcp = function(expr) return has_ip_protocol(6) end,
   tcp_port = expand_tcp_port,
   tcp_src_port = expand_tcp_src_port,
   tcp_dst_port = expand_tcp_dst_port,
   tcp_portrange = expand_tcp_portrange,
   tcp_src_portrange = expand_tcp_src_portrange,
   tcp_dst_portrange = expand_tcp_dst_portrange,
   udp = function(expr) return has_ip_protocol(17) end,
   udp_port = expand_udp_port,
   udp_src_port = expand_udp_src_port,
   udp_dst_port = expand_udp_dst_port,
   udp_portrange = expand_udp_portrange,
   udp_src_portrange = expand_udp_src_portrange,
   udp_dst_portrange = expand_udp_dst_portrange,
   icmp = function(expr) return has_ip_protocol(1) end,
   protochain = unimplemented,
   arp = is_arp_protocol,
   arp_host = expand_arp_host,
   arp_src = expand_arp_src_host,
   arp_src_host = expand_arp_src_host,
   arp_dst = expand_arp_dst_host,
   arp_dst_host = expand_arp_dst_host,
   rarp = is_rarp_protocol,
   rarp_host = expand_rarp_host,
   rarp_src = expand_rarp_src_host,
   rarp_src_host = expand_rarp_src_host,
   rarp_dst = expand_rarp_dst_host,
   rarp_dst_host = expand_rarp_dst_host,
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
      -- Mod 2^32 to preserve uint32 range.
      local ret = { '%', { op, lhs, rhs }, 2^32 }
      local assertions = concat(lhs_assertions, rhs_assertions)
      -- RHS of division can't be 0.
      if op == '/' or op == '%' then
         assertions = concat(assertions, { '!=', rhs, 0 })
      end
      return ret, assertions
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
   if size == 4 then return { '%', { 'ntohl', ret }, 2^32 }, asserts end
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
         res = { 'if', table.remove(assertions), res, { 'fail' } }
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

function expand(expr, dlt)
   dlt = dlt or 'RAW'
   expr = expand_bool(expr, dlt)
   if verbose then pp(expr) end
   return expr
end

function selftest ()
   print("selftest: pf.expand")
   local parse = require('pf.parse').parse
   local equals, assert_equals = utils.equals, utils.assert_equals
   assert_equals({ '=', 1, 2 },
      expand(parse("1 = 2"), 'EN10MB'))
   assert_equals({ '=', 1, "len" },
      expand(parse("1 = len"), 'EN10MB'))
   assert_equals({ 'if',
                   { '<=', { '+', { '+', 0, 0 }, 1 }, 'len'},
                   { '=', { '[]', { '+', 0, 0 }, 1 }, 2 },
                   { 'fail' } },
      expand(parse("ether[0] = 2"), 'EN10MB'))
   -- Could check this, but it's very large
   expand(parse("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"),
          "EN10MB")
   print("OK")
end
