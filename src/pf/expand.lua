module(...,package.seeall)

local utils = require('pf.utils')

verbose = os.getenv("PF_VERBOSE");

local expand_arith, expand_relop, expand_bool

local set, concat, pp = utils.set, utils.concat, utils.pp
local uint16, uint32 = utils.uint16, utils.uint32
local ipv4_to_int, ipv6_as_4x32 = utils.ipv4_to_int, utils.ipv6_as_4x32

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

local function unimplemented(expr, dlt)
   error("not implemented: "..expr[1])
end

-- Ethernet protocols
local PROTO_IPV4 = 2048       -- 0x800
local PROTO_ARP = 2054        -- 0x806
local PROTO_RARP = 32821      -- 0x8035
local PROTO_ATALK = 32923     -- 0x809b
local PROTO_AARP = 33011      -- 0x80f3
local PROTO_IPV6 = 34525      -- 0x86dd
local PROTO_DECNET = 24579    -- 0x6003
local PROTO_SCA = 24583       -- 0x6007
local PROTO_LAT = 24580       -- 0x6004
local PROTO_MOPDL = 24577     -- 0x6001
local PROTO_MOPRC = 24578     -- 0x6002
local PROTO_ISO = 65278       -- 0xfefe
local PROTO_STP = 66          -- 0x42
local PROTO_IPX = 33079       -- 0X8137
local PROTO_NETBEUI = 61680   -- 0xf0f0
local ether_min_payloads = {
   [PROTO_IPV4] = 20,
   [PROTO_ARP] = 28,
   [PROTO_RARP] = 28,
   [PROTO_IPV6] = 40
}

-- IP protocols
local PROTO_ICMP = 1          -- 0x1
local PROTO_TCP = 6           -- 0x6
local PROTO_UDP = 17          -- 0x11
local PROTO_SCTP = 132        -- 0x84
local PROTO_IGMP = 2          -- 0x2
local PROTO_IGRP = 9          -- 0x9
local PROTO_PIM = 103         -- 0x67
local PROTO_AH = 51           -- 0x33
local PROTO_ESP = 50          -- 0x32
local PROTO_VRRP = 112        -- 0x70

local ip_min_payloads = {
   [PROTO_ICMP] = 8,
   [PROTO_UDP] = 8,
   [PROTO_TCP] = 20
}

-- Minimum payload checks insert a byte access to the last byte of the
-- minimum payload size.  Since the comparison should fold (because it
-- will always be >= 0), we will be left with just an eager assertion on
-- the minimum packet size, which should help elide future packet size
-- assertions.
local function has_proto_min_payload(min_payloads, proto, accessor)
   local min_payload = assert(min_payloads[proto])
   return { '<=', 0, { accessor, min_payload - 1, 1 } }
end

local function has_ether_protocol(proto)
   return { '=', { '[ether]', 12, 2 }, proto }
end
local function has_ether_protocol_min_payload(proto)
   return has_proto_min_payload(ether_min_payloads, proto, '[ether*]')
end
local function has_ipv4_protocol(proto)
   return { '=', { '[ip]', 9, 1 }, proto }
end
local function has_ipv4_protocol_min_payload(proto)
   -- Since the [ip*] accessor asserts that is_first_ipv4_fragment(),
   -- and we don't want that, we use [ip] and assume the minimum IP
   -- header size.
   local min_payload = assert(ip_min_payloads[proto])
   min_payload = min_payload + assert(ether_min_payloads[PROTO_IPV4])
   return { '<=', 0, { '[ip]', min_payload - 1, 1 } }
end
local function is_first_ipv4_fragment()
   return { '=', { '&', { '[ip]', 6, 2 }, 0x1fff }, 0 }
end
local function has_ipv6_protocol(proto)
   return { 'or',
            { '=', { '[ip6]', 6, 1 }, proto },
            { 'and',
              { '=', { '[ip6]', 6, 1 }, 44 },
              { '=', { '[ip6]', 40, 1 }, proto } } }
end
local function has_ipv6_protocol_min_payload(proto)
   -- Assume the minimum ipv6 header size.
   local min_payload = assert(ip_min_payloads[proto])
   min_payload = min_payload + assert(ether_min_payloads[PROTO_IPV6])
   return { '<=', 0, { '[ip6]', min_payload - 1, 1 } }
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
local function expand_dir_port(expr, has_ipv4_port, has_ipv6_port)
   local port = expr[2]
   return { 'if', { 'ip' },
            { 'and',
              { 'or', has_ipv4_protocol(PROTO_TCP),
                { 'or', has_ipv4_protocol(PROTO_UDP),
                  has_ipv4_protocol(PROTO_SCTP) } },
              has_ipv4_port(port) },
            { 'and',
              { 'or', has_ipv6_protocol(PROTO_TCP),
                { 'or', has_ipv6_protocol(PROTO_UDP),
                  has_ipv6_protocol(PROTO_SCTP) } },
              has_ipv6_port(port) } }
end
local function expand_port(expr)
   return expand_dir_port(expr, has_ipv4_port, has_ipv6_port)
end
local function expand_src_port(expr)
   return expand_dir_port(expr, has_ipv4_src_port, has_ipv4_dst_port)
end
local function expand_dst_port(expr)
   return expand_dir_port(expr, has_ipv4_dst_port, has_ipv6_dst_port)
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
   return expand_proto_port(expr, PROTO_TCP)
end
local function expand_udp_port(expr)
   return expand_proto_port(expr, PROTO_UDP)
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
   return expand_proto_src_port(expr, PROTO_TCP)
end
local function expand_udp_src_port(expr)
   return expand_proto_src_port(expr, PROTO_UDP)
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
   return expand_proto_dst_port(expr, PROTO_TCP)
end
local function expand_udp_dst_port(expr)
   return expand_proto_dst_port(expr, PROTO_UDP)
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
            { '<=', lo, { '[ip6*]', 0, 2 } },
            { '<=', { '[ip6*]', 0, 2 }, hi } }
end
local function has_ipv6_dst_portrange(lo, hi)
   return { 'and',
            { '<=', lo, { '[ip6*]', 2, 2 } },
            { '<=', { '[ip6*]', 2, 2 }, hi } }
end
local function has_ipv6_portrange(lo, hi)
   return { 'or', has_ipv6_src_portrange(lo, hi), has_ipv6_dst_portrange(lo, hi) }
end
local function expand_dir_portrange(expr, has_ipv4_portrange, has_ipv6_portrange)
   local lo, hi = expr[2][1], expr[2][2]
   return { 'if', { 'ip' },
            { 'and',
              { 'or', has_ipv4_protocol(PROTO_TCP),
                { 'or', has_ipv4_protocol(PROTO_UDP),
                  has_ipv4_protocol(PROTO_SCTP) } },
              has_ipv4_portrange(lo, hi) },
            { 'and',
              { 'or', has_ipv6_protocol(PROTO_TCP),
                { 'or', has_ipv6_protocol(PROTO_UDP),
                  has_ipv6_protocol(PROTO_SCTP) } },
              has_ipv6_portrange(lo, hi) } }
end
local function expand_portrange(expr)
   return expand_dir_portrange(expr, has_ipv4_portrange, has_ipv6_portrange)
end
local function expand_src_portrange(expr)
   return expand_dir_portrange(expr, has_ipv4_src_portrange, has_ipv6_dst_portrange)
end
local function expand_dst_portrange(expr)
   return expand_dir_portrange(expr, has_ipv4_src_portrange, has_ipv6_dst_portrange)
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
   return expand_proto_portrange(expr, PROTO_TCP)
end
local function expand_udp_portrange(expr)
   return expand_proto_portrange(expr, PROTO_UDP)
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
   return expand_proto_src_portrange(expr, PROTO_TCP)
end
local function expand_udp_src_portrange(expr)
   return expand_proto_src_portrange(expr, PROTO_UDP)
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
   return expand_proto_dst_portrange(expr, PROTO_TCP)
end
local function expand_udp_dst_portrange(expr)
   return expand_proto_dst_portrange(expr, PROTO_UDP)
end

-- IP protocol

local proto_info = {
   ip   = { id = PROTO_IPV4,  access = "[ip]",    src = 12, dst = 16 },
   arp  = { id = PROTO_ARP,   access = "[arp]",   src = 14, dst = 24 },
   rarp = { id = PROTO_RARP,  access = "[rarp]",  src = 14, dst = 24 },
   ip6  = { id = PROTO_IPV6,  access = "[ip6]",   src =  8, dst = 24 },
}

local function has_proto_dir_host(proto, dir, addr, mask)
   local host = ipv4_to_int(addr)
   local val = { proto_info[proto].access, proto_info[proto][dir], 4 }
   if mask then
      mask = tonumber(mask) and 2^32 - 2^(32 - mask) or ipv4_to_int(mask)
      val = { '&', val, tonumber(mask) }
   end
   return { 'and', has_ether_protocol(proto_info[proto].id), { '=', val, host } }
end

local function expand_ip_src_host(expr)
  return has_proto_dir_host("ip", "src", expr[2], expr[3])
end
local function expand_ip_dst_host(expr)
   return has_proto_dir_host("ip", "dst", expr[2], expr[3])
end
local function expand_ip_host(expr)
   return { 'or', expand_ip_src_host(expr), expand_ip_dst_host(expr) }
end
local function expand_ip_broadcast(expr)
   error("netmask not known, so 'ip broadcast' not supported")
end
local function expand_ip_multicast(expr)
   return { '=', { '[ip]', 16, 1 }, 224 }
end
local function expand_ip6_multicast(expr)
   return { '=', { '[ip6]', 24, 1 }, 255 }
end
local function expand_ip_protochain(expr)
   -- FIXME: Not implemented yet. BPF code of ip protochain is rather complex.
   return unimplemented(expr)
end
local function expand_ip6_protochain(expr)
   -- FIXME: Not implemented yet. BPF code of ip6 protochain is rather complex.
   return unimplemented(expr)
end

local ip_protos = {
   icmp = PROTO_ICMP,
   igmp = PROTO_IGMP,
   igrp = PROTO_IGRP,
   pim  = PROTO_PIM,
   ah   = PROTO_AH,
   esp  = PROTO_ESP,
   vrrp = PROTO_VRRP,
   udp  = PROTO_UDP,
   tcp  = PROTO_TCP,
   sctp = PROTO_SCTP,
}

local function expand_ip_proto(expr, ip_type)
   local proto = ip_protos[expr[2]]
   if ip_type == 'ip' then return has_ipv4_protocol(proto) end
   if ip_type == 'ip6' then return has_ipv6_protocol(proto) end
   return has_ip_protocol(proto)
end

-- ARP protocol

local function expand_arp_src_host(expr)
   return has_proto_dir_host("arp", "src", expr[2], expr[3])
end
local function expand_arp_dst_host(expr)
   return has_proto_dir_host("arp", "dst", expr[2], expr[3])
end
local function expand_arp_host(expr)
   return { 'or', expand_arp_src_host(expr), expand_arp_dst_host(expr) }
end

-- RARP protocol

local function expand_rarp_src_host(expr)
   return has_proto_dir_host("rarp", "src", expr[2], expr[3])
end
local function expand_rarp_dst_host(expr)
   return has_proto_dir_host("rarp", "dst", expr[2], expr[3])
end
local function expand_rarp_host(expr)
   return { 'or', expand_rarp_src_host(expr), expand_rarp_dst_host(expr) }
end

-- IPv6

local function ipv6_dir_host(proto, dir, addr, mask_len)
   mask_len = mask_len or 128
   local offset = proto_info.ip6[dir]
   local ipv6 = ipv6_as_4x32(addr)

   local function match_ipv6_fragment(i)
      local fragment = ipv6[i]

      -- Calculate mask for fragment
      local mask = mask_len >= 32 and 0 or mask_len
      mask_len = mask_len >= 32 and mask_len - 32 or 0

      -- Retrieve address current offset
      local val = { proto_info.ip6.access, offset, 4 }
      offset = offset + 4

      if mask ~= 0 then val = { '&', val, 2^32 - 2^(32 - mask) } end
      return { '=', val, fragment }
   end

   -- Lowering of an IPv6 address does not require to go iterate through all
   -- IPv6 fragments (4x32). Once mask_len becomes 0 is possible to exit.
   local function match_ipv6(i)
      local i = i or 1
      local expr = match_ipv6_fragment(i)
      if mask_len == 0 or i > 4 then return expr end
      return { 'and', expr, match_ipv6(i + 1) }
   end

   return { 'and', has_ether_protocol(PROTO_IPV6), match_ipv6() }
end

local function expand_src_ipv6_host(expr)
   return ipv6_dir_host('ip6', 'src', expr[2], expr[3])
end
local function expand_dst_ipv6_host(expr)
   return ipv6_dir_host('ip6', 'dst', expr[2], expr[3])
end
local function expand_ipv6_host(expr)
   return { 'or',
            ipv6_dir_host('ip6', 'src', expr[2], expr[3]),
            ipv6_dir_host('ip6', 'dst', expr[2], expr[3]) }
end

-- Host

-- Format IPv4 expr: { { 'ipv4', 127, 0, 0, 1 }, 8 }
-- Format IPv6 expr: { { 'ipv6', 0, 0, 0, 0, 0, 0, 0, 1 }, 128 }
local function is_ipv6_addr(expr)
   return expr[2][1] == 'ipv6'
end

local function expand_src_host(expr)
   if is_ipv6_addr(expr) then return expand_src_ipv6_host(expr) end
   return { 'if', { 'ip' }, expand_ip_src_host(expr),
            { 'if', { 'arp' }, expand_arp_src_host(expr),
              expand_rarp_src_host(expr) } }
end
local function expand_dst_host(expr)
   if is_ipv6_addr(expr) then return expand_dst_ipv6_host(expr) end
   return { 'if', { 'ip' }, expand_ip_dst_host(expr),
            { 'if', { 'arp' }, expand_arp_dst_host(expr),
              expand_rarp_dst_host(expr) } }
end
-- Format IPv4: { 'ipv4/len', { 'ipv4', 127, 0, 0, 1 }, 8 }
-- Format IPv4: { 'ipv4/mask', { 'ipv4', 127, 0, 0, 1 }, { 'ipv4', 255, 0, 0, 0 } }
-- Format IPv6: { 'ipv6/len', { 'ipv6', 0, 0, 0, 0, 0, 0, 0, 1 }, 128 }
local function expand_host(expr)
   if is_ipv6_addr(expr) then return expand_ipv6_host(expr) end
   return { 'if', { 'ip' }, expand_ip_host(expr),
            { 'if', { 'arp' }, expand_arp_host(expr),
              expand_rarp_host(expr) } }
end

-- Ether

local function ehost_to_int(addr)
   assert(addr[1] == 'ehost', "Not a valid ehost address")
   return uint16(addr[2], addr[3]), uint32(addr[4], addr[5], addr[6], addr[7])
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
local function expand_ether_broadcast(expr)
   local broadcast = { 'ehost', 255, 255, 255, 255, 255, 255 }
   local hi, lo = ehost_to_int(broadcast)
   return { 'and',
            { '=', { '[ether]', 0, 2 }, hi },
            { '=', { '[ether]', 2, 4 }, lo } }
end
local function expand_ether_multicast(expr)
   return { '!=', { '&', { '[ether]', 0, 1 }, 1 }, 0 }
end

-- Ether protos

local function expand_ip(expr)
   return has_ether_protocol(PROTO_IPV4)
end
local function expand_ip6(expr)
   return has_ether_protocol(PROTO_IPV6)
end
local function expand_arp(expr)
   return has_ether_protocol(PROTO_ARP)
end
local function expand_rarp(expr)
   return has_ether_protocol(PROTO_RARP)
end
local function expand_atalk(expr)
  return { 'or',
           has_ether_protocol(PROTO_ATALK),
           { 'if', { '>', { '[ether]', 12, 2}, 1500 },
             { 'fail' },
             { 'and',
               { '=', { '[ether]', 18, 2 }, 491675 },
               { '=', { '[ether]', 14, 4 }, 2863268616 } } } }
end
local function expand_aarp(expr)
  return { 'or',
           has_ether_protocol(PROTO_AARP),
           { 'if', { '>', { '[ether]', 12, 2}, 1500 },
             { 'fail' },
             { 'and',
               { '=', { '[ether]', 18, 2 }, 33011 },
               { '=', { '[ether]', 14, 4 }, 2863268608 } } } }
end
local function expand_decnet(expr)
   return has_ether_protocol(PROTO_DECNET)
end
local function expand_sca(expr)
   return has_ether_protocol(PROTO_SCA)
end
local function expand_lat(expr)
   return has_ether_protocol(PROTO_LAT)
end
local function expand_mopdl(expr)
   return has_ether_protocol(PROTO_MOPDL)
end
local function expand_moprc(expr)
   return has_ether_protocol(PROTO_MOPRC)
end
local function expand_iso(expr)
   return { 'and',
            { '<=', { '[ether]', 12, 2 }, 1500 },
            { '=', { '[ether]', 14, 2 }, PROTO_ISO } }
end
local function expand_stp(expr)
   return { 'and',
            { '<=', { '[ether]', 12, 2 }, 1500 },
            { '=', { '[ether]', 14, 1 }, PROTO_STP } }
end
local function expand_ipx(expr)
  return { 'or',
           has_ether_protocol(PROTO_IPX),
           { 'if', { '>', { '[ether]', 12, 2}, 1500 },
             { 'fail' },
             { 'or',
               { 'and',
                 { '=', { '[ether]', 18, 2 }, 33079 },
                 { '=', { '[ether]', 14, 4 }, 2863268608 } },
               { 'or',
                 { '=', { '[ether]', 14, 1 }, 224 },
                 { '=', { '[ether]', 14, 2 }, 65535 } } } } }
end
local function expand_netbeui(expr)
   return { 'and',
            { '<=', { '[ether]', 12, 2 }, 1500 },
            { '=', { '[ether]', 14, 2 }, PROTO_NETBEUI } }
end

local ether_protos = {
   ip      = expand_ip,
   ip6     = expand_ip6,
   arp     = expand_arp,
   rarp    = expand_rarp,
   atalk   = expand_atalk,
   aarp    = expand_aarp,
   decnet  = expand_decnet,
   sca     = expand_sca,
   lat     = expand_lat,
   mopdl   = expand_mopdl,
   moprc   = expand_moprc,
   iso     = expand_iso,
   stp     = expand_stp,
   ipx     = expand_ipx,
   netbeui = expand_netbeui,
}

local function expand_ether_proto(expr)
   return ether_protos[expr[2]](expr)
end

-- ISO

local PROTO_CLNP = 129    -- 0x81
local PROTO_ESIS = 130    -- 0x82
local PROTO_ISIS = 131    -- 0x83

local iso_protos = {
   clnp = PROTO_CLNP,
   esis = PROTO_ESIS,
   isis = PROTO_ISIS,
}

local function has_iso_protocol(proto)
  return { 'and',
           { '<=', { '[ether]', 12, 2 }, 1500 },
           { 'and',
             { '=', { '[ether]', 14, 2 }, 65278 },
             { '=', { '[ether]', 17, 1 }, proto } } }
end

local function expand_iso_proto(expr)
   local proto = iso_protos[expr[2]]
   assert(proto, "Invalid ISO protocol")
   return has_iso_protocol(proto)
end

-- Net

local function expand_src_net(expr)
   if is_ipv6_addr(expr[2]) then return expand_src_ipv6_host(expr[2]) end
   return expand_src_host(expr[2])
end
local function expand_dst_net(expr)
   if is_ipv6_addr(expr[2]) then return expand_dst_ipv6_host(expr[2]) end
   return expand_dst_host(expr[2])
end

-- Format IPv4 expr: { 'net', { 'ipv4/len', { 'ipv4', 127, 0, 0, 0 }, 8 } }
-- Format IPV6 expr: { 'net', { 'ipv6/len', { 'ipv6', 0, 0, 0, 0, 0, 0, 0, 1 }, 128 } }
local function expand_net(expr)
   if is_ipv6_addr(expr[2]) then return expand_ipv6_host(expr[2]) end
   return expand_host(expr[2])
end

-- VLAN

-- Each use of 'vlan' expression increments the filter offsets by 4.

-- FIXME: The function is called two times even when there's only one single 'vlan'
-- expression to be evaluated. As the value -- of 'offset' increments in each call,
-- the resulting code is incorrect. The last value of 'offset' is the one used.
local expand_vlan = (function()
  local offset = 8
  local function is_vlan_protocol(offset)
     return { 'or',
              { '=', { '[ether]', offset, 2 }, 33024 },
              { '=', { '[ether]', offset, 2 }, 37120 } }
  end
  return function(expr, dlt)
     offset = offset + 4
     local vlan_id = expr[2]
     if not vlan_id then return is_vlan_protocol(offset) end
     return { 'and',
              is_vlan_protocol(offset),
              { '=', { '&', { '[ether]', offset + 2, 2 }, 4095 }, vlan_id } }
  end
end)()

-- MPLS

local PROTO_MPLS = 34887

-- FIXME:
-- 1. Same problem as VLAN, the code generated is not correct because the
-- function is being called more times than necessary.
-- 2. The first mpls keyword encountered in expression changes the decoding
-- offsets for the remainder of expression on the assumption that the packet is
-- a MPLS-encapsulated IP packet. This means that -- the code generated by
-- following operators may be different based on this asummption. For instance in
-- 'mpls && mpls 1024 && host 192.9.200.1' the code generated -- by host is not
-- the same as 'host 192.9.200.1'.
local expand_mpls = (function()
  local offset = 8
  return function(expr, dlt)
     offset = offset + 4
     local mpls_id = expr[2]
     if not mpls_id then
        if offset == 12 then has_ether_protocol(PROTO_MPLS) end
        return { '=', { '[ether]', offset, 1 }, 0 }
     end
     if offset == 12 and mpls_id then
        return { 'and',
                 has_ether_protocol(PROTO_MPLS),
                 { '=', { '&', { '[ether]', offset + 2, 4 }, 4294963200 }, mpls_id } }
     end
     return { 'and',
              { '=', { '[ether]', offset, 1 }, 0 },
              { '=', { '&', { '[ether]', offset + 2, 4 }, 4294963200 }, mpls_id } }
  end
end)()

-- DECNET

local function expand_decnet_src(expr)
   local addr = expr[2]
   local addr_int = uint16(addr[2], addr[3])
   return { 'if', { '=', { '&', { '[ether]', 16, 1}, 7 }, 2 },
            { '=', { '[ether]', 19, 2}, addr_int },
            { 'if', { '=', { '&', { '[ether]', 16, 2}, 65287 }, 33026 },
              { '=', { '[ether]', 20, 2}, addr_int },
              { 'if', { '=', { '&', { '[ether]', 16, 1}, 7 }, 6 },
                { '=', { '[ether]', 31, 2}, addr_int },
                { 'if', { '=', { '&', { '[ether]', 16, 2}, 65287 }, 33030 },
                  { '=', { '[ether]', 32, 2}, addr_int },
                  { 'fail' } } } } }
end
local function expand_decnet_dst(expr)
   local addr = expr[2]
   local addr_int = uint16(addr[2], addr[3])
   return { 'if', { '=', { '&', { '[ether]', 16, 1}, 7 }, 2 },
            { '=', { '[ether]', 17, 2}, addr_int },
            { 'if', { '=', { '&', { '[ether]', 16, 2}, 65287 }, 33026 },
              { '=', { '[ether]', 18, 2}, addr_int },
              { 'if', { '=', { '&', { '[ether]', 16, 1}, 7 }, 6 },
                { '=', { '[ether]', 23, 2}, addr_int },
                { 'if', { '=', { '&', { '[ether]', 16, 2}, 65287 }, 33030 },
                  { '=', { '[ether]', 24, 2}, addr_int },
                  { 'fail' } } } } }
end
local function expand_decnet_host(expr)
   return { 'or', expand_decnet_src(expr), expand_decnet_dst(expr) }
end

-- IS-IS

local function expand_isis_protocol(...)

   local function concat(lop, reg, values)
      local result = { '=', reg, values[1] }
      if #values == 1 then return result end
      for i = 2, #values do
         result = { 'or', { '=', reg, values[i] }, result }
      end
      return result
   end

   return { 'if', { 'and',
            { '<=', { '[ether]', 12, 2 }, 1500 },
            { 'and',
              { '=', { '[ether]', 14, 2 }, 65278 },
              { '=', { '[ether]', 17, 1, }, 131 } } },
                concat('or', { '[ether]', 21, 1 }, {...} ),
                { 'fail' } }
end

local function expand_l1(expr)
   return expand_isis_protocol(15, 17, 18, 24, 26)
end
local function expand_l2(expr)
   return expand_isis_protocol(16, 17, 20, 25, 27)
end
local function expand_iih(expr)
   return expand_isis_protocol(15, 16, 17)
end
local function expand_lsp(expr)
   return expand_isis_protocol(18, 20)
end
local function expand_snp(expr)
   return expand_isis_protocol(24, 25, 26, 27)
end
local function expand_csnp(expr)
   return expand_isis_protocol(24, 25)
end
local function expand_psnp(expr)
   return expand_isis_protocol(26, 27)
end

-- Packet length

local function expand_less(expr)
   return { '<=', 'len', expr[2] }
end
local function expand_greater(expr)
   return { '>=', 'len', expr[2] }
end

-- PPP

local PROTO_PPPOED = 34915
local PROTO_PPPOES = 34916

-- FIXME: The first pppoes keyword encountered in expression changes the
-- decoding offsets for the remainder of expression on the assumption that the
-- packet is a PPPoE session packet.
local function expand_pppoes(expr)
   local pppoes_id = expr[2]
   if not pppoes_id then return has_ether_protocol(PROTO_PPPOES) end
   return { 'and', has_ether_protocol(PROTO_PPPOES),
            { '=', { '&', { '[ether]', 14, 2 }, 65535 }, pppoes_id } }
end


local primitive_expanders = {
   dst_host = expand_dst_host,
   dst_net = expand_dst_net,
   dst_port = expand_dst_port,
   dst_portrange = expand_dst_portrange,
   src_host = expand_src_host,
   src_net = expand_src_net,
   src_port = expand_src_port,
   src_portrange = expand_src_portrange,
   host = expand_host,
   ether_src = expand_ether_src_host,
   ether_src_host = expand_ether_src_host,
   ether_dst = expand_ether_dst_host,
   ether_dst_host = expand_ether_dst_host,
   ether_host = expand_ether_host,
   ether_broadcast = expand_ether_broadcast,
   broadcast = expand_ether_broadcast,
   ether_multicast = expand_ether_multicast,
   multicast = expand_ether_multicast,
   ether_proto = expand_ether_proto,
   gateway = unimplemented,
   net = expand_net,
   port = expand_port,
   portrange = expand_portrange,
   less = expand_less,
   greater = expand_greater,
   ip = expand_ip,
   ip_proto = function(expr) return expand_ip_proto(expr, 'ip') end,
   ip_protochain = expand_ip_protochain,
   ip_host = expand_ip_host,
   ip_src = expand_ip_src_host,
   ip_src_host = expand_ip_src_host,
   ip_dst = expand_ip_dst_host,
   ip_dst_host = expand_ip_dst_host,
   ip_broadcast = expand_ip_broadcast,
   ip_multicast = expand_ip_multicast,
   ip6 = expand_ip6,
   ip6_proto = function(expr) return expand_ip_proto(expr, 'ip6') end,
   ip6_protochain = expand_ip6_protochain,
   ip6_multicast = expand_ip6_multicast,
   proto = expand_ip_proto,
   tcp = function(expr) return has_ip_protocol(PROTO_TCP) end,
   tcp_port = expand_tcp_port,
   tcp_src_port = expand_tcp_src_port,
   tcp_dst_port = expand_tcp_dst_port,
   tcp_portrange = expand_tcp_portrange,
   tcp_src_portrange = expand_tcp_src_portrange,
   tcp_dst_portrange = expand_tcp_dst_portrange,
   udp = function(expr) return has_ip_protocol(PROTO_UDP) end,
   udp_port = expand_udp_port,
   udp_src_port = expand_udp_src_port,
   udp_dst_port = expand_udp_dst_port,
   udp_portrange = expand_udp_portrange,
   udp_src_portrange = expand_udp_src_portrange,
   udp_dst_portrange = expand_udp_dst_portrange,
   icmp = function(expr) return has_ip_protocol(PROTO_ICMP) end,
   igmp = function(expr) return has_ip_protocol(PROTO_IGMP) end,
   igrp = function(expr) return has_ip_protocol(PROTO_IGRP) end,
   pim = function(expr) return has_ip_protocol(PROTO_PIM) end,
   ah = function(expr) return has_ip_protocol(PROTO_AH) end,
   esp = function(expr) return has_ip_protocol(PROTO_ESP) end,
   vrrp = function(expr) return has_ip_protocol(PROTO_VRRP) end,
   protochain = expand_ip_protochain,
   arp = expand_arp,
   arp_host = expand_arp_host,
   arp_src = expand_arp_src_host,
   arp_src_host = expand_arp_src_host,
   arp_dst = expand_arp_dst_host,
   arp_dst_host = expand_arp_dst_host,
   rarp = expand_rarp,
   rarp_host = expand_rarp_host,
   rarp_src = expand_rarp_src_host,
   rarp_src_host = expand_rarp_src_host,
   rarp_dst = expand_rarp_dst_host,
   rarp_dst_host = expand_rarp_dst_host,
   atalk = expand_atalk,
   aarp = expand_aarp,
   decnet = expand_decnet,
   decnet_src = expand_decnet_src,
   decnet_src_host = expand_decnet_src,
   decnet_dst = expand_decnet_dst,
   decnet_dst_host = expand_decnet_dst,
   decnet_host = expand_decnet_host,
   iso = expand_iso,
   stp = expand_stp,
   ipx = expand_ipx,
   netbeui = expand_netbeui,
   sca = expand_sca,
   lat = expand_lat,
   moprc = expand_moprc,
   mopdl = expand_mopdl,
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
   vlan = expand_vlan,
   mpls = expand_mpls,
   pppoed = function(expr) return has_ether_protocol(PROTO_PPPOED) end,
   pppoes = expand_pppoes,
   iso_proto = expand_iso_proto,
   clnp = function(expr) return has_iso_protocol(PROTO_CLNP) end,
   esis = function(expr) return has_iso_protocol(PROTO_ESIS) end,
   isis = function(expr) return has_iso_protocol(PROTO_ISIS) end,
   l1 = expand_l1,
   l2 = expand_l2,
   iih = expand_iih,
   lsp = expand_lsp,
   snp = expand_snp,
   csnp = expand_csnp,
   psnp = expand_psnp,
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
   '+', '-', '*', '/', '&', '|', '^', '&&', '||', '<<', '>>'
)
local associative_binops = set(
   '+', '*', '&', '|', '^'
)
local bitops = set('&', '|', '^')
local unops = set('ntohs', 'ntohl', 'uint32')
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
      return concat(assert_expr(has_ether_protocol(proto)),
                    assert_expr(has_ether_protocol_min_payload(proto)))
   end
   function assert_ipv4_protocol(proto)
      return concat(assert_expr(has_ipv4_protocol(proto)),
                    assert_expr(has_ipv4_protocol_min_payload(proto)))
   end
   function assert_ipv6_protocol(proto)
      return concat(assert_expr(has_ipv6_protocol(proto)),
                    assert_expr(has_ipv6_protocol_min_payload(proto)))
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
   elseif level == 'ether*' then
      return 14, {}
   elseif level == 'arp' then
      return 14, assert_ether_protocol(PROTO_ARP)
   elseif level == 'rarp' then
      return 14, assert_ether_protocol(PROTO_RARP)
   elseif level == 'ip' then
      return 14, assert_ether_protocol(PROTO_IPV4)
   elseif level == 'ip6' then
      return 14, assert_ether_protocol(PROTO_IPV6)
   elseif level == 'ip*' then
      return ipv4_payload_offset()
   elseif level == 'ip6*' then
      return ipv6_payload_offset()
   elseif level == 'icmp' then
      return ipv4_payload_offset(PROTO_ICMP)
   elseif level == 'udp' then
      return ipv4_payload_offset(PROTO_UDP)
   elseif level == 'tcp' then
      return ipv4_payload_offset(PROTO_TCP)
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
      local ret = { 'uint32', { op, lhs, rhs } }
      local assertions = concat(lhs_assertions, rhs_assertions)
      -- RHS of division can't be 0.
      if op == '/' then
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
   if size == 4 then return { 'uint32', { 'ntohl', ret } }, asserts end
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
      return { 'if', expand_bool(expr[2], dlt), { 'false' }, { 'true' } }
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
