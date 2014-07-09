module(...,package.seeall)

-- stubs
local function set() end

local punctuation = set(
   '(', ')', '[', ']', '!', '!=', '<', '<=', '>', '>=', '=',
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||', '<<', '>>'
)

local addressables = set(
   'arp', 'rarp', 'wlan', 'ether', 'fddi', 'tr', 'ppp',
   'slip', 'link', 'radio', 'ip', 'ip6', 'tcp', 'udp', 'icmp'
)

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

local function function_builder(...)
   local written = 'return function('
   local vcount = 0
   local lcount = 0
   local indent = '   '
   local jumps = {}
   local function write(str)
      written = written .. str
   end
   local function writeln(str)
      write(indent .. str .. '\n')
   end
   local function v(str)
      vcount = vcount + 1
      writeln('local v'..vcount..' = '..str)
   end
   local function label()
      lcount = lcount + 1
      return 'L'..lcount
   end
   local function jump(label)
      if label == 'ACCEPT' then return 'return true' end
      if label == 'REJECT' then return 'return false' end
      jumps[label] = true
      return 'goto '..label
   end
   local function test(cond, kt, kf, k)
      if kt == k then
         writeln('if not '..comp..' then '..jump(kf)..' end')
         writeln('if not '..comp..' then '..jump(kf)..' end')
      else
         writeln('if '..comp..' then '..jump(kt)..' end')
         if kf ~= k then builder.writeln('do '..jump(kf)..' end') end
      end
   end
   local function writelabel(label)
      if jumps[label] then write('::'..label..'::\n') end
   end
   local function finish(str)
      write('end')
      return written
   end
   local needs_comma = false
   for _, v in ipairs({...}) do
      if needs_comma then write(',') end
      write(v)
      needs_comma = true
   end
   write(')\n')
   return { write = write, writeln = writeln,
            v = v, label = label, test = test, writelabel = writelabel,
            finish = finish }
end

local function unimplemented(builder, expr)
   error("not implemented: "..expr.type)
end

local primitive_codegens = {
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
   port = unimplemented,
   portrange = unimplemented,
   less = unimplemented,
   greater = unimplemented,
   ip = unimplemented,
   ip_proto = unimplemented,
   ip_protochain = unimplemented,
   ip_broadcast = unimplemented,
   ip_multicast = unimplemented,
   ip6 = unimplemented,
   ip6_proto = unimplemented,
   ip6_protochain = unimplemented,
   ip6_multicast = unimplemented,
   proto = unimplemented,
   tcp = unimplemented,
   udp = unimplemented,
   icmp = unimplemented,
   protochain = unimplemented,
   arp = unimplemented,
   rarp = unimplemented,
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

local relop_map = {
   ['<']='<', ['<=']='<=', ['=']='==', ['!=']='~=', ['>=']='>=', ['>']='>'
}

local function compile_bool(builder, expr, kt, kf, k)
   assert(type(expr) == 'table', 'logical expression must be a table')
   if expr.type == 'not' or expr.type == '!' then
      return compile_bool(builder, expr[1], kf, kt, k)
   elseif expr.type == 'and' or expr.type == '&&' then
      local knext = builder.label()
      compile_bool(builder, expr[0], knext, kf, knext)
      builder.writelabel(knext)
      compile_bool(builder, expr[1], kt, kf, k)
   elseif expr.type == 'or' or expr.type == '||' then
      local knext = builder.label()
      compile_bool(builder, expr[0], kt, knext, knext)
      builder.writelabel(knext)
      compile_bool(builder, expr[1], kt, kf, k)
   elseif relop_map[expr.type] then
      -- An arithmetic relop.
      local op = relop_map[expr.type]
      local lhs = compile_value(builder, expr[0])
      local rhs = compile_value(builder, expr[1])
      local comp = lhs..' '..op..' '..rhs
      builder.test(comp, kt, kf, k)
   else
      -- A logical primitive.
      local codegen = primitive_codegens[expr.type]
      assert(codegen, "unimplemented code generator: "..expr.type)
      codegen(builder, expr, kt, kf, k)
   end
end

function compile_lua(parsed)
   local builder = function_builder('P')
   compile_bool(builder, parsed, 'ACCEPT', 'REJECT')
   return builder.finish()
end

function compile(parsed)
   return assert(loadstring(compile_lua(parsed), 'generated.lua'))()
end

function selftest ()
   print("selftest: pf.codegen")
   local parse = require('pf.parse').parse
   -- print(compile_lua(parse("ip")))
   print("OK")
end
