#!/usr/bin/env luajit
-- -*- lua -*-
-- This module generates (a subset of) pflang, libpcap's filter language

-- Convention: initial uppercase letter => generates pflang expression
-- initial lowercase letter => aux helper

module(..., package.seeall)
local choose = require("pf.utils").choose

local function Empty() return { "" } end

-- Given something like { 'host', '127.0.0.1' }, make it sometimes
-- start with src or dst. This should only be called on expressions
-- which can start with src or dst!
local function srcdstify(expr)
   local r = math.random()
   if r < 1/3 then table.insert(expr, 1, "src")
   elseif r < 2/3 then table.insert(expr, 1, "dst")
   end -- else: leave it unchanged
   return expr
end

local function IPProtocol()
   -- Comment out icmp6 temporarily, due to bug 132
   return choose({ "icmp", "igmp", "igrp", "pim", "ah", "esp", "vrrp",
                    "udp", "tcp" })
   -- Ignore sctp, because "keyword elision not implemented sctp"
end

-- These are parsed seperately from IPProtocol values in pflua; does it make
-- sense to mainain this separation?
local function MoreProtocols()
   return choose({ "ip", "arp", "rarp", "ip6" })
end

local function ProtocolName()
   return { choose({ IPProtocol, MoreProtocols })() }
end

local function portNumber()
   return math.random(1, 2^16 - 1)
end

local function Port()
   return { "port", portNumber() }
end

local function PortRange()
   local port1, port2 = portNumber(), portNumber()
   -- work around bug 129
   if port1 > port2 then port1, port2 = port2, port1 end
   return { "portrange", port1 .. '-' .. port2 }
end

local function ProtocolWithPort()
   protocol = choose({ "tcp", "udp" })
   return { protocol, "port", portNumber() }
end

local function octet() return math.random(0, 255) end

local function ipv4Addr()
   return table.concat({ octet(), octet(), octet(), octet() }, '.')
end

local function Host()
   return srcdstify({ 'host', ipv4Addr() })
end

local function netmask() return math.random(0, 32) end

-- This function is overly conservative with zeroing octets.
-- TODO: zero more precisely? It's trickier than it looks; tcpdump says
-- 10.0.0.0/6 isn't ok ('non-network bits set'), but 10.0.0.0/7 is!
function netspec()
   local mask = netmask()
   local o1, o2, o3, o4 = octet(), octet(), octet(), octet()
   if mask < 32 then o4 = 0 end
   if mask < 24 then o3 = 0 end
   if mask < 16 then o2 = 0 end
   if mask < 8 then o1 = 0 end
   local addr = table.concat({ o1, o2, o3, o4 }, '.')
   return addr .. '/' .. mask
end

function Net()
   return srcdstify({ 'net', netspec() })
end

local function PflangClause()
   return choose({ Empty, ProtocolName, Port, PortRange, ProtocolWithPort,
                   Host, Net })()
end

-- Add logical operators (or/not)
-- Do not test 'and', because it fails fast on the BPF pipeline for some
-- cases that match no packets. (Bug 130)
function PflangLogical()
   local r = math.random()
   local pclause = PflangClause()
   local pclause2 = PflangClause()

   if r < 0.9 then
      local logicOp = 'or'

      table.insert(pclause, logicOp)
      for _,v in ipairs(pclause2) do table.insert(pclause, v) end
      return pclause
   else
      table.insert(pclause, 1, "not")
      return pclause
   end
end

function Pflang()
   -- Work around bugs 131 and 132
   --return choose({ PflangClause, PflangLogical })()
   return PflangClause()
end
