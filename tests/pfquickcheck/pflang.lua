#!/usr/bin/env luajit
-- -*- lua -*-
-- This module generates (a subset of) pflang, libpcap's filter language

module(..., package.seeall)
local choose = require("pf.utils").choose

local function IPProtocol()
   return choose({ "icmp", "icmp6", "igmp", "igrp", "pim", "ah", "esp", "vrrp",
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

local function PortNumber()
   return math.random(1, 2^16 - 1)
end

local function Port()
   return { "port", PortNumber() }
end

local function PortRange()
   local port1, port2 = PortNumber(), PortNumber()
   -- work around bug 129
   if port1 > port2 then port1, port2 = port2, port1 end
   return { "portrange", port1 .. '-' .. port2 }
end

local function ProtocolWithPort()
   protocol = choose({ "tcp", "udp" })
   return { protocol, "port", PortNumber() }
end

local function PflangClause()
   return choose({ ProtocolName, Port, PortRange, ProtocolWithPort })()
end

-- Add logical operators (and/or/not)
function PflangLogical()
   local r = math.random()
   local pclause = PflangClause()
   local pclause2 = PflangClause()

   if r < 0.9 then
      local logicOp = 'and'
      if r < 0.45 then logicOp = 'or' end

      table.insert(pclause, logicOp)
      for _,v in ipairs(pclause2) do table.insert(pclause, v) end
      return pclause
   else
      table.insert(pclause, 1, "not")
      return pclause
   end
end

function Pflang()
   return choose({ PflangClause, PflangLogical })()
end
