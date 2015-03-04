#!/usr/bin/env luajit
-- -*- lua -*-
-- This module generates (a subset of) pflang, libpcap's filter language

module(..., package.seeall)
local choose = require("pf.utils").choose

local ProtocolName, PortNumber, Port, PortRange

function ProtocolName()
   return { choose({ "ip", "tcp", "udp" }) }
end

function PortNumber()
   return math.random(1, 2^16 - 1)
end

function Port()
   return { "port", PortNumber() }
end

function PortRange()
   return { "portrange", PortNumber() .. '-' .. PortNumber() }
end

function Pflang()
   return choose({ ProtocolName, Port, PortRange })()
end
