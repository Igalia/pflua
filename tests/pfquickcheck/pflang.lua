#!/usr/bin/env luajit
-- -*- lua -*-
-- This module generates (a subset of) pflang, libpcap's filter language

module(..., package.seeall)
local choose = require("pf.utils").choose

local ProtocolName

function ProtocolName()
   return choose({ "ip", "tcp", "udp" })
end

function Pflang()
   return choose({ ProtocolName })()
end
