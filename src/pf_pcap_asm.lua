--[[
--
-- This module is used to obtain the resulting jitted asm code for a pcap
-- expression.
--
-- The file used for packet filtering is a 1GB file from pflua-bench, so it's
-- necessary to clone that repo, uncompress the file and create a symbolic link:
--
--  $ git clone https://github.com/Igalia/pflua-bench.git
--  $ pflua-bench=<path-to-pflua-bench>
--  $ pflua=<path-to-pflua>
--  $ unxz $pflua-bench/src/ts/pcaps/igalia/one-gigabyte.xz
--  $ ln -fs $pflua-bench/src/ts/pcaps/igalia/one-gigabyte.xz
--      $pflua/src/ts/pcaps/igalia/one-gigabyte.pcap
--
--]]

module("pf_pcap_asm", package.seeall)

local savefile = require("pf.savefile")
local libpcap = require("pf.libpcap")
local buffer = require("pf.buffer")
local bpf = require("pf.bpf")

-- Compiles pcap expression
function compile_pcap_filter(filter_str, dlt_name)
   return bpf.compile(libpcap.compile(filter_str, dlt_name))
end

-- Counts number of packets within file
function filter_count(pred, file)
   local total_pkt = 0
   local count = 0
   local records = savefile.records_mm(file)

   while true do
      local pkt, hdr = records()
      if not pkt then break end

      local length = hdr.incl_len
      local packet = buffer.from_uchar(pkt, length)
      execute_pred_ensuring_trace(pred, packet, length)
   end
   return count, total_pkt
end

-- Executing pred within a function ensures a trace for this call
function execute_pred_ensuring_trace(pred, packet, length)
    pred(packet, length)
end

-- Calls func() during seconds
function call_during_seconds(seconds, func, pred, file)
    local time = os.time
    local finish = time() + seconds
    while (true) do
        func(pred, file)
        if (time() > finish) then break end
    end
end

function selftest(filter)
   print("selftest: pf_pcap_asm")

   local file = "ts/pcaps/igalia/one-gigabyte.pcap"
   if (filter == nil or filter == '') then
      filter = "tcp port 80"
   end
   local dlt = "EN10MB"

   local pred = compile_pcap_filter(filter, dlt)
   call_during_seconds(1, filter_count, pred, file)

   print("OK")
end
