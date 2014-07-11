module("pf",package.seeall)

local savefile = require("pf.savefile")
local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")
local parse = require('pf.parse')
local expand = require('pf.expand')
local codegen = require('pf.codegen')

function compile_pcap_filter(filter_str, dlt_name)
   local bpf_prog = bpf.compile(libpcap.compile(filter_str, dlt_name))
   return function(P, len) return bpf_prog(P, len) ~= 0 end
end

function compile_pcap_filter2(filter_str, dlt_name)
   local expr = parse.parse(filter_str)
   expr = expand.expand(expr, dlt_name)
   return codegen.compile(expr)
end

function filter_count(pred, file)
   local total_pkt = 0
   local count = 0
   local records = savefile.records_mm(file)
   while true do
      local pkt, hdr = records()
      if not pkt then break end
      total_pkt = total_pkt + 1
      local length = hdr.incl_len
      if pred(pkt, length) then
         count = count + 1
      end
   end
   return count, total_pkt
end

function selftest ()
   print("selftest: pf")
   
   local function test_null(str)
      local f = compile_pcap_filter(str)
      local f2 = compile_pcap_filter2(str, "EN10MB")
      assert(f(str, 0) == false, "null packet should be rejected")
      assert(f2(str, 0) == false, "null packet should be rejected2")
   end
   test_null("icmp")
   test_null("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

   local function assert_count(filter, file, expected, dlt)
      local pred2 = compile_pcap_filter2(filter, dlt)
      local pred = compile_pcap_filter(filter, dlt)
      local actual = filter_count(pred, file)
      assert(actual == expected, 'got ' .. actual .. ', expected ' .. expected)
      actual = filter_count(pred2, file)
      assert(actual == expected, 'got ' .. actual .. ', expected ' .. expected)
   end
   assert_count('', "ts/pcaps/ws/v4.pcap", 43, "EN10MB")
   assert_count('ip', "ts/pcaps/ws/v4.pcap", 43, "EN10MB")
   assert_count('tcp', "ts/pcaps/ws/v4.pcap", 41, "EN10MB")
   assert_count('tcp port 80', "ts/pcaps/ws/v4.pcap", 41, "EN10MB")

   print("OK")
end
