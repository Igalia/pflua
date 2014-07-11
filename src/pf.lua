module("pf",package.seeall)

local ffi = require("ffi")
local savefile = require("pf.savefile")
local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")

function compile_pcap_filter(filter_str, dlt_name)
   return bpf.compile(libpcap.compile(filter_str, dlt_name))
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
      local packet = ffi.cast("uint8_t*", pkt) 
      if pred(packet, length) ~= 0 then
         count = count + 1
      end
   end
   return count, total_pkt
end

function selftest ()
   print("selftest: pf")
   
   local function test_null(str)
      local f = compile_pcap_filter(str)
      assert(f(ffi.cast("uint8_t*", str), 0) == 0, "null packet should be rejected")
   end
   test_null("icmp")
   test_null("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

   local function assert_count(filter, file, expected, dlt)
      local pred = compile_pcap_filter(filter, dlt)
      local actual = filter_count(pred, file)
      assert(actual == expected, 'got ' .. actual .. ', expected ' .. expected)
   end
   assert_count('', "ts/pcaps/ws/v4.pcap", 43, "EN10MB")
   assert_count('ip', "ts/pcaps/ws/v4.pcap", 43, "EN10MB")
   assert_count('tcp', "ts/pcaps/ws/v4.pcap", 41, "EN10MB")
   assert_count('tcp port 80', "ts/pcaps/ws/v4.pcap", 41, "EN10MB")

   print("OK")
end
