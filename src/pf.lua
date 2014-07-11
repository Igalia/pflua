module("pf",package.seeall)

local savefile = require("pf.savefile")
local types = require("pf.types")
local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")
local parse = require('pf.parse')
local expand = require('pf.expand')
local codegen = require('pf.codegen')

function compile_filter(filter_str, opts)
   local opts = opts or {}
   local dlt = opts.dlt or "EN10MB"
   if opts.pcap_offline_filter then
      local bytecode = libpcap.compile(filter_str, dlt)
      return function(P, len)
         local header = types.pcap_record(0, 0, len, len)
         return libpcap.offline_filter(bytecode, header, P) ~= 0
      end
   elseif opts.bpf then
      local bytecode = libpcap.compile(filter_str, dlt)
      local bpf_prog = bpf.compile(bytecode)
      return function(P, len) return bpf_prog(P, len) ~= 0 end
   else
      local expr = parse.parse(filter_str)
      expr = expand.expand(expr, dlt)
      return codegen.compile(expr)
   end
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
      local f1 = compile_filter(str, { libpcap = true })
      local f2 = compile_filter(str, { bpf = true })
      local f3 = compile_filter(str, { bpf = false })
      assert(f1(str, 0) == false, "null packet should be rejected (libpcap)")
      assert(f2(str, 0) == false, "null packet should be rejected (bpf)")
      assert(f3(str, 0) == false, "null packet should be rejected (pflua)")
   end
   test_null("icmp")
   test_null("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

   local function assert_count(filter, file, expected)
      local f1 = compile_filter(filter, { libpcap = true })
      local f2 = compile_filter(filter, { bpf = true })
      local f3 = compile_filter(filter, { bpf = false })
      local actual
      actual = filter_count(f1, file)
      assert(actual == expected,
             'libpcap: got ' .. actual .. ', expected ' .. expected)
      actual = filter_count(f2, file)
      assert(actual == expected,
             'bpf: got ' .. actual .. ', expected ' .. expected)
      actual = filter_count(f3, file)
      assert(actual == expected,
             'pflua: got ' .. actual .. ', expected ' .. expected)
   end
   assert_count('', "ts/pcaps/ws/v4.pcap", 43)
   assert_count('ip', "ts/pcaps/ws/v4.pcap", 43)
   assert_count('tcp', "ts/pcaps/ws/v4.pcap", 41)
   assert_count('tcp port 80', "ts/pcaps/ws/v4.pcap", 41)

   print("OK")
end
