#!/usr/bin/env luajit
-- -*- lua -*-
module(..., package.seeall)
package.path = package.path .. ";../?.lua;../../src/?.lua"
-- A or not A should always be true
-- B and not B should always be false.

local pf = require("pf")
local savefile = require("pf.savefile")
local utils = require('pf.utils')

local pflang = require('pfquickcheck.pflang')

local function exclude_middle(expr)
   r = math.random()
   local op, expected, em
   if r < 0.5 then
      op = 'or'
      expected = true
   else
     op = 'and'
     expected = false
   end
   em = utils.dup(expr)
   table.insert(em, op)
   table.insert(em, 'not')
   em = utils.concat(em, expr)
   return em, expected
end

function property(packets)
   --nil pkt_idx, pflang_expr, bpf_result, pflua_result to avoid
   -- confusing debug information
   pkt_idx, pflang_expr, pflua_result, expected, opt = nil
   opt = true
   if math.random() < 0.5 then opt = false end
   local pkt, P, pkt_len, a, pflua_pred

   a = pflang.PflangClause()
   a, expected = exclude_middle(a)
   pflang_expr = table.concat(a, ' ')
   pkt, pkt_idx = utils.choose_with_index(packets)
   P, pkt_len = pkt.packet, pkt.len
   pflua_pred = pf.compile_filter(pflang_expr)
   pflua_result = pflua_pred(P, pkt_len)
   return expected, pflua_result
end

function print_extra_information()
   print(("The pflang expression was %s and the packet number %s"):
         format(pflang_expr, pkt_idx))
   local optimization = "optimization on"
   if not opt then optimization = "optimization off" end
   print(("expected %s, pure-lua: %s, %s"):format(expected, pflua_result,
                                                  optimization))
end

function handle_prop_args(prop_args)
   if #prop_args ~= 1 then
      print("Usage: (pflua-quickcheck [args] properties/excluded_middle)"
            .. " PATH/TO/CAPTURE.PCAP")
      os.exit(1)
   end

   local capture = prop_args[1]
   return savefile.load_packets(capture)
end
