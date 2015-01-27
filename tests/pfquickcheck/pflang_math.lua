#!/usr/bin/env luajit
module(..., package.seeall)
package.path = package.path .. ";../../src/?.lua"

local io = require("io")
local codegen = require("pf.backend")
local expand = require("pf.expand")
local parse = require("pf.parse")
local pfcompile = require("pfcompile")

-- Generate pflang arithmetic
local PflangNumber, PflangSmallNumber, PflangOp
function PflangNumber() return math.random(0, 2^32-1) end
-- TODO: remove PflangSmallNumber; it's a workaround to avoid triggering
-- https://github.com/Igalia/pflua/issues/83 (float and integer muls diverge)
function PflangSmallNumber() return math.random(0, 2^17) end
function PflangOp() return utils.choose({ '+', '-', '*', '/' }) end
function PflangArithmetic()
   return { PflangNumber(), PflangOp(), PflangSmallNumber() }
end

-- Evaluate math expressions with tcpdump and pflang's IR

-- Pflang allows arithmetic as part of larger expressions.
-- This tool uses len < arbitrary_arithmetic_here as a scaffold

-- Here is a truncated example of the tcpdump output that is parsed
--tcpdump -d "len < -4 / 2"
--(000) ld       #pktlen
--(001) jge      #0x7ffffffe      jt 2    jf 3

function tcpdump_eval(str_expr)
   local expr = "len < " .. str_expr
   local cmdline = ('tcpdump -d "%s"'):format(expr)
   local bpf = io.popen(cmdline):read("*all")
   local res = string.match(bpf, "#(0x%x+)")
   return tonumber(res)
end

-- Here is an example of the pflua output that is parsed
--return function(P,length)
--   return length < ((519317859 + 63231) % 4294967296)
--end

-- Old style:
-- return function(P,length)
--    local v1 = 3204555350 * 122882
--    local v2 = v1 % 4294967296
--    do return length < v2 end
-- end

function pflua_eval(str_expr)
   local expr = "len < " .. str_expr
   local ir = expand.expand(parse.parse(expr))
   local filter = pfcompile.compile_lua_ast(ir, "Arithmetic check")
   -- Old style:
   --  local math_string = string.match(filter, "v1 = [%d-+/*()%a. ]*")
   local math_str = string.match(filter, "return length < ([%d%a %%-+/*()]*)")
   math_str = "v1 = " .. math_str
   -- Loadstring has a different env, so floor doesn't resolve; use math.floor
   math_str = math_str:gsub('floor', 'math.floor')
   v1 = nil
   loadstring(math_str)() -- v1 must not be local, or this approach will fail
   -- v1 should always be within [0..2^32-1]
   assert(v1 >= 0)
   assert (v1 < 2^32)
   assert(v1 == math.floor(v1))
   return v1
end
