#!/usr/bin/env luajit
-- -*- lua -*-
module(..., package.seeall)
local pflang_math = require("pflang_math")

function property()
   arithmetic_expr = table.concat(pflang_math.PflangArithmetic(), ' ')
   local tcpdump_result = pflang_math.tcpdump_eval(arithmetic_expr)
   local pflua_result = pflang_math.pflua_eval(arithmetic_expr)
   return tcpdump_result, pflua_result
end

function print_extra_information()
   print(("The arithmetic expression was %s"):format(arithmetic_expr))
end
