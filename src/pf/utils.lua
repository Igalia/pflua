module(...,package.seeall)

local ffi = require("ffi")

ffi.cdef[[
typedef long time_t;
typedef long suseconds_t;
struct timeval {
  time_t      tv_sec;     /* seconds */
  suseconds_t tv_usec;    /* microseconds */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);
]]

local zero_sec, zero_usec

function now()
   local tv = ffi.new("struct timeval")
   assert(ffi.C.gettimeofday(tv, nil) == 0)
   if not zero_sec then
      zero_sec = tv.tv_sec
      zero_usec = tv.tv_usec
   end
   local secs = tonumber(tv.tv_sec - zero_sec)
   secs = secs + tonumber(tv.tv_usec - zero_usec) * 1e-6
   return secs
end

function set(...)
   local ret = {}
   for k, v in pairs({...}) do ret[v] = true end
   return ret
end

function concat(a, b)
   local ret = {}
   for _, v in ipairs(a) do table.insert(ret, v) end
   for _, v in ipairs(b) do table.insert(ret, v) end
   return ret
end

function dup(table)
   local ret = {}
   for k, v in pairs(table) do ret[k] = v end
   return ret
end

function equals(expected, actual)
   if type(expected) ~= type(actual) then return false end
   if type(expected) == 'table' then
      for k, v in pairs(expected) do
         if not equals(v, actual[k]) then return false end
      end
      for k, _ in pairs(actual) do
         if expected[k] == nil then return false end
      end
      return true
   else
      return expected == actual
   end
end

function pp(expr, indent, suffix)
   indent = indent or ''
   suffix = suffix or ''
   if type(expr) == 'number' then
      print(indent..expr..suffix)
   elseif type(expr) == 'string' then
      print(indent..'"'..expr..'"'..suffix)
   elseif type(expr) == 'boolean' then
      print(indent..(expr and 'true' or 'false')..suffix)
   elseif type(expr) == 'table' then
      if #expr == 1 then
         print(indent..'{ "'..expr[1]..'" }'..suffix)
      else
         print(indent..'{ "'..expr[1]..'",')
         indent = indent..'  '
         for i=2,#expr-1 do pp(expr[i], indent, ',') end
         pp(expr[#expr], indent, ' }'..suffix)
      end
   else
      error("unsupported type "..type(expr))
   end
   return expr
end

function assert_equals(expected, actual)
   if not equals(expected, actual) then
      pp(expected)
      pp(actual)
      error('not equal')
   end
end

function selftest ()
   print("selftest: pf.utils")
   local tab = { 1, 2, 3 }
   assert(tab ~= dup(tab))
   assert_equals(tab, dup(tab))
   assert_equals({ 1, 2, 3, 1, 2, 3 }, concat(tab, tab))
   assert_equals(set(3, 2, 1), set(1, 2, 3))
   print("OK")
end
