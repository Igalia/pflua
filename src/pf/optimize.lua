module(...,package.seeall)

local bit = require('bit')
local utils = require('pf.utils')

verbose = os.getenv("PF_VERBOSE");

local expand_arith, expand_relop, expand_bool

local set, concat, dup, pp = utils.set, utils.concat, utils.dup, utils.pp

local relops = set('<', '<=', '=', '!=', '>=', '>')

local binops = set(
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||', '<<', '>>'
)
local associative_binops = set(
   '+', '*', '&', '|', '^'
)
local bitops = set('&', '|', '^')
local unops = set('ntohs', 'ntohl')

local folders = {
   ['+'] = function(a, b) return a + b end,
   ['-'] = function(a, b) return a - b end,
   ['*'] = function(a, b) return a * b end,
   ['/'] = function(a, b) return math.floor(a / b) end,
   ['%'] = function(a, b) return a % b end,
   ['&'] = function(a, b) return bit.band(a, b) end,
   ['^'] = function(a, b) return bit.bxor(a, b) end,
   ['|'] = function(a, b) return bit.bor(a, b) end,
   ['<<'] = function(a, b) return bit.lshift(a, b) end,
   ['>>'] = function(a, b) return bit.rshift(a, b) end,
   ['ntohs'] = function(a) return bit.rshift(bit.bswap(a), 16) end,
   ['ntohl'] = function(a) return bit.bswap(a) end,
   ['='] = function(a, b) return a == b end,
   ['!='] = function(a, b) return a ~= b end,
   ['<'] = function(a, b) return a < b end,
   ['<='] = function(a, b) return a <= b end,
   ['>='] = function(a, b) return a >= b end,
   ['>'] = function(a, b) return a > b end
}

local function cfkey(expr)
   if type(expr) == 'table' then
      local ret = 'table('..cfkey(expr[1])
      for i=2,#expr do ret = ret..' '..cfkey(expr[i]) end
      return ret..')'
   else
      return type(expr)..'('..tostring(expr)..')'
   end
end

local simple = set('true', 'false', 'fail')

function try_invert(expr, relop)
   local op = expr[1]
   if unops[op] and (relop == '=' or relop == '!=') then
      return assert(folders[op]), expr[2]
   elseif bitops[op] and (relop == '=' or relop == '!=') then
      local lhs, rhs = expr[2], expr[3]
      if type(lhs) == 'number' and unops[rhs[1]] then
         local fold =  assert(folders[rhs[1]])
         return fold, { op, fold(lhs), rhs[2] }
      elseif type(rhs) == 'number' and unops[lhs[1]] then
         local fold =  assert(folders[lhs[1]])
         return fold, { op, lhs[2], fold(rhs) }
      end
   end
end

local function simplify(expr)
   if type(expr) ~= 'table' then return expr end
   local op = expr[1]
   if binops[op] then
      local lhs = simplify(expr[2])
      local rhs = simplify(expr[3])
      if type(lhs) == 'number' and type(rhs) == 'number' then
         return assert(folders[op])(lhs, rhs)
      elseif associative_binops[op] then
         if type(rhs) == 'table' and rhs[1] == op and type(lhs) == 'number' then
            lhs, rhs = rhs, lhs
         end
         if type(lhs) == 'table' and lhs[1] == op and type(rhs) == 'number' then
            if type(lhs[2]) == 'number' then
               return { op, assert(folders[op])(lhs[2], rhs), lhs[3] }
            elseif type(lhs[3]) == 'number' then
               return { op, lhs[2], assert(folders[op])(lhs[3], rhs) }
            end
         end
      end
      return { op, lhs, rhs }
   elseif unops[op] then
      local rhs = simplify(expr[2])
      if type(rhs) == 'number' then return assert(folders[op])(rhs) end
      return { op, rhs }
   elseif relops[op] then
      local lhs = simplify(expr[2])
      local rhs = simplify(expr[3])
      if type(lhs) == 'number' then
         if type(rhs) == 'number' then
            return { assert(folders[op])(lhs, rhs) and 'true' or 'false' }
         end
         invert_lhs, inverted_rhs = try_invert(rhs, op)
         if invert_lhs then lhs, rhs = invert_lhs(lhs), inverted_rhs end
      elseif type(rhs) == 'number' then
         invert_rhs, inverted_lhs = try_invert(lhs, op)
         if invert_rhs then lhs, rhs = inverted_lhs, invert_rhs(rhs) end
      end
      return { op, lhs, rhs }
   elseif op == 'not' then
      local rhs = simplify(expr[2])
      if rhs[1] == 'true' then return { 'false' }
      elseif rhs[1] == 'false' then return { 'true' }
      else return { op, rhs } end
   elseif op == 'if' then
      local test = simplify(expr[2])
      local kt = simplify(expr[3])
      local kf = simplify(expr[4])
      if test[1] == 'true' then return kt
      elseif test[1] == 'false' then return kf
      elseif test[1] == 'fail' then return test
      elseif test[1] == 'not' then return simplify({op, test[2], kf, kt })
      elseif kt[1] == 'true' and kf[1] == 'false' then return test
      -- FIXME: Memoize cfkey to avoid O(n^2) badness.
      elseif test[1] == 'if' then
         if test[3][1] == 'fail' then
            -- if (if A fail B) C D -> if A fail (if B C D)
            return simplify({op, test[2], {'fail'}, {op, test[4], kt, kf}})
         elseif test[4][1] == 'fail' then
            -- if (if A B fail) C D -> if A (if B C D) fail
            return simplify({op, test[2], {op, test[3], kt, kf}, {'fail'}})
         elseif kt[1] == 'if' and cfkey(test[2]) == cfkey(kt[2]) then
            if kf[1] == 'if' and cfkey(test[2]) == cfkey(kf[2]) then
               -- if (if A B C) (if A D E) (if A F G)
               -- -> if A (if B D F) (if C E G)
               return simplify({ 'if', test[2],
                                 { 'if', test[3], kt[3], kf[3] },
                                 { 'if', test[4], kt[4], kf[4] } })
            elseif simple[kf[1]] then
               -- if (if A B C) (if A D E) F
               -- -> if A (if B D F) (if C E F)
               return simplify({ 'if', test[2],
                                 simplify({ 'if', test[3], kt[3], kf }),
                                 simplify({ 'if', test[4], kt[4], kf }) })
            end
         elseif (kf[1] == 'if' and cfkey(test[2]) == cfkey(kf[2])
                 and simple[kt[1]]) then
            -- if (if A B C) D (if A E F)
            -- -> if A (if B D E) (if C D F)
            return simplify({ 'if', test[2],
                              { 'if', test[3], kt, kf[3] },
                              { 'if', test[4], kt, kf[4] } })
         end
      end
      return { op, test, kt, kf }
   else
      local res = { op }
      for i=2,#expr do table.insert(res, simplify(expr[i])) end
      return res
   end
end

-- Conditional folding.
local function cfold(expr, db)
   if type(expr) ~= 'table' then return expr end
   local op = expr[1]
   if binops[op] then return expr
   elseif unops[op] then return expr
   elseif relops[op] then
      local key = cfkey(expr)
      if db[key] ~= nil then
         return { db[key] and 'true' or 'false' }
      else
         return expr
      end
   elseif op == 'not' then
      local rhs = cfold(expr[2], db)
      local key = cfkey(rhs)
      if db[key] ~= nil then return { db[key] and 'false' or 'true' }
      elseif rhs[1] == 'true' then return { 'false' }
      elseif rhs[1] == 'false' then return { 'true' }
      else return { op, rhs } end
   elseif op == 'if' then
      local test = cfold(expr[2], db)
      local key = cfkey(test)
      if db[key] ~= nil then
         if db[key] then return cfold(expr[3], db) end
         return cfold(expr[4], db)
      else
         local db_kt = dup(db)
         local db_kf = dup(db)
         db_kt[key] = true
         db_kf[key] = false
         return { op, test, cfold(expr[3], db_kt), cfold(expr[4], db_kf) }
      end
   else
      return expr
   end
end

-- Range inference.
local function infer_ranges(expr)
   local function cons(car, cdr) return { car, cdr } end
   local function car(pair) return pair[1] end
   local function cdr(pair) return pair[2] end
   local function cadr(pair) return car(cdr(pair)) end
   local function push(db)
      return cons({ len={}, [1]={}, [2]={}, [4]={} }, db)
   end
   local function lookup(db, pos, size)
      while db do
         local pair = car(db)[size][cfkey(pos)]
         if pair then return pair[1], pair[2] end
         db = cdr(db)
      end
      if size == 1 then return 0, 0xff end
      if size == 2 then return 0, 0xffff end
      assert(size == 4)
      return 0, 0xffffffff
   end
   local function intern(db, pos, size, min, max)
      car(db)[size][cfkey(pos)] = { min, max }
   end
   local function merge(db, head)
      for size, tab in pairs(head) do
         for key, pair in pairs(tab) do
            car(db)[size][key] = pair
         end
      end
   end
   local function union(db, h1, h2)
      for size, tab in pairs(h1) do
         for key, pair in pairs(tab) do
            local min2, max2 = h2[size][key]
            if min2 then
               local min1, max1 = pair
               car(db)[size][key] = { math.min(min1, min2), math.ax(max1, max2) }
            end
         end
      end
   end

   local function eta(expr, kt, kf)
      if expr[1] == 'true' then return kt end
      if expr[1] == 'false' then return kf end
      if expr[1] == 'fail' then return 'REJECT' end
      return nil
   end

   local function restrict_range(min, max, op, val)
      if op == '<=' then
         return min, math.min(max, val), math.max(min, val + 1), max
      elseif op == '=' then
         return val, val, min, max
      elseif op == '~=' then
         return min, max, val, val
      else
         print('implement me', op)
         return min, max, min, max
      end
   end

   local function visit(expr, db_t, db_f, kt, kf)
      if type(expr) ~= 'table' then return expr end
      local op = expr[1]

      -- Arithmetic ops just use the store for lookup, so we can just
      -- use db_t and not worry about continuations.
      if op == '[]' then
         local pos, size = visit(expr[2], db_t), expr[3]
         local min, max = lookup(db_t, pos, size)
         if min == max then return min end
         return { op, pos, size }
      elseif unops[op] then
         local rhs = visit(expr[2], db_t)
         if type(rhs) == 'number' then
            return assert(folders[op])(rhs)
         end
         return { op, rhs }
      elseif binops[op] then
         local lhs, rhs = visit(expr[2], db_t), visit(expr[3], db_t)
         if type(lhs) == 'number' and type(rhs) == 'number' then
            return assert(folders[op])(lhs, rhs)
         end
         return { op, lhs, rhs }
      end

      -- Logical ops add to their db_t and db_f stores.
      if relops[op] then
         local lhs, rhs = visit(expr[2], db_t), visit(expr[3], db_t)
         if type(lhs) == 'number' and type(rhs) == 'number' then
            return { assert(folders[op])(lhs, rhs) and 'true' or 'false' }
         end
         if (type(lhs) == 'table' and lhs[1] == '[]'
             and type(rhs) == 'number') then
             local pos, size, val = lhs[2], lhs[3], rhs
             local min, max = lookup(db_t, pos, size)
             -- TODO: fold
             min_t, max_t, min_f, max_f = restrict_range(min, max, op, val)
             intern(db_t, pos, size, min_t, max_t)
             intern(db_f, pos, size, min_f, max_f)
         end
         return { op, lhs, rhs }
      elseif op == 'not' then
         return { op, visit(expr[2], db_f, db_t, kf, kt) }
      elseif op == 'if' then
         local test, t, f = expr[2], expr[3], expr[4]

         local test_db_t, test_db_f = push(db_t), push(db_t)
         local test_kt, test_kf = eta(t, kt, kf), eta(f, kt, kf)
         test = visit(test, test_db_t, test_db_f, test_kt, test_kf)

         local kt_db_t, kt_db_f = push(test_db_t), push(test_db_t)
         local kf_db_t, kf_db_f = push(test_db_f), push(test_db_f)
         t = visit(t, kt_db_t, kt_db_f, kt, kf)
         f = visit(f, kf_db_t, kf_db_f, kt, kf)

         if test_kt == 'fail' then
            local head_t, head_f = car(kf_db_t), car(kf_db_f)
            local assertions = cadr(kf_db_t)
            merge(db_t, assertions)
            merge(db_t, head_t)
            merge(db_f, assertions)
            merge(db_f, head_f)
         elseif test_kf == 'fail' then
            local head_t, head_f = car(kt_db_t), car(kt_db_f)
            local assertions = cadr(kt_db_t)
            merge(db_t, assertions)
            merge(db_t, head_t)
            merge(db_f, assertions)
            merge(db_f, head_f)
         else
            local head_t_t, head_t_f = car(kt_db_t), car(kt_db_f)
            local head_f_t, head_f_f = car(kf_db_t), car(kf_db_f)
            union(db_t, head_t_t, head_f_t)
            union(db_f, head_t_f, head_f_f)
         end
         return { op, test, t, f }
      else
         return expr
      end
   end
   return visit(expr, push(), push(), 'ACCEPT', 'REJECT')
end

-- Length assertion hoisting.
local function lhoist(expr, db)
   local function eta(expr, kt, kf)
      if expr[1] == 'true' then return kt end
      if expr[1] == 'false' then return kf end
      if expr[1] == 'fail' then return 'REJECT' end
      return nil
   end
   local function annotate(expr, kt, kf)
      local op = expr[1]
      if (op == '<=' and kf == 'REJECT'
          and type(expr[2]) == 'number' and expr[3] == 'len') then
         return { expr[2], expr }
      elseif op == 'if' then
         local test, t, f = expr[2], expr[3], expr[4]
         local test_a = annotate(test, eta(t, kt, kf), eta(f, kt, kf))
         local t_a, f_a =  annotate(t, kt, kf), annotate(f, kt, kf)
         local rhs_min
         if eta(t, kt, kf) == 'REJECT' then rhs_min = f_a[1]
         elseif eta(f, kt, kf) == 'REJECT' then rhs_min = t_a[1]
         else rhs_min = math.min(t_a[1], f_a[1]) end
         return { math.max(test_a[1], rhs_min), { op, test_a, t_a, f_a } }
      else
         return { 0, expr }
      end
   end

   local function reduce(aexpr, min)
      if min < aexpr[1] then
         return { 'if', { '<=', aexpr[1], 'len' },
                  reduce(aexpr, aexpr[1]),
                  { 'fail' } }
      end
      local expr = aexpr[2]
      local op = expr[1]
      if op == 'if' then
         local t, kt, kf =
            reduce(expr[2], min), reduce(expr[3], min), reduce(expr[4], min)
         if t[1] == '<=' and type(t[2]) == 'number' and t[3] == 'len' then
            if t[2] <= min then return kt else return kf end
         end
         return { op, t, kt, kf }
      else
         return expr
      end
   end
      
   return reduce(annotate(expr, 'ACCEPT', 'REJECT'), 0)
end

function optimize(expr)
   expr = simplify(expr)
   expr = simplify(cfold(expr, {}))
   expr = simplify(infer_ranges(expr))
   expr = simplify(lhoist(expr))
   if verbose then pp(expr) end
   return expr
end

function selftest ()
   print("selftest: pf.optimize")
   local parse = require('pf.parse').parse
   local expand = require('pf.expand').expand
   local function opt(str) return optimize(expand(parse(str), "EN10MB")) end
   local equals, assert_equals = utils.equals, utils.assert_equals
   assert_equals({ 'false' },
      opt("1 = 2"))
   assert_equals({ '=', 1, "len" },
      opt("1 = len"))
   assert_equals({ 'if', { '<=', 1, 'len'},
                   { '=', { '[]', 0, 1 }, 2 },
                   { 'fail' }},
      opt("ether[0] = 2"))
   -- Could check this, but it's very large
   opt("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")
   print("OK")
end
