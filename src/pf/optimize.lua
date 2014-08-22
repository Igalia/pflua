module(...,package.seeall)

local bit = require('bit')
local utils = require('pf.utils')

verbose = os.getenv("PF_VERBOSE");

local expand_arith, expand_relop, expand_bool

local set, concat, dup, pp = utils.set, utils.concat, utils.dup, utils.pp

local relops = set('<', '<=', '=', '!=', '>=', '>')

local binops = set(
   '+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>'
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

local function memoize(f)
   local cache = { }
   return cache, function (arg)
      local result = cache[arg]
      if result == nil then
         result = f(arg)
         cache[arg] = result
      end
      return result
   end
end

local cfkey_cache, cfkey

cfkey_cache, cfkey = memoize(function (expr)
   if type(expr) == 'table' then
      local ret = 'table('..cfkey(expr[1])
      for i=2,#expr do ret = ret..' '..cfkey(expr[i]) end
      return ret..')'
   else
      return type(expr)..'('..tostring(expr)..')'
   end
end)

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

local simplify_if

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
      local test, t, f = simplify(expr[2]), simplify(expr[3]), simplify(expr[4])
      return simplify_if(test, t, f)
   else
      local res = { op }
      for i=2,#expr do table.insert(res, simplify(expr[i])) end
      return res
   end
end

function simplify_if(test, t, f)
   local op = test[1]
   if op == 'not' then return simplify_if(test[2], f, t)
   elseif op == 'true' then return t
   elseif op == 'false' then return f
   elseif op == 'fail' then return test
   elseif t[1] == 'true' and f[1] == 'false' then return test
   -- FIXME: Memoize cfkey to avoid O(n^2) badness.
   elseif op == 'if' then
      if test[3][1] == 'fail' then
         -- if (if A fail B) C D -> if A fail (if B C D)
         return simplify_if(test[2], {'fail'}, simplify_if(test[4], t, f))
      elseif test[4][1] == 'fail' then
         -- if (if A B fail) C D -> if A (if B C D) fail
         return simplify_if(test[2], simplify_if(test[3], t, f), {'fail'})
      elseif t[1] == 'if' and cfkey(test[2]) == cfkey(t[2]) then
         if f[1] == 'if' and cfkey(test[2]) == cfkey(f[2]) then
            -- if (if A B C) (if A D E) (if A F G)
            -- -> if A (if B D F) (if C E G)
            return simplify_if(test[2],
                               simplify_if(test[3], t[3], f[3]),
                               simplify_if(test[4], t[4], f[4]))
         elseif simple[f[1]] then
            -- if (if A B C) (if A D E) F
            -- -> if A (if B D F) (if C E F)
            return simplify_if(test[2],
                               simplify_if(test[3], t[3], f),
                               simplify_if(test[4], t[4], f))
         end
      elseif (f[1] == 'if' and cfkey(test[2]) == cfkey(f[2])
              and simple[t[1]]) then
         -- if (if A B C) D (if A E F)
         -- -> if A (if B D E) (if C D F)
         return simplify_if(test[2],
                            simplify_if(test[3], t, f[3]),
                            simplify_if(test[4], t, f[4]))
      end
   end
   return { 'if', test, t, f }
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
         local db_kt = expr[4][1] == 'fail' and db or dup(db)
         local db_kf = expr[3][1] == 'fail' and db or dup(db)
         db_kt[key] = true
         db_kf[key] = false
         return { op, test, cfold(expr[3], db_kt), cfold(expr[4], db_kf) }
      end
   else
      return expr
   end
end

-- Range inference.
local function Range(min, max)
   -- if min is less than max, we have unreachable code.  still, let's
   -- not violate assumptions (e.g. about wacky bitshift semantics)
   if min > max then min, max = min, min end
   local ret = { min_ = min, max_ = max }
   function ret:min() return self.min_ end
   function ret:max() return self.max_ end
   function ret:range() return self:min(), self:max() end
   function ret:fold()
      if self:min() == self:max() then return self:min() end
   end
   function ret:lt(other) return self:max() < other:min() end
   function ret:gt(other) return self:min() > other:max() end
   function ret:crosses(val) return self:min() < val and self:max() > val end
   function ret:union(other)
      return Range(math.min(self:min(), other:min()),
                   math.max(self:max(), other:max()))
   end
   function ret:restrict(other)
      return Range(math.max(self:min(), other:min()),
                   math.min(self:max(), other:max()))
   end
   function ret.binary(lhs, rhs, op) -- for monotonic functions
      local fold = assert(folders[op])
      local a = fold(lhs:min(), rhs:min())
      local b = fold(lhs:min(), rhs:max())
      local c = fold(lhs:max(), rhs:max())
      local d = fold(lhs:max(), rhs:min())
      return Range(math.min(a, b, c, d), math.max(a, b, c, d))
   end
   function ret.add(lhs, rhs) return lhs:binary(rhs, '+') end
   function ret.sub(lhs, rhs) return lhs:binary(rhs, '-') end
   function ret.mul(lhs, rhs) return lhs:binary(rhs, '*') end
   function ret.div(lhs, rhs)
      if not rhs:crosses(0) then return lhs:binary(rhs, '/') end
      -- 0 is prohibited by assertions.
      local low, high = Range(rhs:min(), -1), Range(1, rhs:max())
      return lhs:binary(low, '/'):union(lhs:binary(high, '/'))
   end
   function ret.mod(lhs, rhs)
      if rhs:min() > 0 then return lhs:restrict(Range(0, rhs:max() - 1)) end
      if rhs:max() < 0 then return lhs:restrict(Range(rhs:min() + 1, 0)) end
      return lhs:restrict(Range(rhs:min() + 1, rhs:max() - 1))
   end
   function ret.band(lhs, rhs)
      if lhs:min() < 0 and rhs:min() < 0 then return Range(-2^31, 2^31-1) end
      return Range(0, math.min(lhs:max(), rhs:max()))
   end
   function ret.bor(lhs, rhs)
      local function saturate(x)
         local y = 1
         while y < x do y = y * 2 end
         return y - 1
      end
      if lhs:min() < 0 or rhs:min() < 0 then return Range(-2^31, -1) end
      return Range(bit.bor(lhs:min(), rhs:min()),
                   saturate(bit.bor(lhs:max(), rhs:max())))
   end
   function ret.bxor(lhs, rhs) return lhs:bor(rhs) end
   function ret.lshift(lhs, rhs)
      local function npot(x) -- next power of two
         if x >= 2^31 then return 32 end
         local n, i = 1, 1
         while n < x do n, i = n * 2, i + 1 end
         return i
      end
      if lhs:min() >= 0 then
         local min_lhs, max_lhs = lhs:min(), lhs:max()
         -- It's nuts, but lshift does an implicit modulo on the RHS.
         local min_shift, max_shift = 0, 31
         if rhs:min() >= 0 and rhs:max() < 32 then
            min_shift, max_shift = rhs:min(), rhs:max()
         end
         if npot(max_lhs) + max_shift < 32 then
            assert(bit.lshift(max_lhs, max_shift) > 0)
            return Range(bit.lshift(min_lhs, min_shift),
                         bit.lshift(max_lhs, max_shift))
         end
      end
      return Range(-2^31, 2^31-1)
   end
   function ret.rshift(lhs, rhs)
      local min_lhs, max_lhs = lhs:min(), lhs:max()
      -- Same comments wrt modulo of shift.
         local min_shift, max_shift = 0, 31
      if rhs:min() >= 0 and rhs:max() < 32 then
         min_shift, max_shift = rhs:min(), rhs:max()
      end
      if min_shift > 0 then
         -- If we rshift by 1 or more, result will not be negative.
         if min_lhs >= 0 and max_lhs < 2^32 then
            return Range(bit.rshift(min_lhs, max_shift),
                         bit.rshift(max_lhs, min_shift))
         else
            -- -1 is "all bits set".
            return Range(bit.rshift(-1, max_shift),
                         bit.rshift(-1, min_shift))
         end
      elseif min_lhs >= 0 and max_lhs < 2^31 then
         -- Left-hand-side in [0, 2^31): result not negative.
         return Range(bit.rshift(min_lhs, max_shift),
                      bit.rshift(max_lhs, min_shift))
      else
         -- Otherwise punt.
         return Range(-2^31, 2^31-1)
      end
   end
   return ret
end

local function infer_ranges(expr)
   local Inf = 1/0
   local function cons(car, cdr) return { car, cdr } end
   local function car(pair) return pair[1] end
   local function cdr(pair) return pair[2] end
   local function cadr(pair) return car(cdr(pair)) end
   local function push(db)
      return cons({}, db)
   end
   local function lookup(db, expr)
      if type(expr) == 'number' then return Range(expr, expr) end
      local key = cfkey(expr)
      while db do
         local range = car(db)[key]
         if range then return range end
         db = cdr(db)
      end
      return Range(-Inf, Inf)
   end
   local function define(db, expr, range)
      if range:fold() then return range:min() end
      car(db)[cfkey(expr)] = range
      return expr
   end
   local function restrict(db, expr, range)
      return define(db, expr, lookup(db, expr):restrict(range))
   end
   local function merge(db, head)
      for key, range in pairs(head) do car(db)[key] = range end
   end
   local function union(db, h1, h2)
      for key, range1 in pairs(h1) do
         local range2 = h2[key]
         if h2[key] then car(db)[key] = range1:union(range2) end
      end
   end

   local function eta(expr, kt, kf)
      if expr[1] == 'true' then return kt end
      if expr[1] == 'false' then return kf end
      if expr[1] == 'fail' then return 'REJECT' end
      return nil
   end

   -- Returns lhs false range, lhs true range, rhs false range, rhs true range
   local function branch_ranges(op, lhs, rhs)
      local function lt(a, b)
         return Range(a:min(), math.min(a:max(), b:max() - 1))
      end
      local function le(a, b)
         return Range(a:min(), math.min(a:max(), b:max()))
      end
      local function eq(a, b)
         return Range(math.max(a:min()), math.min(a:max(), b:max()))
      end
      local function ge(a, b)
         return Range(math.max(a:min(), b:min()), a:max())
      end
      local function gt(a, b)
         return Range(math.max(a:min(), b:min()+1), a:max())
      end
      if op == '<' then
         return lt(lhs, rhs), ge(lhs, rhs), gt(rhs, lhs), le(rhs, lhs)
      elseif op == '<=' then
         return le(lhs, rhs), gt(lhs, rhs), ge(rhs, lhs), lt(rhs, lhs)
      elseif op == '=' then
         -- Could restrict false continuations more.
         return eq(lhs, rhs), lhs, eq(rhs, lhs), rhs
      elseif op == '!=' then
         return lhs, eq(lhs, rhs), rhs, eq(rhs, lhs)
      elseif op == '>=' then
         return ge(lhs, rhs), lt(lhs, rhs), le(rhs, lhs), gt(rhs, lhs)
      elseif op == '>' then
         return gt(lhs, rhs), le(lhs, rhs), lt(rhs, lhs), ge(rhs, lhs)
      else
         error('unimplemented '..op)
      end
   end
   local function unop_range(op, rhs)
      if op == 'ntohs' then return Range(0, 0xffff) end
      if op == 'ntohl' then return Range(-2^31, 2^31-1) end
      error('unexpected op '..op)
   end
   local function binop_range(op, lhs, rhs)
      if op == '+' then return lhs:add(rhs) end
      if op == '-' then return lhs:sub(rhs) end
      if op == '*' then return lhs:mul(rhs) end
      if op == '/' then return lhs:div(rhs) end
      if op == '%' then return lhs:mod(rhs) end
      if op == '&' then return lhs:band(rhs) end
      if op == '|' then return lhs:bor(rhs) end
      if op == '^' then return lhs:bxor(rhs) end
      if op == '<<' then return lhs:lshift(rhs) end
      if op == '>>' then return lhs:rshift(rhs) end
      error('unexpected op '..op)
   end

   local function visit(expr, db_t, db_f, kt, kf)
      if type(expr) ~= 'table' then return expr end
      local op = expr[1]

      -- Logical ops add to their db_t and db_f stores.
      if relops[op] then
         local db = push(db_t)
         local lhs, rhs = visit(expr[2], db), visit(expr[3], db)
         merge(db_t, car(db))
         merge(db_f, car(db))
         local function fold(l, r)
            return { assert(folders[op])(l, r) and 'true' or 'false' }
         end
         local lhs_range, rhs_range = lookup(db_t, lhs), lookup(db_t, rhs)
         -- If we folded both sides, or if the ranges are strictly
         -- ordered, the condition will fold.
         if ((lhs_range:fold() and rhs_range:fold())
             or lhs_range:lt(rhs_range) or lhs_range:gt(rhs_range)) then
            return fold(lhs_range:min(), rhs_range:min())
         end
         -- Otherwise, the relop may restrict the ranges for both
         -- arguments along both continuations.
         local lhs_range_t, lhs_range_f, rhs_range_t, rhs_range_f =
            branch_ranges(op, lhs_range, rhs_range)
         restrict(db_t, lhs, lhs_range_t)
         restrict(db_f, lhs, lhs_range_f)
         restrict(db_t, rhs, rhs_range_t)
         restrict(db_f, rhs, rhs_range_f)
         return { op, lhs, rhs }
      elseif op == 'false' or op == 'true' or op == 'fail' then
         return expr
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
         -- An arithmetic op, which interns into the fresh table pushed
         -- by the containing relop.
         local db = db_t
         if op == '[]' then
            local pos, size = visit(expr[2], db), expr[3]
            local ret = { op, pos, size }
            local size_max
            if size == 1 then size_max = 0xff
            elseif size == 2 then size_max = 0xffff
            else size_max = 0xffffffff end
            local range = lookup(db, ret):restrict(Range(0, size_max))
            return define(db, ret, range)
         elseif unops[op] then
            local rhs = visit(expr[2], db)
            if type(rhs) == 'number' then return assert(folders[op])(rhs) end
            local range = unop_range(op, lookup(db, rhs))
            return restrict(db, { op, rhs }, range)
         elseif binops[op] then
            local lhs, rhs = visit(expr[2], db), visit(expr[3], db)
            if type(lhs) == 'number' and type(rhs) == 'number' then
               return assert(folders[op])(lhs, rhs)
            end
            local lhs_range, rhs_range = lookup(db, lhs), lookup(db, rhs)
            -- As a special case, remove % if it is unneeded.
            if op == '%' then
               local rhs_val = rhs_range:fold()
               if rhs_val and rhs_val > 0 then
                  if lhs_range:min() >= 0 and lhs_range:max() < rhs_val then
                     return lhs
                  end
                  -- could do strength reduction here if rhs is power of 2
               end
            end
            local range = binop_range(op, lhs_range, rhs_range)
            return restrict(db, { op, lhs, rhs }, range)
         else
            error('what is this '..op)
         end
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

function fixpoint(f, expr)
   local prev
   repeat expr, prev = f(expr), expr until utils.equals(expr, prev)
   return expr
end

function optimize_inner(expr)
   expr = simplify(expr)
   expr = simplify(cfold(expr, {}))
   expr = simplify(infer_ranges(expr))
   expr = simplify(lhoist(expr))
   cfkey_cache = { }
   return expr
end

function optimize(expr)
   expr = fixpoint(optimize_inner, expr)
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
   opt("tcp port 5555")
   print("OK")
end
