module(...,package.seeall)

local utils = require('pf.utils')

local set, pp, dup = utils.set, utils.pp, utils.dup

local relops = set('<', '<=', '=', '!=', '>=', '>')

local binops = set(
   '+', '-', '*', '/', '&', '|', '^', '<<', '>>'
)
local unops = set('ntohs', 'ntohl', 'uint32', 'int32')

local count = 0

local function fresh()
   count = count + 1
   return 'var'..count
end

local function lower_arith(expr, k)
   if type(expr) ~= 'table' then return k(expr) end
   local op = expr[1]
   if unops[op] then
      local operand = expr[2]
      local function have_operand(operand)
         local result = fresh()
         return { 'let', result, { op, operand }, k(result) }
      end
      return lower_arith(operand, have_operand)
   elseif binops[op] then
      local lhs, rhs = expr[2], expr[3]
      local function have_lhs(lhs)
         local function have_rhs(rhs)
            local result = fresh()
            return { 'let', result, { op, lhs, rhs}, k(result) }
         end
         return lower_arith(rhs, have_rhs)
      end
      return lower_arith(lhs, have_lhs)
   else
      assert(op == '[]')
      local operand, size = expr[2], expr[3]
      local function have_operand(operand)
         local result = fresh()
         return { 'let', result, { op, operand, size }, k(result) }
      end
      return lower_arith(operand, have_operand)
   end
end

local function lower_comparison(expr, k)
   local op, lhs, rhs = expr[1], expr[2], expr[3]
   assert(relops[op])
   local function have_lhs(lhs)
      local function have_rhs(rhs)
         return k({ op, lhs, rhs })
      end
      return lower_arith(rhs, have_rhs)
   end
   return lower_arith(lhs, have_lhs)
end

local function lower_bool(expr, k)
   local function lower(expr)
      local function have_bool(expr)
         return expr
      end
      return lower_bool(expr, have_bool)
   end
   local op = expr[1]
   if (op == 'if') then
      local test, t, f = expr[2], expr[3], expr[4]
      local function have_test(test)
         return k({ 'if', test, lower(t), lower(f) })
      end
      return lower_bool(test, have_test)
   elseif op == 'true' or op == 'false' or op == 'fail' then
      return k(expr)
   else
      return lower_comparison(expr, k)
   end
end

function lower(expr)
   count = 0
   local function have_bool(expr)
      return expr
   end
   return lower_bool(expr, have_bool)
end

local function cse(expr)
   local replacements = {}
   local function lookup(expr)
      return replacements[expr] or expr 
   end
   local function visit(expr, env)
      if type(expr) == 'number' then return expr end
      if type(expr) == 'string' then return lookup(expr) end
      local op = expr[1]
      if op == 'let' then
         local var, val, body = expr[2], expr[3], expr[4]
         assert(type(val) == 'table')
         local arith_op = val[1]
         local key, replacement_val
         if unops[arith_op] then
            local lhs = visit(val[2], env)
            key = arith_op..','..lhs
            replacement_val = { arith_op, lhs }
         elseif binops[arith_op] then
            local lhs, rhs = visit(val[2], env), visit(val[3], env)
            key = arith_op..','..lhs..','..rhs
            replacement_val = { arith_op, lhs, rhs }
         else
            assert(arith_op == '[]')
            local lhs, size = visit(val[2], env), val[3]
            key = arith_op..','..lhs..','..size
            replacement_val = { arith_op, lhs, size }
         end
         local cse_var = env[key]
         if cse_var then
            replacements[var] = cse_var
            return visit(body, env)
         else
            env = dup(env)
            env[key] = var
            return { 'let', var, replacement_val, visit(body, env) }
         end
      elseif op == 'if' then
         return { 'if', visit(expr[2], env), visit(expr[3], env), visit(expr[4], env) }
      elseif op == 'true' or op == 'false' or op == 'fail' then
         return expr
      else
         assert(relops[op])
         return { op, visit(expr[2], env), visit(expr[3], env) }
      end
   end
   return visit(expr, {})
end

local function inline_single_use_variables(expr)
   local counts, substs = {}, {}
   local function count(expr)
      if expr == 'len' then return
      elseif type(expr) == 'number' then return
      elseif type(expr) == 'string' then counts[expr] = counts[expr] + 1 
      else
         assert(type(expr) == 'table')
         local op = expr[1]
         if op == 'if' then
            count(expr[2])
            count(expr[3])
            count(expr[4])
         elseif op == 'let' then
            counts[expr[2]] = 0
            count(expr[3])
            count(expr[4])
         elseif relops[op] then
            count(expr[2])
            count(expr[3])
         elseif unops[op] then
            count(expr[2])
         elseif binops[op] then
            count(expr[2])
            count(expr[3])
         elseif op == 'true' or op == 'false' or op == 'fail' then

         else 
            assert(op == '[]')
            count(expr[2])
         end
      end
   end
   local function lookup(expr)
      return substs[expr] or expr
   end
   local function subst(expr) 
      if type(expr) == 'number' then return expr end
      if type(expr) == 'string' then return lookup(expr) end
      local op = expr[1]
      if op == 'let' then
         local var, val, body = expr[2], expr[3], expr[4]
         assert(type(val) == 'table')
         local arith_op = val[1]
         local replacement_val
         if unops[arith_op] then
            local lhs = subst(val[2])
            replacement_val = { arith_op, lhs }
         elseif binops[arith_op] then
            local lhs, rhs = subst(val[2]), subst(val[3])
            replacement_val = { arith_op, lhs, rhs }
         else
            assert(arith_op == '[]')
            local lhs, size = subst(val[2]), val[3]
            replacement_val = { arith_op, lhs, size }
         end
         if counts[var] == 1 then
            substs[var] = replacement_val
            return subst(body)
         else
            return { 'let', var, replacement_val, subst(body) }
         end
      elseif op == 'if' then
         return { 'if', subst(expr[2]), subst(expr[3]), subst(expr[4]) }
      elseif op == 'true' or op == 'false' or op == 'fail' then
         return expr
      else
         assert(relops[op])
         return { op, subst(expr[2]), subst(expr[3]) }
      end
   end
   count(expr)
   return subst(expr)
end

local function codegen(expr)
   local function do_return(stmt) return { 'do', { 'return', stmt } } end
   local k_values = { ACCEPT='true', REJECT='false' }
   local label_counter = 0
   local function fresh_label()
      label_counter = label_counter + 1
      return 'L'..label_counter
   end
   local function compile(expr, kt, kf)
      assert(type(expr) == 'table')
      local op = expr[1]
      if op == 'if' then
         local function eta_reduce(expr)
            if expr[1] == 'false' then return kf, false
            elseif expr[1] == 'true' then return kt, false
            elseif expr[1] == 'fail' then return 'REJECT', false
            else return fresh_label(), true end
         end
         local test, t, f = expr[2], expr[3], expr[4]
         local test_kt, fresh_kt = eta_reduce(t)
         local test_kf, fresh_kf = eta_reduce(f)

         local result = { 'do', compile(test, test_kt, test_kf) }
         if fresh_kt then
            table.insert(result, { 'label', test_kt, compile(t, kt, kf) })
         end
         if fresh_kf then
            table.insert(result, { 'label', test_kf, compile(f, kt, kf) })
         end
         return result
      elseif op == 'let' then
         local var, val, body = expr[2], expr[3], expr[4]
         return { 'do', { 'bind', var, val }, compile(body, kt, kf) }
      elseif op == 'true' then
         if (kt == 'ACCEPT') then return do_return({ 'true' }) end
         if (kt == 'REJECT') then return do_return({ 'false' }) end
         return { 'goto', kt }
      elseif op == 'false' then
         if (kf == 'ACCEPT') then return do_return({ 'true' }) end
         if (kf == 'REJECT') then return do_return({ 'false' }) end
         return { 'goto', kf }
      elseif op == 'fail' then
         return do_return({ 'false' })
      else
         assert(relops[op])
         local kt_value, kf_value = k_values[kt], k_values[kf]
         if kt_value == 'true' and kf_value == 'false' then
            return do_return(expr)
         elseif kt_value == 'false' and kf_value == 'true' then
            return do_return({ 'not', expr })
         elseif kt_value then
            assert(kt_value ~= kf_value) -- can we get here?
            return { 'do',
                     { 'if', expr, { 'return', kt_value } },
                     { 'goto', kf } }
         elseif kf_value then
            return { 'do',
                     { 'if', { 'not', expr }, { 'return', kf_value } },
                     { 'goto', kt } }
         else
            return { 'do',
                     { 'if', expr, { 'goto', kt } },
                     { 'goto', kf } }
         end
      end
   end
   return compile(expr, 'ACCEPT', 'REJECT')
end

local function reduce(expr, is_last)
   local op = expr[1]
   if op == 'do' then
      if #expr == 2 then
         local first_op = expr[2][1]
         assert(first_op ~= 'bind')
         if first_op ~= 'return' or is_last then
            return reduce(expr[2], is_last)
         end
      end
      local result = { 'do' }
      for i=2,#expr do
         local is_last = i==#expr
         local subexpr = reduce(expr[i], is_last)
         local function can_inline_do(subexpr, is_last)
            for j=2,#subexpr do
               if subexpr[j][1] == 'bind' then return false end
            end
            return is_last or subexpr[#subexpr][1] ~= 'return'
         end
         if subexpr[1] == 'do' and can_inline_do(subexpr, is_last) then
            for j=2,#subexpr do table.insert(result, subexpr[j]) end
         else
            table.insert(result, subexpr)
         end
      end
      return result
   elseif op == 'goto' then
      return expr
   elseif op == 'label' then
      return { 'label', expr[2], reduce(expr[3], is_last) }
   elseif op == 'if' then
      return { 'if', expr[2], reduce(expr[3], is_last) }
   elseif op == 'return' then
      return expr
   else
      assert(op == 'bind')
      return expr
   end
end

-- do expressions are necessary when they can be jumped over or through, or for return.
--
-- if foo then goto L1; var v2 = bar; return v2 < 34; L1: qux
--

-- Transformations on the codegen-level language:
--
-- 1. Removal of useless do expressions:
--    do goto foo end
--
-- 2. Removal of useless do for returns:
--    if foo then do return true end end
--
-- 3. Removal of useless nested do blocks:
--    do qux; do foo; bar end; baz; end
--
-- 4. Removal of useless goto immediately followed by label:
--    goto L1; L1: foo
--
-- 5. Removal of labels that are never used:
--    L1: foo
--
-- 6. Label forwarding:
--    goto L1; ...; L1: goto L2


function selftest()
   local expr = { 'if', { '<', { '+', 3, 4 }, { '+', 7, 8 } },
                  { '<', 'len', 42 },
                  { 'false' } }
   local expr2 = { 'if', { '<', { '+', 3, 4 }, { '+', 3, 4 } },
                  { 'true' },
                  { 'false' } }
   pp(lower(expr))
   pp(cse(lower(expr)))
   pp(cse(lower(expr2)))
   pp(inline_single_use_variables(cse(lower(expr))))
   pp(inline_single_use_variables(cse(lower(expr2))))
   pp(codegen(inline_single_use_variables(cse(lower(expr)))))
   pp(codegen(inline_single_use_variables(cse(lower(expr2)))))
   pp(reduce(codegen(inline_single_use_variables(cse(lower(expr))))))
   pp(reduce(codegen(inline_single_use_variables(cse(lower(expr2))))))
   local parse = require('pf.parse').parse
   local expand = require('pf.expand').expand
   local optimize = require('pf.optimize').optimize

   local function test_codegen(expr)
      return reduce(codegen(inline_single_use_variables(cse(lower(optimize(expand(parse(expr), "EN10MB")))))))
   end

   pp(test_codegen("ip"))
end
