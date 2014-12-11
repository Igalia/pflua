module(...,package.seeall)

local utils = require('pf.utils')

local verbose = os.getenv("PF_VERBOSE");

local set, pp, dup = utils.set, utils.pp, utils.dup

local relops = set('<', '<=', '=', '!=', '>=', '>')

local function lower(expr)
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


local function delabel(expr)
   local function remove_trivial_gotos(expr, knext)
      -- Sweep expression from bottom to top, keeping track of what the
      -- fall-through label is.  If we get to a "goto" to a fall-through
      -- label, remove it.
      local op = expr[1]
      if op == 'do' then
         local reversed_result = {}
         for i=#expr,2,-1 do
            local subexpr = remove_trivial_gotos(expr[i], knext)
            if subexpr[1] == 'goto' and subexpr[2] == knext then
               -- Useless goto; skip.
            else
               table.insert(reversed_result, subexpr)
               if subexpr[1] == 'label' then
                  knext = subexpr[2]
               else
                  knext = nil
               end
            end
         end
         local result = { 'do' }
         for i=#reversed_result,1,-1 do
            table.insert(result, reversed_result[i])
         end
         return result
      elseif op == 'goto' then
         return expr
      elseif op == 'label' then
         return { 'label', expr[2], remove_trivial_gotos(expr[3], knext) }
      elseif op == 'if' then
         return { 'if', expr[2], remove_trivial_gotos(expr[3], knext) }
      elseif op == 'return' then
         return expr
      else
         assert(op == 'bind')
         return expr
      end
   end
   local counts = {}
   local function count_label_uses(expr)
      local op = expr[1]
      if op == 'do' then
         for i=#expr,2,-1 do
            count_label_uses(expr[i])
         end
      elseif op == 'goto' then
         counts[expr[2]] = counts[expr[2]] + 1
      elseif op == 'label' then
         counts[expr[2]] = 0
         -- We shouldn't generate code like "L1: goto L2".
         assert(expr[3][1] ~= 'goto')
         count_label_uses(expr[3])
      elseif op == 'if' then
         count_label_uses(expr[3])
      elseif op == 'return' then
         -- nop
      else
         assert(op == 'bind')
      end
   end
   local function remove_unreferenced_labels(expr)
      local op = expr[1]
      if op == 'do' then
         local result = { 'do' }
         for i=2,#expr do
            table.insert(result, remove_unreferenced_labels(expr[i]))
         end
         return result
      elseif op == 'goto' then
         return expr
      elseif op == 'label' then
         local body = remove_unreferenced_labels(expr[3])
         if counts[expr[2]] == 0 then return body end
         return { 'label', expr[2], body }
      elseif op == 'if' then
         return { 'if', expr[2], remove_unreferenced_labels(expr[3]) }
      elseif op == 'return' then
         return expr
      else
         assert(op == 'bind')
         return expr
      end
   end
   expr = remove_trivial_gotos(expr, nil)
   count_label_uses(expr)
   return remove_unreferenced_labels(expr)
end

local function optimize_code(expr)
   return delabel(reduce(expr))
end

function codegen(expr)
   expr = utils.fixpoint(optimize_code, lower(expr))
   if verbose then pp(expr) end
   return expr
end

function selftest()
   local parse = require('pf.parse').parse
   local expand = require('pf.expand').expand
   local optimize = require('pf.optimize').optimize
   local convert_anf = require('pf.anf').convert_anf

   local function test(expr)
      return codegen(convert_anf(optimize(expand(parse(expr), "EN10MB"))))
   end

   pp(test("tcp port 80"))
end
