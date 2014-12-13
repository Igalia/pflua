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
                     { 'if', expr, { 'return', { kt_value } } },
                     { 'goto', kf } }
         elseif kf_value then
            return { 'do',
                     { 'if', { 'not', expr }, { 'return', { kf_value } } },
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
   local subst_labels = {}
   local function has_fallthrough(expr)
      local op = expr[1]
      if op == 'goto' or op == 'return' then return false end
      if op == 'if' or op == 'bind' then return true end
      if op == 'do' then return has_fallthrough(expr[#expr]) end
      assert(op == 'label')
      return has_fallthrough(expr[3])
   end
   local function count_label_uses(expr)
      local op = expr[1]
      if op == 'do' then
         for i=#expr,2,-1 do
            local subexpr = expr[i]
            if subexpr[1] == 'label' then
               assert(i>2)
               if not has_fallthrough(expr[i-1]) then
                  -- A label that has no fallthrough and which is only
                  -- referenced once can be substituted directly into
                  -- its predecessor.
                  subst_labels[subexpr[2]] = subexpr[3]
               end
            end
            count_label_uses(subexpr)
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
   local function should_inline_label(label)
      return counts[label] == 1 and subst_labels[label]
   end
   local function remove_unreferenced_labels(expr)
      local op = expr[1]
      if op == 'do' then
         local result = { 'do' }
         for i=2,#expr do
            if expr[i][1] == 'label' and should_inline_label(expr[i][2]) then
               -- Skip; it will be inlined in the goto.
            else
               table.insert(result, remove_unreferenced_labels(expr[i]))
            end
         end
         return result
      elseif op == 'goto' then
         -- Inline the label.
         if counts[expr[2]] == 1 and subst_labels[expr[2]] then
            return remove_unreferenced_labels(subst_labels[expr[2]])
         else
            return expr
         end
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

local function optimize_code_inner(expr)
   return delabel(reduce(expr))
end

local function optimize_code(expr)
   expr = utils.fixpoint(optimize_code_inner, expr)
   if verbose then pp(expr) end
   return expr
end

local function filter_builder(...)
   local written = 'return function('
   local vcount = 0
   local lcount = 0
   local indent = ''
   local jumps = {}
   local builder = {}
   local db_stack = {}
   local db = {}
   function builder.write(str)
      written = written .. str
   end
   function builder.writeln(str)
      builder.write(indent .. str .. '\n')
   end
   function builder.bind(var, val)
      builder.writeln('local '..var..' = '..val)
   end
   function builder.push()
      indent = indent .. '   '
   end
   function builder.pop()
      indent = indent:sub(4)
      builder.writeln('end')
   end
   function builder.jump(label)
      builder.writeln('goto '..label)
   end
   function builder.writelabel(label)
      builder.write('::'..label..'::\n')
   end
   function builder.finish(str)
      builder.pop()
      if verbose then print(written) end
      return written
   end
   local needs_comma = false
   for _, v in ipairs({...}) do
      if needs_comma then builder.write(',') end
      builder.write(v)
      needs_comma = true
   end
   builder.write(')\n')
   builder.push()
   return builder
end

local function read_buffer_word_by_type(buffer, offset, size)
   if size == 1 then
      return buffer..'['..offset..']'
   elseif size == 2 then
      return ('ffi.cast("uint16_t*", '..buffer..'+'..offset..')[0]')
   elseif size == 4 then
      return ('ffi.cast("uint32_t*", '..buffer..'+'..offset..')[0]')
   else
      error("bad [] size: "..size)
   end
end

local function serialize(builder, expr)
   local function serialize_value(expr)
      if expr == 'len' then return 'length' end
      if type(expr) == 'number' then return expr end
      if type(expr) == 'string' then return expr end
      assert(type(expr) == 'table', 'unexpected type '..type(expr))
      local op, lhs = expr[1], serialize_value(expr[2])
      if op == 'ntohs' then
         return 'bit.rshift(bit.bswap('..lhs..'), 16)'
      elseif op == 'ntohl' then
         return 'bit.bswap('..lhs..')'
      elseif op == 'int32' then
         return 'bit.tobit('..lhs..')'
      elseif op == 'uint32' then
         return '('..lhs..' % '.. 2^32 ..')'
      end
      local rhs = serialize_value(expr[3])
      if op == '[]' then
         return read_buffer_word_by_type('P', lhs, rhs)
      elseif op == '+' then return '('..lhs..' + '..rhs..')'
      elseif op == '-' then return '('..lhs..' - '..rhs..')'
      elseif op == '*' then return '('..lhs..' * '..rhs..')'
      elseif op == '/' then return 'math.floor('..lhs..' / '..rhs..')'
      elseif op == '&' then return 'bit.band('..lhs..','..rhs..')'
      elseif op == '^' then return 'bit.bxor('..lhs..','..rhs..')'
      elseif op == '|' then return 'bit.bor('..lhs..','..rhs..')'
      elseif op == '<<' then return 'bit.lshift('..lhs..','..rhs..')'
      elseif op == '>>' then return 'bit.rshift('..lhs..','..rhs..')'
      else error('unexpected op', op) end
   end

   local relop_map = {
      ['<']='<', ['<=']='<=', ['=']='==', ['!=']='~=', ['>=']='>=', ['>']='>'
   }

   local function serialize_bool(expr)
      local op = expr[1]
      if op == 'not' then
         return 'not '..serialize_bool(expr[2])
      elseif op == 'true' then
         return 'true'
      elseif op == 'false' then
         return 'false'
      elseif relop_map[op] then
         -- An arithmetic relop.
         local op = relop_map[op]
         local lhs, rhs = serialize_value(expr[2]), serialize_value(expr[3])
         return lhs..' '..op..' '..rhs
      else
         error('unhandled primitive'..op)
      end
   end

   local serialize_sequence

   function serialize_stmt(expr)
      assert(type(expr) == 'table', 'logical expression must be a table')
      local op = expr[1]
      if op == 'if' then
         local test, t = expr[2], expr[3]
         local out = 'if '..serialize_bool(expr[2])..' then'
         if expr[3][1] == 'goto' then
            builder.writeln(out..' goto '..expr[3][2]..' end')
         elseif (expr[3][1] == 'return' and
                 expr[3][2][1] == 'true' or expr[3][2][1] == 'false') then
            builder.writeln(out..' return '..expr[3][2][1]..' end')
         else
            builder.writeln(out)
            builder.push()
            serialize_sequence(expr[3])
            builder.pop()
         end
      elseif op == 'bind' then
         builder.bind(expr[2], serialize_value(expr[3]))
      elseif op == 'goto' then
         builder.jump(expr[2])
      elseif op == 'label' then
         builder.writelabel(expr[2])
         serialize_stmt(expr[3])
      elseif op == 'do' then
         builder.writeln('do')
         builder.push()
         for i=2,#expr do
            serialize_stmt(expr[i])
         end
         builder.pop()
      elseif op == 'return' then
         builder.writeln('return '..serialize_bool(expr[2]))
      else
         error('unhandled primitive'..op)
      end
   end
   function serialize_sequence(expr)
      if (expr[1] == 'do') then
         for i=2,#expr do serialize_stmt(expr[i]) end
      else
         serialize_stmt(expr)
      end
   end
   serialize_sequence(expr)
end

function codegen(expr)
   expr = optimize_code(lower(expr))
   pp(expr)
   local builder = filter_builder('P', 'length')
   serialize(builder, expr)
   local str = builder.finish()
   if verbose then pp(str) end
   return str
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
