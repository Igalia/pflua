module(...,package.seeall)

verbose = os.getenv("PF_VERBOSE");

local function filter_builder(...)
   local written = 'return function('
   local vcount = 0
   local lcount = 0
   local indent = '   '
   local jumps = {}
   local builder = {}
   function builder.write(str)
      written = written .. str
   end
   function builder.writeln(str)
      builder.write(indent .. str .. '\n')
   end
   function builder.v(str)
      vcount = vcount + 1
      builder.writeln('local v'..vcount..' = '..str)
      return 'v'..vcount
   end
   function builder.label()
      lcount = lcount + 1
      return 'L'..lcount
   end
   function builder.jump(label)
      if label == 'ACCEPT' then return 'return true' end
      if label == 'REJECT' then return 'return false' end
      jumps[label] = true
      return 'goto '..label
   end
   function builder.test(cond, kt, kf, k)
      if kt == k then
         builder.writeln('if not '..cond..' then '..builder.jump(kf)..' end')
      else
         builder.writeln('if '..cond..' then '..builder.jump(kt)..' end')
         if kf ~= k then builder.writeln('do '..builder.jump(kf)..' end') end
      end
   end
   function builder.writelabel(label)
      if jumps[label] then builder.write('::'..label..'::\n') end
   end
   function builder.finish(str)
      builder.write('end')
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
   return builder
end

local function compile_value(builder, expr)
   if expr == 'len' then return 'length' end
   if type(expr) == 'number' then return expr end
   assert(type(expr) == 'table', 'unexpected type '..type(expr))
   local op = expr[1]
   local lhs = expr[2]
   local rhs = expr[3]
   if op == '[]' then
      local accessor
      if rhs == 1 then accessor = 'u8'
      elseif rhs == 2 then accessor = 'u16'
      elseif rhs == 4 then accessor = 's32'
      else error('unexpected [] size', rhs) end
      return builder.v('P:'..lhs..'('..rhs..')')
   elseif op == '+' then return builder.v(lhs..'+'..rhs)
   elseif op == '-' then return builder.v(lhs..'-'..rhs)
   elseif op == '*' then return builder.v(lhs..'*'..rhs)
   elseif op == '/' then return builder.v('math.floor('..lhs..'/'..rhs..')')
   elseif op == '%' then return builder.v(lhs..'%'..rhs)
   elseif op == '&' then return builder.v('bit.band('..lhs..','..rhs..')')
   elseif op == '^' then return builder.v('bit.bxor('..lhs..','..rhs..')')
   elseif op == '|' then return builder.v('bit.bor('..lhs..','..rhs..')')
   elseif op == '<<' then return builder.v('bit.lshift('..lhs..','..rhs..')')
   elseif op == '>>' then return builder.v('bit.rshift('..lhs..','..rhs..')')
   else error('unexpected op', op) end
end

local relop_map = {
   ['<']='<', ['<=']='<=', ['=']='==', ['!=']='~=', ['>=']='>=', ['>']='>'
}

local function compile_bool(builder, expr, kt, kf, k)
   assert(type(expr) == 'table', 'logical expression must be a table')
   local op = expr[1]
   if op == 'not' then
      return compile_bool(builder, expr[2], kf, kt, k)
   elseif op == 'and' then
      local knext = builder.label()
      compile_bool(builder, expr[2], knext, kf, knext)
      builder.writelabel(knext)
      compile_bool(builder, expr[3], kt, kf, k)
   elseif op == 'or' then
      local knext = builder.label()
      compile_bool(builder, expr[2], kt, knext, knext)
      builder.writelabel(knext)
      compile_bool(builder, expr[3], kt, kf, k)
   elseif op == 'if' then
      local test_kt = builder.label()
      local test_kf = builder.label()
      compile_bool(builder, expr[2], test_kt, test_kf, test_kt)
      builder.writelabel(test_kt)
      compile_bool(builder, expr[3], kt, kf, nil)
      builder.writelabel(test_kf)
      compile_bool(builder, expr[4], kt, kf, k)
   elseif op == 'assert' then
      compile_bool(builder, expr[2], nil, 'REJECT', nil)
      compile_bool(builder, expr[3], kt, kf, k)
   elseif op == 'constant' then
      if expr[2] then
         if kt ~= k then builder.write(builder.jump(kt)) end
      else
         if kf ~= k then builder.write(builder.jump(kf)) end
      end
   elseif op == 'fail' then
      builder.write('do return false end')
   elseif relop_map[op] then
      -- An arithmetic relop.
      local op = relop_map[op]
      local lhs = compile_value(builder, expr[2])
      local rhs = compile_value(builder, expr[3])
      local comp = lhs..' '..op..' '..rhs
      builder.test(comp, kt, kf, k)
   else
      error('unhandled primitive'..op)
   end
end

function compile_lua(parsed)
   dlt = dlt or 'RAW'
   local builder = filter_builder('P', 'length')
   compile_bool(builder, parsed, 'ACCEPT', 'REJECT')
   return builder.finish()
end

function compile(parsed)
   return assert(loadstring(compile_lua(parsed), 'generated.lua'))()
end

function selftest ()
   print("selftest: pf.codegen")
   local parse = require('pf.parse').parse
   local expand = require('pf.expand').expand
   compile_lua(expand(parse("ip"), 'EN10MB'))
   compile_lua(expand(parse("tcp"), 'EN10MB'))
   print("OK")
end
