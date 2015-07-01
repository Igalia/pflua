module(...,package.seeall)

---
--- Program := 'match' Captures Dispatch
--- Captures := '(' [ Identifier' [',' Identifier]... ] ')'
--- Dispatch := Call | Cond
--- Call := Identifier Args?
--- Args := '(' [ ArithmeticExpression [ ',' ArithmeticExpression ] ] ')'
--- Cond := '{' Clause... '}'
--- Clause := Test '=>' Dispatch [ClauseTerminator]
--  Test := 'otherwise' | LogicalExpression
--- ClauseTerminator := ',' | ';'
---
--- LogicalExpression and ArithmeticExpression are embedded productions
--- of pflang.  'otherwise' is a Test that always matches.
---
--- Comments are prefixed by '--' and continue to the end of the line.
---
--- The result of evaluating a Program is either a tail call to a
--- handler procedure, or nil if no dispatch matches.
---
--- A Call matches if all of the conditions necessary to evaluate the
--- arithmetic expressions in its arguments are true.  (For example, the
--- argument handle(ip[42]) is only valid if the packet is an IPv4
--- packet of a sufficient length.)
---
--- A Cond always matches; once you enter a Cond, no clause outside the
--- Cond will match.  If no clause in the Cond matches, the result is
--- nil.
---
--- A Clause matches if the Test on the left-hand-side of the arrow is
--- true.  If the right-hand-side is a call, the conditions from the
--- call arguments (if any) are implicitly added to the Test on the
--- left.  In this way it's possible for the Test to be true but some
--- condition from the Call to be false, which causes the match to
--- proceed with the next Clause.
---
--- Unlike pflang, attempting to access out-of-bounds packet data merely
--- causes a clause not to match, instead of immediately aborting the
--- match.
---

local utils = require('pf.utils')
local set, assert_equals = utils.set, utils.assert_equals
local parse_pflang = require('pf.parse').parse

local function split(str, pat)
   pat = '()'..pat..'()'
   local ret, start_pos = {}, 1
   local tok_pos, end_pos = str:match(pat)
   while tok_pos do
      table.insert(ret, str:sub(start_pos, tok_pos - 1))
      start_pos = end_pos
      tok_pos, end_pos = str:match(pat, start_pos)
   end
   table.insert(ret, str:sub(start_pos))
   return ret
end

local function remove_comments(str)
   local lines = split(str, '\n')
   for i=1,#lines do
      local line = lines[i]
      local comment = line:match('()%-%-')
      if comment then lines[i] = line:sub(1, comment - 1) end
   end
   return table.concat(lines, '\n')
end

-- Return line, line number, column number.
local function error_location(str, pos)
   local start, count = 1, 1
   local stop = str:match('()\n', start)
   while stop and stop < pos do
      start, stop = stop + 1, str:match('()\n', stop + 1)
      count = count + 1
   end
   if stop then stop = stop - 1 end
   return str:sub(start, stop), count, pos - start + 1
end

local function scanner(str)
   str = remove_comments(str)
   local pos = 1
   local function error_str(message, ...)
      local line, line_number, column_number = error_location(str, pos)
      local message = "\npfmatch: syntax error:%d:%d: "..message..'\n'
      local result = message:format(line_number, column_number, ...)
      result = result..line.."\n"
      result = result..string.rep(" ", column_number-1).."^".."\n"
      return result
   end
   local primitive_error = error
   local function error(message, ...)
       primitive_error(error_str(message, ...))
   end

   local function skip_whitespace()
      pos = str:match('^%s*()', pos)
   end
   local function peek(pat)
      skip_whitespace()
      return str:match('^'..pat, pos)
   end
   local function check(pat)
      skip_whitespace()
      local start_pos, end_pos = pos, peek(pat.."()")
      if not end_pos then return nil end
      pos = end_pos
      return str:sub(start_pos, end_pos - 1)
   end
   local seen_identifiers = {}
   local function next_identifier(opts)
      opts = opts or {}
      local id = check('%a%w*')
      if not id then error('expected an identifier') end
      if opts.assert_free and seen_identifiers[id] then
         error('duplicate identifier: %s', id)
      end
      if opts.assert_bound and not seen_identifiers[id] then
         error('unbound identifier: %s', id)
      end
      seen_identifiers[id] = true
      return id
   end
   local function next_balanced(pair)
      local tok = check('%b'..pair)
      if not tok then error("expected balanced '%s'", pair) end
      return tok:sub(2, #tok - 1)
   end
   local function consume(pat)
      if not check(pat) then error("expected pattern '%s'", pat) end
   end
   local function done()
      skip_whitespace()
      return pos == #str + 1
   end
   return {
      error = error,
      peek = peek,
      check = check,
      next_identifier = next_identifier,
      next_balanced = next_balanced,
      consume = consume,
      done = done
   }
end

local parse_dispatch

local function parse_call(scanner)
   local proc = scanner.next_identifier({assert_bound=true})
   if not proc then scanner.error('expected a procedure call') end
   local result = { 'call', proc }
   if scanner.peek('%(') then
      local args_str = scanner.next_balanced('()')
      if not args_str:match('^%s*$') then
         local args = split(args_str, ',')
         for i=1,#args do
            table.insert(result, parse_pflang(args[i], {arithmetic=true}))
         end
      end
   end
   return result
end

local function parse_cond(scanner)
   local res = { 'cond' }
   while not scanner.check('}') do
      local test
      if scanner.check('otherwise') then
         test = { 'true' }
         scanner.consume('=>')
      else
         test = parse_pflang(scanner.consume_until('=>'))
      end
      local consequent = parse_dispatch(scanner)
      scanner.check('[,;]')
      table.insert(res, { test, consequent })
   end
   return res
end

function parse_dispatch(scanner)
   if scanner.check('{') then return parse_cond(scanner) end
   return parse_call(scanner)
end

local function parse_captures(scanner)
   local captures = {}
   scanner.consume('%(')
   if not scanner.check('%)') then
      repeat
         table.insert(captures, scanner.next_identifier({assert_free=true}))
      until not scanner.check(',')
      scanner.consume('%)')
   end
   return captures
end

function parse(str)
   local scanner = scanner(str)
   scanner.consume('match')
   local captures = parse_captures(scanner)
   local dispatch = parse_dispatch(scanner)
   if not scanner.done() then scanner.error("unexpected token") end
   return { 'match', captures, dispatch }
end

function selftest()
   print("selftest: pf.match")
   local function test(str, expr) assert_equals(expr, parse(str)) end
   test("match () {}", { 'match', {}, { 'cond' } })
   test("match (\n--comment\n) {}", { 'match', {}, { 'cond' } })
   test("match (x,y) {}", { 'match', { 'x', 'y' }, { 'cond' } })
   test(" match \n  (  x   , y   )   {  }   ",
        { 'match', { 'x', 'y' }, { 'cond' } })
   test("match(x,y){}",
        { 'match', { 'x', 'y' }, { 'cond' } })
   test("match (x,y) x()",
        { 'match', { 'x', 'y' }, { 'call', 'x' } })
   test("match (x,y) x(1)",
        { 'match', { 'x', 'y' }, { 'call', 'x', 1 } })
   test("match (x,y) x(1&1)",
        { 'match', { 'x', 'y' }, { 'call', 'x', { '&', 1, 1 } } })
   test("match (x,y) x(ip[42])",
        { 'match', { 'x', 'y' }, { 'call', 'x', { '[ip]', 42, 1 } } })
   test("match (x,y) x(ip[42], 10)",
        { 'match', { 'x', 'y' }, { 'call', 'x', { '[ip]', 42, 1 }, 10 } })
   print("OK")
end
