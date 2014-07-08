module("pf.lang",package.seeall)

local function skip_whitespace(str, pos)
   while pos <= #str and str:match('^%s', pos) do
      pos = pos + 1
   end
   return pos
end

local punctuation = {}
do
   local ops = {
      '(', ')', '[', ']', '!', '!=', '<', '<=', '>', '>=', '=',
      '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||', '<<', '>>'
   }
   for k, v in pairs(ops) do punctuation[v] = true end
end

local function lex_host_or_keyword(str, pos)
   local name, next_pos = str:match("^([%w.-]+)()", pos)
   assert(name, "failed to parse hostname or keyword at "..pos)
   assert(name:match("^%w", 1, 1), "bad hostname or keyword "..name)
   assert(name:match("^%w", #name, #name), "bad hostname or keyword "..name)
   return tonumber(name, 10) or name, next_pos
end

local function lex_ipv4_or_host(str, pos)
   local function lex_byte(str)
      local byte = tonumber(str, 10)
      if byte >= 256 then return nil end
      return byte
   end
   local digits, dot = str:match("^(%d%d?%d?)()%.", pos)
   if not digits then return lex_host_or_keyword(str, start_pos) end
   local addr = { type='ipv4' }
   local byte = lex_byte(digits)
   if not byte then return lex_host_or_keyword(str, pos) end
   table.insert(addr, byte)
   pos = dot
   for i=1,3 do
      local digits, dot = str:match("^%.(%d%d?%d?)()", pos)
      if not digits then break end
      table.insert(addr, assert(lex_byte(digits), "failed to parse ipv4 addr"))
      pos = dot
   end
   local terminators = " \t\r\n)/"
   assert(pos > #str or terminators:find(str:sub(pos, pos), 1, true),
          "unexpected terminator for ipv4 address")
   return addr, pos
end

local function lex_ipv6(str, pos)
   local addr = { type='ipv6' }
   -- FIXME: Currently only supporting fully-specified IPV6 names.
   local digits, dot = str:match("^(%x%x?)()%:", pos)
   assert(digits, "failed to parse ipv6 address at "..pos)
   table.insert(addr, tonumber(digits, 16))
   pos = dot
   for i=1,15 do
      local digits, dot = str:match("^%:(%x%x?)()", pos)
      assert(digits, "failed to parse ipv6 address at "..pos)
      table.insert(addr, tonumber(digits, 16))
      pos = dot
   end
   local terminators = " \t\r\n)/"
   assert(pos > #str or terminators:find(str:sub(pos, pos), 1, true),
          "unexpected terminator for ipv6 address")
   return addr, pos
end

local function lex_addr(str, pos)
   local start_pos = pos
   if str:match("^%d%d?%d?%.", pos) then
      return lex_ipv4_or_host(str, pos)
   elseif str:match("^%x?%x?%:", pos) then
      return lex_ipv6(str, pos)
   else
      return lex_host_or_keyword(str, pos)
   end
end

local number_terminators = " \t\r\n)]!<>=+-*/%&|^"

local function lex_number(str, pos, base)
   local res = 0
   local i = pos
   while i <= #str do
      local chr = str:sub(i,i)
      local n = tonumber(chr, base)
      if n then
         res = res * base + n
         i = i + 1
      elseif str:match("^[%a_.]", i) then
         return nil, i
      else
         return res, i
      end
   end
   return res, i  -- EOS
end

local function lex_hex(str, pos)
   local ret, next_pos = lex_number(str, pos, 16)
   assert(ret, "unexpected end of hex literal at "..pos)
   return ret, next_pos
end

local function lex_octal_or_addr(str, pos, in_brackets)
   local ret, next_pos = lex_number(str, pos, 8)
   if not ret then
      if in_brackets then return lex_host_or_keyword(str, pos) end
      return lex_addr(str, pos)
   end
   return ret, next_pos
end

local function lex_decimal_or_addr(str, pos, in_brackets)
   local ret, next_pos = lex_number(str, pos, 10)
   if not ret then
      if in_brackets then return lex_host_or_keyword(str, pos) end
      return lex_addr(str, pos)
   end
   return ret, next_pos
end

local function lex(str, pos, opts, in_brackets)
   -- EOF.
   if pos > #str then return nil, pos end

   -- Non-alphanumeric tokens.
   local two = str:sub(pos,pos+1)
   if punctuation[two] then return two, pos+2 end
   local one = str:sub(pos,pos)
   if punctuation[one] then return one, pos+1 end

   if in_brackets and one == ':' then return one, pos+1 end

   -- Numeric literals or net addresses.
   if opts.maybe_arithmetic and one:match('^%d') then
      if two == ('0x') then
         return lex_hex(str, pos+2)
      elseif two:match('^0%d') then
         return lex_octal_or_addr(str, pos, in_brackets)
      else
         return lex_decimal_or_addr(str, pos, in_brackets)
      end
   end

   -- IPV6 net address beginning with [a-fA-F].
   if not in_brackets and str:match('^%x?%x?%:', pos) then
      return lex_ipv6(str, pos)
   end

   -- "len" is the only bare name that can appear in an arithmetic
   -- expression.  "len-1" lexes as { 'len', '-', 1 } in arithmetic
   -- contexts, but { "len-1" } otherwise.
   if opts.maybe_arithmetic and str:match("^len", pos) then
      if pos + 3 > #str or not str:match("^[%w.]", pos+3) then
         return 'len', pos+3
      end
   end

   -- Keywords or hostnames.
   return lex_host_or_keyword(str, pos)
end

function tokens(str)
   local pos, next_pos = 1, nil
   local peeked = nil
   local brackets = 0
   local function peek(opts)
      if not next_pos then
         pos = skip_whitespace(str, pos)
         peeked, next_pos = lex(str, pos, opts or {}, brackets > 0)
         if peeked == '[' then brackets = brackets + 1 end
         if peeked == ']' then brackets = brackets - 1 end
         assert(next_pos, "next pos is nil")
      end
      return peeked
   end
   local function next(opts)
      local tok = assert(peek(opts), "unexpected end of filter string")
      pos, next_pos = next_pos, nil
      return tok
   end
   return { peek = peek, next = next }
end

function compile(str)
   local ast = parse(str)
end

function selftest ()
   print("selftest: pf.lang")
   local function lex_test(str, elts, opts)
      local lexer = tokens(str)
      for i, val in pairs(elts) do
         local tok = lexer.next(opts)
         assert(tok == val, "expected "..val.." but got "..tok)
      end
      assert(not lexer.peek(opts), "more tokens, yo")
   end
   lex_test("ip", {"ip"}, {maybe_arithmetic=true})
   lex_test("len", {"len"}, {maybe_arithmetic=true})
   lex_test("len", {"len"}, {})
   lex_test("len-1", {"len-1"}, {})
   lex_test("len-1", {"len", "-", 1}, {maybe_arithmetic=true})
   lex_test("1-len", {1, "-", "len"}, {maybe_arithmetic=true})
   lex_test("1-len", {"1-len"}, {})
   lex_test("tcp port 80", {"tcp", "port", 80}, {})
   lex_test("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)",
            { 'tcp', 'port', 80, 'and',
              '(', '(',
              '(',
              'ip', '[', 2, ':', 2, ']', '-',
              '(', '(', 'ip', '[', 0, ']', '&', 15, ')', '<<', 2, ')',
              ')',
              '-',
              '(', '(', 'tcp', '[', 12, ']', '&', 240, ')', '>>', 2, ')',
              ')', '!=', 0, ')'
            }, {maybe_arithmetic=true})
   print("OK")
end
