module("pf.lang",package.seeall)

local function skip_whitespace(str, pos)
   while pos <= #str and str:match('^%s', pos) do
      pos = pos + 1
   end
   return pos
end

local punctuation = {
   '(', ')', '[', ']', '!', '!=', '<', '<=', '>', '>=', '=',
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||'
}
for k, v in ipairs(punctuation) do
   table.remove(punctuation, k)
   punctuation[v] = true
end

local function lex_host_or_keyword(str, pos)
   local name, next_pos = str:match("^([%w_.-]+)()", pos)
   assert(name, "failed to parse hostname or keyword at "..pos)
   return name, next_pos
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
   addr:insert(byte)
   pos = dot
   for i=1,3 do
      local digits, dot = str:match("^%.(%d%d?%d?)()", pos)
      if not digits then break end
      addr:insert(assert(lex_byte(digits), "failed to parse ipv4 addr"))
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
   addr:insert(tonumber(digits, 16))
   pos = dot
   for i=1,15 do
      local digits, dot = str:match("^%:(%x%x?)()", pos)
      assert(digits, "failed to parse ipv6 address at "..pos)
      addr:insert(tonumber(digits, 16))
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
      elseif number_terminators:find(chr, 1, true) then
         return res, i
      else
         return nil, i
      end
   end
   return res, i  -- EOS
end

local function lex_hex(str, pos)
   local ret, next_pos = lex_number(str, pos, 16)
   assert(ret, "unexpected end of hex literal at "..pos)
   return ret, next_pos
end

local function lex_octal_or_addr(str, pos)
   local ret, next_pos = lex_number(str, pos, 8)
   if not ret then return lex_addr(str, pos) end
   return ret, next_pos
end

local function lex_decimal_or_addr(str, pos)
   local ret, next_pos = lex_number(str, pos, 10)
   if not ret then return lex_addr(str, pos) end
   return ret, next_pos
end

local function lex(str, pos, len_is_keyword)
   -- EOF.
   if pos > #str then return nil, pos end

   -- Non-alphanumeric tokens.
   local two = str:sub(pos,pos+1)
   if punctuation[two] then return two, pos+2 end
   local one = str:sub(pos,pos)
   if punctuation[one] then return one, pos+1 end

   -- Numeric literals or net addresses.
   if one:match('^%d') then
      if two == ('0x') then return lex_hex(str, pos+2) end
      if two:match('^0%d') then return lex_octal_or_addr(str, pos) end
      return lex_decimal_or_addr(str, pos)
   end

   -- IPV6 net address beginning with [a-fA-F].
   if str:match('^%x?%x?%:', pos) then
      return lex_ipv6(str, pos)
   end

   -- Unhappily, a special case for "len", which is the only bare name
   -- that can appear in an arithmetic expression.  "len-1" lexes as {
   -- 'len', '-', 1 } in arithmetic contexts, but "len-1" otherwise.
   -- Clownshoes grammar!
   if str:match("^len", pos) and len_is_keyword then
      local ch = str:sub(pos+3, pos+3)
      if ch == '' or number_terminators:find(ch, 1, true) then
         return 'len', pos+3
      end
   end

   -- Keywords or hostnames.
   return lex_host_or_keyword(str, pos)
end

function tokens(str)
   local pos, next_pos = 1, nil
   local peeked = nil
   local function peek(len_is_keyword)
      if not next_pos then
         pos = skip_whitespace(str, pos)
         peeked, next_pos = lex(str, pos, len_is_keyword)
         assert(next_pos, "next pos is nil")
      end
      return peeked
   end
   local function next(len_is_keyword)
      local tok = assert(peek(len_is_keyword),
                         "unexpected end of filter string")
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
   local function lex_test(str, elts, len_is_keyword)
      local lexer = tokens(str)
      for i, val in pairs(elts) do
         local tok = lexer.next(len_is_keyword)
         assert(tok == val, "expected "..val.." but got "..tok)
      end
      assert(not lexer.peek(len_is_keyword), "more tokens, yo")
   end
   lex_test("ip", {"ip"}, true)
   lex_test("len", {"len"}, true)
   lex_test("len", {"len"}, false)
   lex_test("len-1", {"len-1"}, false)
   lex_test("len-1", {"len", "-", 1}, true)
   print("OK")
end
