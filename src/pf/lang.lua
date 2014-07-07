module("pf.lang",package.seeall)

local function skip_whitespace(str, pos)
   while pos <= #str and str:sub(pos,pos+1):match('%s') do
      pos = pos + 1
   end
   return pos
end

local punctuation = {
   '(', ')', '[', ']', '!', '!=', '<', '<=', '>', '>=', '=',
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||'
}

local function parse_addr(str, pos)
   local digits, dot = str:match("^(%d+)()%.", pos)
   if dot then
      -- IPV4
      
   else
      local digits, colon = str:match("^(%x+)()%:", pos)
      assert(colon, "failed to parse address at "..pos)
      -- IPV6
   end
end

local function parse_number(str, pos, base)
   local res = 0
   local i = pos
   local terminators = " \t\r\n)]!<>=+-*/%&|^"
   while i <= #str do
      local chr = str:sub(i,i+1)
      local n = tonumber(chr, base)
      if n then
         res = res * base + n
      elseif terminators:find(chr, 1, true) then
         return res, i
      else
         return nil, i
      end
   end
end

local function parse_hex(str, pos)
   local ret, next_pos = parse_number(str, pos, 16)
   assert(ret, "unexpected end of hex literal at "..pos)
   return ret, next_pos
end

local function parse_octal_or_addr(str, pos)
   local ret, next_pos = parse_number(str, pos, 8)
   if not ret then return parse_addr(str, pos) end
   return ret, next_pos
end

local function parse_decimal_or_addr(str, pos)
   local ret, next_pos = parse_number(str, pos, 10)
   if not ret then return parse_addr(str, pos) end
   return ret, next_pos
end

local function peek_token(str, pos)
   -- EOF.
   if pos > #str then return nil, pos end

   -- Non-alphanumeric tokens.
   local two = str:sub(pos,pos+2)
   if punctuation[two] then return two end
   local one = str:sub(pos,pos+1)
   if punctuation[one] then return one end

   -- Numeric literals or net addresses.
   if one:match('%d') then
      if two == ('0x') then return parse_hex(str, pos+2) end
      if two:match('0%d') then return parse_octal_or_addr(str, pos) end
      return parse_decimal_or_addr(str, pos)
   end

   -- Everything else: keywords (which are alphanumeric)
end

function tokens(str)
   local pos, next_pos = 1, nil
   local peeked = nil
   local function peek()
      if not next_pos then
         pos = skip_whitespace(str, pos)
         peeked, next_pos = peek_token(str, pos)
      end
      return peeked
   end
   local function next()
      local tok = assert(peek(), "unexpected end of filter string")
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
   
   print("OK")
end
