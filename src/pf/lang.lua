module("pf.lang",package.seeall)

local function skip_whitespace(str, pos)
   while pos <= #str and str:match('^%s', pos) do
      pos = pos + 1
   end
   return pos
end

local function set(...)
   local ret = {}
   for k, v in pairs({...}) do ret[v] = true end
   return ret
end

local function record(type, ...)
   return { type = type, ... }
end

local punctuation = set(
   '(', ')', '[', ']', '!', '!=', '<', '<=', '>', '>=', '=',
   '+', '-', '*', '/', '%', '&', '|', '^', '&&', '||', '<<', '>>'
)

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
   local addr = record('ipv4')
   local byte = lex_byte(digits)
   if not byte then return lex_host_or_keyword(str, pos) end
   table.insert(addr, byte)
   pos = dot
   for i=1,3 do
      local digits, dot = str:match("^%.(%d%d?%d?)()", pos)
      if not digits then break end
      local byte = assert(lex_byte(digits), "failed to parse ipv4 addr")
      table.insert(addr, byte)
      pos = dot
   end
   local terminators = " \t\r\n)/"
   assert(pos > #str or terminators:find(str:sub(pos, pos), 1, true),
          "unexpected terminator for ipv4 address")
   return addr, pos
end

local function lex_ipv6(str, pos)
   local addr = record('ipv6')
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

   -- If we are in brackets, then : separates an expression from an
   -- access size.  Otherwise it separates parts of an IPv6 address.
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

   -- Again, if we're in brackets, there won't be an IPv6 address.
   if in_brackets then return lex_host_or_keyword(str, pos) end

   -- Keywords or addresses.
   return lex_addr(str, pos)
end

local function tokens(str)
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
   local function consume(expected, opts)
      local tok = next(opts)
      assert(tok == expected, "expected "..expected..", got:", tok)
   end
   local function check(expected, opts)
      if peek(opts) ~= expected then return false end
      next()
      return true
   end
   return { peek = peek, next = next, consume = consume, check = check }
end

local addressables = set(
   'arp', 'rarp', 'wlan', 'ether', 'fddi', 'tr', 'ppp',
   'slip', 'link', 'radio', 'ip', 'ip6', 'tcp', 'udp', 'icmp'
)

local function unimplemented(lexer, tok)
   error("not implemented: "..tok)
end

local function unary(parse_arg)
   return function(lexer, tok)
      return record(tok, parse_arg(lexer))
   end
end

function parse_host_arg(lexer)
   local arg = lexer.next()
   if type(arg) == 'string' or arg.type == 'ipv4' or arg.type == 'ipv6' then
      return arg
   end
   error('invalid host', arg)
end

function parse_int_arg(lexer, max_len)
   local ret = lexer.next()
   assert(type(ret) == 'number', 'expected a number', ret)
   if max_len then assert(ret <= max_len, 'out of range '..ret) end
   return ret
end

function parse_uint16_arg(lexer) return parse_int_arg(lexer, 0xffff) end

function parse_net_arg(lexer)
   local arg = lexer.next()
   if arg.type == 'ipv4' or arg.type == 'ipv6' then
      if lexer.check('/') then
         local len = parse_int_arg(lexer, arg.type == 'ipv4' and 32 or 128)
         return record(arg.type..'/len', arg, len)
      elseif lexer.check('mask') then
         lexer.next()
         local mask = lexer.next()
         assert(mask.type == arg.type, 'bad mask', mask)
         return record(arg.type..'/mask', arg, mask)
      else
         return arg
      end
   elseif type(arg) == 'string' then
      error('named nets currently unsupported ' .. arg)
   else
      assert(type(arg) == 'number')  -- `net 10'
      error('bare numbered nets currently unsupported', arg)
   end
end

local parse_port_arg = parse_uint16_arg

local function parse_portrange_arg(lexer)
   local start = parse_port_arg(lexer)
   lexer.consume('-')
   return record('portrange', start, parse_port_arg(lexer))
end

local src_or_dst_types = {
   host = unary(parse_host_arg),
   net = unary(parse_net_arg),
   port = unary(parse_port_arg),
   portrange = unary(parse_portrange_arg)
}

local function parse_src_or_dst(lexer, tok)
   local type = lexer.next()
   local parser = assert(src_or_dst_types[type],
                         "unknown "..tok.." type "..type)
   return parser(lexer, tok..'-'..type)
end

local primitives = {
   dst = parse_src_or_dst,
   src = parse_src_or_dst,
   host = unary(parse_host_arg),
   ether = unimplemented,
   gateway = unimplemented,
   net = unimplemented,
   port = unimplemented,
   portrange = unimplemented,
   less = unimplemented,
   greater = unimplemented,
   ip = unimplemented,
   ip6 = unimplemented,
   proto = unimplemented,
   tcp = unimplemented,
   udp = unimplemented,
   icmp = unimplemented,
   protochain = unimplemented,
   arp = unimplemented,
   rarp = unimplemented,
   atalk = unimplemented,
   aarp = unimplemented,
   decnet = unimplemented,
   iso = unimplemented,
   stp = unimplemented,
   ipx = unimplemented,
   netbeui = unimplemented,
   lat = unimplemented,
   moprc = unimplemented,
   mopdl = unimplemented,
   llc = unimplemented,
   ifname = unimplemented,
   on = unimplemented,
   rnr = unimplemented,
   rulenum = unimplemented,
   reason = unimplemented,
   rset = unimplemented,
   ruleset = unimplemented,
   srnr = unimplemented,
   subrulenum = unimplemented,
   action = unimplemented,
   wlan = unimplemented,
   type = unimplemented,
   subtype = unimplemented,
   dir = unimplemented,
   vlan = unimplemented,
   mpls = unimplemented,
   pppoed = unimplemented,
   pppoes = unimplemented,
   iso = unimplemented,
   clnp = unimplemented,
   esis = unimplemented,
   isis = unimplemented,
   l1 = unimplemented,
   l2 = unimplemented,
   iih = unimplemented,
   lsp = unimplemented,
   snp = unimplemented,
   csnp = unimplemented,
   psnp = unimplemented,
   vpi = unimplemented,
   vci = unimplemented,
   lane = unimplemented,
   oamf4s = unimplemented,
   oamf4e = unimplemented,
   oamf4 = unimplemented,
   oam = unimplemented,
   metac = unimplemented,
   bcc = unimplemented,
   sc = unimplemented,
   ilmic = unimplemented,
   connectmsg = unimplemented,
   metaconnect = unimplemented
}

local function parse_primitive_or_relop(lexer, tok)
   if type(tok) == 'string' then
      if addressables[tok] and lexer.peek() == '[' then
         return parse_relop(lexer, peeked)
      end
      local parser = primitives[tok]
      if parser then return parser(lexer, tok) end

      -- At this point the official pcap grammar is squirrely.  It says:
      -- "If an identifier is given without a keyword, the most recent
      -- keyword is assumed.  For example, `not host vs and ace' is
      -- short for `not host vs and host ace` and which should not be
      -- confused with `not (host vs or ace)`."  For now we punt on this
      -- part of the grammar.
      error("keyword elision not implemented")
   end

end

local function parse_expr(lexer)
   local tok = lexer.peek({maybe_arithmetic=true})
   if not tok then return nil end
   lexer.next()
   if tok == '(' then
      local expr = parse_expr(lexer)
      assert(lexer.next() == ')', "expected )")
      return expr
   end
   local expr = parse_primitive_or_relop(lexer, tok)
   return expr
end

function compile(str)
   return parse_expr(tokens(str))
end

function selftest ()
   print("selftest: pf.lang")
   local function check(expected, actual)
      assert(type(expected) == type(actual),
             "expected "..type(expected).." but got "..type(actual))
      if type(expected) == 'table' then
         for k, v in pairs(expected) do check(v, actual[k]) end
      else
         assert(expected == actual, "expected "..expected.." but got "..actual)
      end
   end

   local function lex_test(str, elts, opts)
      local lexer = tokens(str)
      for i, val in ipairs(elts) do
         check(val, lexer.next(opts))
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
   lex_test("host 127.0.0.1", { 'host', { type='ipv4', 127, 0, 0, 1 } })
   lex_test("net 10.0.0.0/24", { 'net', { type='ipv4', 10, 0, 0, 0 }, '/', 24 })

   local function compile_test(str, elts) check(elts, compile(str)) end
   compile_test("host 127.0.0.1",
                { type='host', { type='ipv4', 127, 0, 0, 1 } })
   compile_test("src host 127.0.0.1",
                { type='src-host', { type='ipv4', 127, 0, 0, 1 } })
   compile_test("src net 10.0.0.0/24",
                { type='src-net',
                  { type='ipv4/len', { type='ipv4', 10, 0, 0, 0 }, 24 }})
   print("OK")
end
