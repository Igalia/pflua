module("pf",package.seeall)

local ffi = require("ffi")
local bit = require("bit")
local band = bit.band

-- Note: the bit module represents uint32_t values with the high-bit set
-- as negative int32_t values, so we do the same for all of our 32-bit
-- values including the "k" field in BPF instructions.

ffi.cdef[[
struct bpf_insn { uint16_t code; uint8_t jt, jf; int32_t k; };
struct bpf_program { uint32_t bf_len; struct bpf_insn *bf_insns; };
]]
local bpf_program_mt = {
  __len = function (program) return program.bf_len end,
  __index = function (program, idx)
     assert(idx >= 0 and idx < #program)
     return program.bf_insns[idx]
  end
}

bpf_insn = ffi.typeof("struct bpf_insn")
bpf_program = ffi.metatype("struct bpf_program", bpf_program_mt)

local function BPF_CLASS(code) return band(code, 0x07) end
local BPF_LD   = 0x00
local BPF_LDX  = 0x01
local BPF_ST   = 0x02
local BPF_STX  = 0x03
local BPF_ALU  = 0x04
local BPF_JMP  = 0x05
local BPF_RET  = 0x06
local BPF_MISC = 0x07

local function BPF_SIZE(code) return band(code, 0x18) end
local BPF_W = 0x00
local BPF_H = 0x08
local BPF_B = 0x10

local function BPF_MODE(code) return band(code, 0xe0) end
local BPF_IMM = 0x00
local BPF_ABS = 0x20
local BPF_IND = 0x40
local BPF_MEM = 0x60
local BPF_LEN = 0x80
local BPF_MSH = 0xa0

local function BPF_OP(code) return band(code, 0xf0) end
local BPF_ADD = 0x00
local BPF_SUB = 0x10
local BPF_MUL = 0x20
local BPF_DIV = 0x30
local BPF_OR = 0x40
local BPF_AND = 0x50
local BPF_LSH = 0x60
local BPF_RSH = 0x70
local BPF_NEG = 0x80
local BPF_JA = 0x00
local BPF_JEQ = 0x10
local BPF_JGT = 0x20
local BPF_JGE = 0x30
local BPF_JSET = 0x40

local function BPF_SRC(code) return band(code, 0x08) end
local BPF_K = 0x00
local BPF_X = 0x08

local function BPF_RVAL(code) return band(code, 0x18) end
local BPF_A = 0x10

local function BPF_MISCOP(code) return band(code, 0xf8) end
local BPF_TAX = 0x00
local BPF_TXA = 0x80

local BPF_MEMWORDS = 16

local function runtime_u32(s32)
   if (s32 < 0) then return s32 + 0x10000000 end
   return s32
end

local function runtime_div(a, b)
   -- FIXME: Redo code generator to allow div-by-zero to bail.
   return bit.tobit(math.floor(runtime_u32(a) / runtime_u32(b)))
end

local function runtime_mul(a, b)
   -- FIXME: This can overflow.  We need a math.imul.
   return bit.tobit(runtime_u32(a) * runtime_u32(b))
end

local function compile_bpf_prog (instructions)
   local head = '';
   local body = '';
   local function write_head(code) head = head .. '  ' .. code .. '\n' end
   local function write_body(code) body = body .. '  ' .. code .. '\n' end
   local write = write_body

   local function bin(op, a, b) return '(' .. a .. op .. b .. ')' end
   local function prop(a, b) return bin('.', a, b) end
   local function call(proc, args) return proc .. '(' .. args .. ')' end
   local function comma(a1, a2) return a1 .. ',' .. a2 end
   local function s32(a) return call('bit.tobit', a) end
   local function u32(a) return call('runtime_u32', a) end
   local function add(a, b) return s32(bin('+', a, b)) end
   local function sub(a, b) return s32(bin('-', a, b)) end
   local function mul(a, b) return call('runtime_mul', comma(a, b)) end
   local function div(a, b) return call('runtime_div', comma(a, b)) end
   local function bit(op, a, b) return call(prop('bit', op), comma(a, b)) end
   local function bor(a, b) return bit('bor', a, b) end
   local function band(a, b) return bit('band', a, b) end
   local function lsh(a, b) return bit('lshift', a, b) end
   local function rsh(a, b) return bit('rshift', a, b) end
   local function neg(a) return s32('-' .. a) end
   local function ee(a, b) return bin('==', a, b) end
   local function ge(a, b) return bin('>=', a, b) end
   local function gt(a, b) return bin('>', a, b) end
   local function assign(lhs, rhs) return lhs .. '=' .. rhs end
   local function label(i) return '::L' .. i .. '::' end
   local function jump(i) return 'goto ' .. label(i) end
   local function cond(test, kt, kf, fallthrough)
      if fallthrough == kf then
         return 'if ' .. test .. ' then ' .. jump(kt) .. 'end'
      elseif fallthrough == kt then
         return cond('not '..test, kf, kt, fallthrough)
      else
         return cond(test, kt, kf, kf) .. jump(kf)
      end
   end

   local function P_ref(size)
      if size == BPF_W then return 'P.s32'
      elseif size == BPF_H then return 'P.u16'
      elseif size == BPF_B then return 'P.u8'
      else error('bad size ' .. size)
      end
   end

   local state = {}
   local function declare(name, init)
      if not state[name] then
         H(assign('local ' .. name, init or '0'))
         state[name] = true
      end
      return name
   end

   local function A() return declare('A') end        -- accumulator
   local function X() return declare('X') end        -- index
   local function M(k)                               -- scratch
      if (k >= BPF_MEMWORDS or k < 0) then error("bad k" .. k) end
      return declare('M'..k)
   end
   local function P(size, mode, k)                   -- packet
      if     mode == BPF_ABS then return call(P_ref(size), k)
      elseif mode == BPF_IND then return call(P_ref(size), add(X(), k))
      elseif mode == BPF_LEN then return 'bit.tobit(P.length)'
      elseif mode == BPF_IMM then return k
      elseif mode == BPF_MEM then return M(k)
      else                        error('bad mode ' .. mode)
      end
   end

   local jump_targets = {}

   local function ld(size, mode, k)
      local rhs
      if     mode == BPF_ABS then rhs = call(P_ref(size), k)
      elseif mode == BPF_IND then rhs = call(P_ref(size), add(X(), k))
      elseif mode == BPF_LEN then rhs = 'bit.tobit(P.length)'
      elseif mode == BPF_IMM then rhs = k
      elseif mode == BPF_MEM then rhs = M(k)
      else                        error('bad mode ' .. mode)
      end
      write(assign(A(), rhs))
   end

   local function ldx(size, mode, k)
      local rhs
      if     mode == BPF_LEN then rhs = 'P.length'
      elseif mode == BPF_IMM then rhs = k
      elseif mode == BPF_MEM then rhs = M(k)
      elseif mode == BPF_MSH then rhs = mul(4, band(call('P.u8', k), 0xf))
      else                        error('bad mode ' .. mode)
      end
      write(assign(X(), rhs))
   end

   local function st(k)
      write(assign(M(k), A()))
   end

   local function stx(k)
      write(assign(M(k), X()))
   end

   local function alu(op, src, k)
      local b
      if     src == BPF_K then b = k
      elseif src == BPF_X then b = X()
      else error('bad src ' .. src)
      end

      local rhs
      if     op == BPF_ADD then rhs = add(A(), b)
      elseif op == BPF_SUB then rhs = sub(A(), b)
      elseif op == BPF_MUL then rhs = mul(A(), b)
      elseif op == BPF_DIV then rhs = div(A(), b)
      elseif op == BPF_OR  then rhs = bor(A(), b)
      elseif op == BPF_AND then rhs = band(A(), b)
      elseif op == BPF_LSH then rhs = lsh(A(), b)
      elseif op == BPF_RSH then rhs = rhs(A(), b)
      elseif op == BPF_NEG then rhs = neg(A())
      else error('bad op ' .. op)
      end
      write(assign(A(), rhs))
   end

   local function jmp(i, op, src, k, jt, jf)
      if op == BPF_JA then
         write(jump(i + runtime_u32(k)))
         return
      end

      local rhs
      if src == BPF_K then rhs = k
      elseif src == BPF_X then rhs = X()
      else error('bad src ' .. src)
      end

      jt = jt + i
      jf = jf + i

      if op == BPF_JEQ then
         write(cond(ee(u32(A()), u32(src)), jt, jf))
      elseif op == BPF_JGT then
         write(cond(gt(u32(A()), u32(src)), jt, jf))
      elseif op == BPF_JGE then
         write(cond(ge(u32(A()), u32(src)), jt, jf))
      elseif op == BPF_JSET then
         write(cond(ee(band(A(), src), 0), jt, jf))
      else
         error('bad op ' .. op)
      end
   end

   local function ret(src, k)
      local rhs
      if src == BPF_K then rhs = k
      elseif src == BPF_A then rhs = A()
      else error('bad src ' .. src)
      end
      write('return ' .. u32(src))
   end

   local function misc(op)
      if op == BPF_TAX then
         write(assign(A(), X()))
      elseif op == BPF_TXA then
         write(assign(A(), X()))
      else error('bad op ' .. op)
      end
   end

   for i=0, #instructions do
      local inst = instructions[i]
      local code = inst.code
      local class = BPF_CLASS(code)
      if     class == BPF_LD  then ld(BPF_SIZE(code), BPF_MODE(code), inst.k)
      elseif class == BPF_LDX then ldx(BPF_SIZE(code), BPF_MODE(code), inst.k)
      elseif class == BPF_ST  then st(inst.k)
      elseif class == BPF_STX then stx(inst.k)
      elseif class == BPF_ALU then alu(BPF_OP(code), BPF_SRC(code), inst.k)
      elseif class == BPF_JMP then jmp(i, BPF_OP(code), BPF_SRC(code), inst.k,
                                       inst.jt, inst.jf)
      elseif class == BPF_RET then ret(BPF_SRC(code), inst.k)
      elseif class == BPF_MISC then misc(BPF_MISCOP(code))
      else error('bad class ' .. class)
      end
      if jump_targets[i] then write(label(i)) end
   end
   return 'function ()\n' .. head .. body .. '  error ("end of bpf?")\nend'
end

function selftest ()
   print("selftest: pf")
   print("OK")
end
