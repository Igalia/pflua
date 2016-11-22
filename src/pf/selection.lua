-- This module implements an "instruction selection" pass over the
-- SSA IR and produces pseudo-instructions for register allocation
-- and code generation.
--
-- This uses a greed matching algorithm over the tree.
--
-- This generates an array of pseudo-instructions like this:
--
--   { { "load", "r1", 12, 2 } }
--     { "add", "r1", "r3" } }
--
-- The instructions available are:
--   * cmp
--   * mov
--   * mov64
--   * load
--   * add
--   * add-i
--   * sub
--   * sub-i
--   * mul
--   * mul-i
--   * div
--   * and
--   * and-i
--   * or
--   * or-i
--   * xor
--   * xor-i
--   * shl
--   * shl-i
--   * shr
--   * shr-i
--   * ntohs
--   * ntohl
--   * uint32
--   * cjmp
--   * jmp
--   * ret-true, ret-false
--   * nop (inserted by register allocation)

module(...,package.seeall)

local utils = require("pf.utils")

local verbose = os.getenv("PF_VERBOSE");

local negate_op = { ["="] = "!=", ["!="] = "=",
                    [">"] = "<=", ["<"] = ">=",
                    [">="] = "<", ["<="] = ">" }

-- this maps numeric operations that we handle in a generic way
-- because the instruction selection is very similar
local numop_map = { ["+"] = "add", ["-"] = "sub", ["*"] = "mul",
                    ["*64"] = "mul", ["&"] = "and", ["|"] = "or",
                    ["^"] = "xor" }

-- extract a number from an SSA IR label
function label_num(label)
   return tonumber(string.match(label, "L(%d+)"))
end

-- Convert a block to a sequence of pseudo-instructions
--
-- Virtual registers are given names prefixed with "r" as in "r1".
-- SSA variables remain prefixed with "v"
local function select_block(blocks, block, new_register, instructions, next_label)
   local this_label = block.label
   local control    = block.control
   local bindings   = block.bindings

   -- these control whether to emit pseudo-instructions for doing
   -- 'return true' or 'return false' at the very end.
   -- (since they may not be needed if the result is always true or false)
   local emit_true, emit_false

   local function emit(instr)
      table.insert(instructions, instr)
   end

   -- emit a jmp, looking up the next block and replace the jump target if
   -- the next block would immediately jmp anyway (via a return statement)
   local function emit_jmp(target_label, condition)
      local target_block = blocks[target_label]

      if target_block.control[1] == "return" then
         if target_block.control[2][1] == "true" then
            if condition then
               emit({ "cjmp", condition, "true-label" })
            else
               emit({ "jmp", "true-label" })
            end
            emit_true = true
            return
         elseif target_block.control[2][1] == "false" then
            if condition then
               emit({ "cjmp", condition, "false-label" })
            else
               emit({ "jmp", "false-label" })
            end
            emit_false = true
            return
         end
      end

      if condition then
         emit({ "cjmp", condition, label_num(target_label) })
      else
         emit({ "jmp", label_num(target_label) })
      end
   end

   local function emit_cjmp(condition, target_label)
      emit_jmp(target_label, condition)
   end

   local function emit_label()
      local max = instructions.max_label
      local num = label_num(this_label)

      if num > max then
         instructions.max_label = num
      end

      emit({ "label", num })
   end

   -- do instruction selection on an arithmetic expression
   -- returns the destination register or immediate
   local function select_arith(expr)
      if type(expr) == "number" then
         if expr > (2 ^ 31)  - 1 then
            tmp = new_register()
            emit({ "mov64", tmp, expr})
            return tmp
         else
            return expr
         end

      elseif type(expr) == "string" then
         return expr

      elseif expr[1] == "[]" then
         local reg = new_register()
         local reg2 = select_arith(expr[2])
         emit({ "load", reg, reg2, expr[3] })
         return reg

      elseif numop_map[expr[1]] then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         local op   = numop_map[expr[1]]
         local op_i = string.format("%s-i", op)

         -- both arguments in registers
         if type(reg2) ~= "number" and type(reg3) ~= "number" then
            local tmp = new_register()
            emit({ "mov", tmp, reg2 })
            emit({ op, tmp, reg3 })
            return tmp

         -- cases with one or more immediate arguments
         elseif type(reg2) == "number" then
            local tmp3 = new_register()
            -- if op is commutative, we can re-arrange to save registers
            if op ~= "sub" then
               emit({ "mov", tmp3, reg3 })
               emit({ op_i, tmp3, reg2 })
               return tmp3
            else
               local tmp2 = new_register()
               emit({ "mov", tmp2, reg2 })
               emit({ "mov", tmp3, reg3 })
               emit({ op, tmp2, tmp3 })
               return tmp2
            end
         elseif type(reg3) == "number" then
            local tmp = new_register()
            emit({ "mov", tmp, reg2 })
            emit({ op_i, tmp, reg3 })
            return tmp
         end

      elseif expr[1] == "/" then
         local reg2 = select_arith(expr[2])
         local rhs = expr[3]
         local tmp = new_register()

         if type(rhs) == "number" then
            -- if dividing by a power of 2, do a shift
            if rhs ~= 0 and bit.band(rhs, rhs-1) == 0 then
               local imm = 0
               rhs = bit.rshift(rhs, 1)
               while rhs ~= 0 do
                  rhs = bit.rshift(rhs, 1)
                  imm = imm + 1
               end

               emit({ "mov", tmp, reg2 })
               emit({ "shr-i", tmp, imm })
            else
               local tmp3 = new_register()
               local reg3 = select_arith(expr[3])
               emit({ "mov", tmp, reg2 })
               emit({ "mov", tmp3, reg3 })
               emit({ "div", tmp, tmp3 })
            end
         else
            local reg3 = select_arith(expr[3])
            emit({ "mov", tmp, reg2 })
            emit({ "div", tmp, reg3 })
         end

         return tmp

      elseif expr[1] == "<<" then
         -- with immediate
         if type(expr[2]) == "number" then
            local reg3 = select_arith(expr[3])
            local tmp = new_register()
            local tmp2 = new_register()
            emit({ "mov", tmp, reg3 })
            emit({ "mov", tmp2, expr[2] })
            emit({ "shl", tmp, tmp2 })
            return tmp
         elseif type(expr[3]) == "number" then
            local reg2 = select_arith(expr[2])
            local imm = expr[3]
            local tmp = new_register()
            if imm <= 8 then
               emit({ "mov", tmp, reg2 })
               emit({ "shl-i", tmp, imm })
            else
               local tmp2 = new_register()
               emit({ "mov", tmp2, imm })
               emit({ "shl", tmp, tmp2 })
            end
            return tmp

         else
            local reg2 = select_arith(expr[2])
            local reg3 = select_arith(expr[3])
            local tmp1 = new_register()
            local tmp2 = new_register()
            emit({ "mov", tmp1, reg2 })
            emit({ "mov", tmp2, reg3 })
            emit({ "shl", tmp1, tmp2 })
            return tmp1
         end

      elseif expr[1] == ">>" then
         -- with immediate
         if type(expr[2]) == "number" then
            local reg3 = select_arith(expr[3])
            local tmp = new_register()
            local tmp2 = new_register()
            emit({ "mov", tmp, reg3 })
            emit({ "mov", tmp2, expr[2] })
            emit({ "shr", tmp, tmp2 })
            return tmp
         elseif type(expr[3]) == "number" then
            local reg2 = select_arith(expr[2])
            local imm = expr[3]
            local tmp = new_register()
            if imm <= 8 then
               emit({ "mov", tmp, reg2 })
               emit({ "shr-i", tmp, imm })
            else
               local tmp2 = new_register()
               emit({ "mov", tmp2, imm })
               emit({ "shr", tmp, tmp2 })
            end
            return tmp

         else
            local reg2 = select_arith(expr[2])
            local reg3 = select_arith(expr[3])
            local tmp1 = new_register()
            local tmp2 = new_register()
            emit({ "mov", tmp1, reg2 })
            emit({ "mov", tmp2, reg3 })
            emit({ "shr", tmp1, tmp2 })
            return tmp1
         end

      elseif expr[1] == "ntohs" then
         local reg = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg })
         emit({ "ntohs", tmp })
         return tmp

      elseif expr[1] == "ntohl" then
         local reg = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg })
         emit({ "ntohl", tmp })
         return tmp

      elseif expr[1] == "uint32" then
         local reg = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg })
         emit({ "uint32", tmp })
         return tmp

      else
	 error(string.format("NYI op %s", expr[1]))
      end
   end

   local function select_bool(expr)
      local reg1 = select_arith(expr[2])
      local reg2 = select_arith(expr[3])

      -- cmp can't have an immediate on the lhs, but sometimes unoptimized
      -- pf expressions will have such a comparison which requires an extra
      -- mov instruction
      if type(reg1) == "number" then
         local tmp = new_register()
         emit({ "mov", tmp, reg1 })
         reg1 = tmp
      end

      emit({ "cmp", reg1, reg2 })
   end

   local function select_bindings()
     for _, binding in ipairs(bindings) do
        local rhs = binding.value
        local reg = select_arith(rhs)
        emit({ "mov", binding.name, reg })
     end
   end

   if control[1] == "return" then
      local result = control[2]

      -- For the first two branches, only record necessity of constructing the
      -- label. The blocks are dropped since these returns can just be replaced
      -- by directly jumping to the true or false return labels at the end
      if result[1] == "false" then
         emit_false = true
      elseif result[1] == "true" then
         emit_true = true
      else
         emit_label()
         select_bindings()
         select_bool(result)
         emit({ "cjmp", result[1], "true-label" })
         emit({ "jmp", "false-label" })
         emit_true = true
         emit_false = true
      end

   elseif control[1] == "if" then
      local cond = control[2]
      local then_label = control[3]
      local else_label = control[4]

      emit_label()
      select_bindings()
      select_bool(cond)

      if next_label == then_label then
         emit_cjmp(negate_op[cond[1]], else_label)
         emit_jmp(then_label)
      else
         emit_cjmp(cond[1], then_label)
         emit_jmp(else_label)
      end

   else
      error(string.format("NYI op %s", control[1]))
   end

   return emit_true, emit_false
end

local function make_new_register(reg_num)
   return
      function()
         local new_var = string.format("r%d", reg_num)
         reg_num = reg_num + 1
         return new_var
      end
end

-- printing instruction IR for debugging
function print_selection(ir)
   utils.pp({ "instructions", ir })
end

function select(ssa)
   local blocks = ssa.blocks
   local instructions = { max_label = 0 }
   local emit_true, emit_false

   local reg_num = 1
   local new_register = make_new_register(reg_num)

   for idx, label in pairs(ssa.order) do
      local next_label = ssa.order[idx+1]
      local et, ef =
         select_block(blocks, blocks[label], new_register,
                      instructions, next_label)
      emit_true = et or emit_true
      emit_false = ef or emit_false
   end

   if emit_false then
      table.insert(instructions, { "ret-false" })
   end
   if emit_true then
      table.insert(instructions, { "ret-true" })
   end

   if verbose then
      print_selection(instructions)
   end

   return instructions
end

function selftest()
   local utils = require("pf.utils")

   -- test on a whole set of blocks
   local function test(block, expected)
      local instructions = select(block)
      utils.assert_equals(instructions, expected)
   end

   test(-- `arp`
        { start = "L1",
          order = { "L1", "L4", "L5" },
          blocks =
             { L1 = { label = "L1",
                      bindings = {},
                      control = { "if", { ">=", "len", 14}, "L4", "L5" } },
               L4 = { label = "L4",
                      bindings = {},
                      control = { "return", { "=", { "[]", 12, 2}, 1544 } } },
               L5 = { label = "L5",
                      bindings = {},
                      control = { "return", { "false" } } } } },
        { { "label", 1 },
          { "cmp", "len", 14 },
          { "cjmp", "<", "false-label"},
          { "jmp", 4 },
          { "label", 4 },
          { "load", "r1", 12, 2 },
          { "cmp", "r1", 1544 },
          { "cjmp", "=", "true-label" },
          { "jmp", "false-label" },
          { "ret-false" },
          { "ret-true" },
          max_label = 4 })

   test(-- `tcp`
        { start = "L1",
          order = { "L1", "L4", "L6", "L7", "L8", "L10", "L12", "L13",
                    "L14", "L16", "L17", "L15", "L11", "L9", "L5" },
          blocks =
             { L1 = { label = "L1",
                      bindings = {},
                      control = { "if", { ">=", "len", 34 }, "L4", "L5" } },
               L4 = { label = "L4",
                      bindings = { { name = "v1", value = { "[]", 12, 2 } } },
                      control = { "if", { "=", "v1", 8 }, "L6", "L7" },
                      idom = "L1" },
               L6 = { label = "L6",
                      bindings = {},
                      control = { "return", { "=", { "[]", 23, 1 }, 6 } },
                      idom = "L4" },
               L7 = { label = "L7",
                      bindings = {},
                      control = { "if", { ">=", "len", 54 }, "L8", "L9" },
                      idom = "L7" },
               L8 = { label = "L8",
                      bindings = {},
                      control = { "if", { "=", "v1", 56710 }, "L10", "L11" },
                      idom = "L7" },
               L10 = { label = "L10",
                       bindings = { { name = "v2", value = { "[]", 20, 1 } } },
                       control = { "if", { "=", "v2", 6 }, "L12", "L13" },
                       idom = "L9" },
               L12 = { label = "L12",
                       bindings = {},
                       control = { "return", { "true" } },
                       idom = "L10" },
	       L13 = { label = "L13",
	               bindings = {},
	               control = { "if", { ">=", "len", 55 }, "L14", "L15" } },
	       L14 = { label = "L14",
	               bindings = {},
	               control = { "if", { "=", "v2", 44 }, "L16", "L17" } },
	       L16 = { label = "L16",
	               bindings = {},
	               control = { "return", { "=", { "[]", 54, 1 }, 6 } } },
	       L17 = { label = "L17",
	               bindings = {},
	               control = { "return", { "false" } } },
	       L15 = { label = "L15",
	               bindings = {},
	               control = { "return", { "false" } } },
	       L11 = { label = "L11",
	               bindings = {},
	               control = { "return", { "false" } } },
	       L9 = { label = "L9",
	              bindings = {},
	              control = { "return", { "false" } } },
	       L5 = { label = "L5",
	              bindings = {},
	              control = { "return", { "false" } } } } },
        { { "label", 1 },
          { "cmp", "len", 34 },
          { "cjmp", "<", "false-label" },
          { "jmp", 4 },
          { "label", 4 },
          { "load", "r1", 12, 2 },
          { "mov", "v1", "r1" },
          { "cmp", "v1", 8 },
          { "cjmp", "!=", 7 },
          { "jmp", 6 },
          { "label", 6 },
          { "load", "r2", 23, 1 },
          { "cmp", "r2", 6 },
          { "cjmp", "=", "true-label" },
          { "jmp", "false-label" },
          { "label", 7 },
          { "cmp", "len", 54 },
          { "cjmp", "<", "false-label" },
          { "jmp", 8 },
          { "label", 8 },
          { "cmp", "v1", 56710 },
          { "cjmp", "!=", "false-label" },
          { "jmp", 10 },
          { "label", 10 },
          { "load", "r3", 20, 1 },
          { "mov", "v2", "r3" },
          { "cmp", "v2", 6 },
          { "cjmp", "!=", 13 },
          { "jmp", "true-label" },
          { "label", 13 },
          { "cmp", "len", 55 },
          { "cjmp", "<", "false-label" },
          { "jmp", 14 },
          { "label", 14 },
          { "cmp", "v2", 44 },
          { "cjmp", "!=", "false-label" },
          { "jmp", 16 },
          { "label", 16 },
          { "load", "r4", 54, 1 },
          { "cmp", "r4", 6 },
          { "cjmp", "=", "true-label" },
          { "jmp", "false-label" },
          { "ret-false" },
          { "ret-true" },
          max_label = 16 })

   test(-- randomly generated by tests
        { start = "L1",
          order = { "L1", "L4", "L5" },
          blocks =
             { L1 = { control = { "if", { ">=", "len", 4 }, "L4", "L5" },
                      bindings = {},
                      label = "L1", },
               L4 = { control = { "return",
                                  { ">", { "ntohs", { "[]", 0, 4 } }, 0 } },
                      bindings = {},
                      label = "L4", },
               L5 = { control = { "return", { "false" } },
                      bindings = {},
                      label = "L5", } } },
        { { "label", 1 },
          { "cmp", "len", 4 },
          { "cjmp", "<", "false-label" },
          { "jmp", 4 },
          { "label", 4 },
          { "load", "r1", 0, 4 },
          { "mov", "r2", "r1" },
          { "ntohs", "r2" },
          { "cmp", "r2", 0 },
          { "cjmp", ">", "true-label" },
          { "jmp", "false-label" },
          { "ret-false" },
          { "ret-true" },
          max_label = 4 })
end
