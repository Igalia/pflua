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
--   * ret-true
--   * ret-false
--   * cmp
--   * mov
--   * mov64
--   * load
--   * add
--   * add-3
--   * add-i
--   * mul
--   * mul-i
--   * and
--   * and-i
--   * shl
--   * shl-i
--   * ntohs
--   * uint32
--   * cjmp
--   * jmp
--   * noop (inserted by register allocation)

module(...,package.seeall)

local utils = require("pf.utils")

local verbose = os.getenv("PF_VERBOSE");

local negate_op = { ["="] = "!=", ["!="] = "=",
                    [">"] = "<=", ["<"] = ">=",
                    [">="] = "<", ["<="] = ">" }

-- extract a number from an SSA IR label
-- decrement by 1 since codegen labels start at 0
function label_num(label)
   return tonumber(string.match(label, "L(%d+)")) - 1
end

-- Convert a block to a sequence of pseudo-instructions
--
-- Virtual registers are given names prefixed with "r" as in "r1".
-- SSA variables remain prefixed with "v"
local function select_block(block, new_register, instructions, next_label)
   local control  = block.control
   local bindings = block.bindings

   local function emit(instr)
      table.insert(instructions, instr)
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
         local offset = expr[2]
         if type(offset) == "table" then
            local reg2 = select_arith(offset)
            emit({ "load", reg, reg2, expr[3] })
         else
            emit({ "load", reg, offset, expr[3] })
         end
         return reg

      -- three register addition
      elseif (expr[1] == "+" and type(expr[2]) == "table" and
              expr[2][1] == "+") then
         local reg1 = select_arith(expr[2][2])
         local reg2 = select_arith(expr[2][3])
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg1 })
         emit({ "add-3", tmp, reg2, reg3 })
         return tmp
      elseif (expr[1] == "+" and type(expr[3]) == "table" and
              expr[3][1] == "+") then
         local reg1 = select_arith(expr[3][2])
         local reg2 = select_arith(expr[3][3])
         local reg3 = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg1 })
         emit({ "add-3", tmp, reg2, reg3 })
         return tmp

      -- addition with immediate
      elseif expr[1] == "+" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg3 })
         emit({ "add-i", tmp, expr[2] })
         return tmp
      elseif expr[1] == "+" and type(expr[3]) == "number" then
         local reg2 = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "add-i", tmp, expr[3] })
         return tmp

      -- multiplication with constant
      elseif expr[1] == "*" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg3 })
         emit({ "mul-i", tmp, expr[2] })
         return tmp
      elseif expr[1] == "*" and type(expr[3]) == "number" then
         local reg2 = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "mul-i", tmp, expr[3] })
         return tmp

      -- & with immediate
      elseif expr[1] == "&" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg3 })
         emit({ "and-i", tmp, expr[2] })
         return tmp
      elseif expr[1] == "&" and type(expr[3]) == "number" then
         local reg2 = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "and-i", tmp, expr[3] })
         return tmp

      -- << with immediate
      elseif expr[1] == "<<" and type(expr[2]) == "number" then
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         local tmp2 = new_register()
         emit({ "mov", tmp, reg3 })
         emit({ "mov", tmp2, expr[2] })
         emit({ "shl", tmp, tmp2 })
         return tmp
      elseif expr[1] == "<<" and type(expr[3]) == "number" then
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

      -- generic multiplication
      elseif expr[1] == "*" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "mul", tmp, reg3 })
         return tmp

      -- generic addition
      elseif expr[1] == "+" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "add", tmp, reg3 })
         return tmp

      elseif expr[1] == "&" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "and", tmp, reg3 })
         return tmp

      elseif expr[1] == "<<" then
         local reg2 = select_arith(expr[2])
         local reg3 = select_arith(expr[3])
         local tmp = new_register()
         emit({ "mov", tmp, reg2 })
         emit({ "shl", tmp, reg3 })
         return tmp

      elseif expr[1] == "ntohs" then
         local reg = select_arith(expr[2])
         local tmp = new_register()
         emit({ "mov", tmp, reg })
         emit({ "ntohs", tmp })
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
      emit({ "cmp", reg1, reg2 })
   end

   emit({ "label", label_num(block.label) })

   for _, binding in ipairs(bindings) do
      local rhs = binding.value
      local reg = select_arith(rhs)
      emit({ "mov", binding.name, reg })
   end

   if control[1] == "return" then
      local result = control[2]

      if result[1] == "false" then
         emit({ "ret-false" })
      elseif result[1] == "true" then
         emit({ "ret-true" })
      else
         select_bool(result)
         emit({ "cjmp", result[1], "true-label" })
         emit({ "ret-false" })
      end

   elseif control[1] == "if" then
      local cond = control[2]
      select_bool(cond)
      if control[3] ~= next_label and control[4] ~= next_label then
         emit({ "cjmp", cond[1], label_num(control[3]) })
         emit({ "jmp", label_num(control[4]) })
      elseif control[3] == next_label then
         emit({ "cjmp", negate_op[cond[1]], label_num(control[4]) })
      elseif control[4] == next_label then
         emit({ "cjmp", cond[1], label_num(control[3]) })
      end
   end
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
   local instructions = {}

   local reg_num = 1
   local new_register = make_new_register(reg_num)

   for idx, label in pairs(ssa.order) do
      local next_label = ssa.order[idx+1]
      select_block(blocks[label], new_register, instructions, next_label)
   end

   if verbose then
      print_selection(instructions)
   end

   return instructions
end

function selftest()
   local utils = require("pf.utils")

   -- tests of simplification/instruction selection pass on arithmetic
   -- and boolean expressions
   local function test(block, expected, next_label)
      local instructions = {}
      local counter = 1
      local new_register = make_new_register(counter)
      -- next_label parameter only matters if there's an `if`
      select_block(block, new_register, instructions, next_label)
      utils.assert_equals(instructions, expected)
   end

   test({ label = "L1",
          bindings = {},
          control = { "if", { ">=", "len", 14 }, "L4", "L5" } },
        {  { "label", 0 },
           { "cmp", "len", 14 },
           { "cjmp", "<", 4 } },
        "L4")

   test({ label = "L4",
          bindings = {},
          control = { "return", { "=", { "[]", 12, 2 }, 1544 } } },
        { { "label", 3 },
          { "load", "r1", 12, 2 },
          { "cmp", "r1", 1544 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                      { "=", { "+", { "[]", 12, 2 }, 5 }, 1 } } },
        {  { "label", 1 },
           { "load", "r1", 12, 2 },
           { "mov", "r2", "r1" },
           { "add-i", "r2", 5 },
           { "cmp", "r2", 1 },
           { "cjmp", "=", "true-label"},
           { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return",
                      { "=", { "*", { "[]", 12, 2 }, 5 }, 1 } } },
        { { "label", 1 },
          { "load", "r1", 12, 2 },
          { "mov", "r2", "r1" },
          { "mul-i", "r2", 5 },
          { "cmp", "r2", 1 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "return", { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 } } },
        { { "label", 1 },
          { "load", "r1", 12, 2 },
          { "load", "r2", 14, 2 },
          { "mov", "r3", "r1" },
          { "mul", "r3", "r2" },
          { "cmp", "r3", 1 },
          { "cjmp", "=", "true-label" },
          { "ret-false" } })

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "+", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { { "label", 1 },
          { "load", "r1", 12, 2 },
          { "mov", "r2", "r1" },
          { "add-i", "r2", 5 },
          { "cmp", "r2", 1 },
          { "cjmp", "!=", 4 } },
        "L4")

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, 5 }, 1 },
                      "L4", "L5" } },
        { { "label", 1 },
          { "load", "r1", 12, 2 },
          { "mov", "r2", "r1" },
          { "mul-i", "r2", 5 },
          { "cmp", "r2", 1 },
          { "cjmp", "!=", 4 } },
         "L4")

   test({ label = "L2",
          bindings = {},
          control = { "if",
                      { "=", { "*", { "[]", 12, 2 }, { "[]", 14, 2 } }, 1 },
                      "L4", "L5" } },
        { { "label", 1 },
          { "load", "r1", 12, 2 },
          { "load", "r2", 14, 2 },
          { "mov", "r3", "r1" },
          { "mul", "r3", "r2" },
          { "cmp", "r3", 1 },
          { "cjmp", "!=", 4 } },
        "L4")

   test({ label = "L10",
          bindings = { { name = "v2", value = { "[]", 20, 1 } } },
          control = { "if", { "=", "v2", 6 }, "L12", "L13" } },
        { { "label", 9 },
          { "load", "r1", 20, 1 },
          { "mov", "v2", "r1" },
          { "cmp", "v2", 6 },
          { "cjmp", "!=", 12 } },
        "L12")

   -- test on a whole set of blocks
   local function test(block, expected)
      local instructions = select(block)
      utils.assert_equals(instructions, expected)
   end

   test(-- this is the first few blocks of the `tcp` filter
        { start = "L1",
          order = { "L1", "L4", "L6", "L7", "L8", "L10", "L12" },
          blocks =
             { L1 = { label = "L1",
	              bindings = {},
	              control = { "if", { ">=", "len", 34 }, "L4", "L5" } },
	       L4 = { label = "L4",
	              bindings = { { name = "v1", value = { "[]", 12, 2 } } },
	              control = { "if", { "=", "v1", 8 }, "L6", "L7" } },
	       L6 = { label = "L6",
	              bindings = {},
	              control = { "return", { "=", { "[]", 23, 1 }, 6 } } },
	       L7 = { label = "L7",
	              bindings = {},
	              control = { "if", { ">=", "len", 54 }, "L8", "L9" } },
               L8 = { label = "L8",
	              bindings = {},
	              control = { "if", { "=", "v1", 56710 }, "L10", "L11" } },
               L10 = { label = "L10",
                       bindings = { { name = "v2", value = { "[]", 20, 1 } } },
                       control = { "if", { "=", "v2", 6 }, "L12", "L13" } },
               L12 = { label = "L12",
                       bindings = {},
                       control = { "return", { "true" } } } } },
        { { "label", 0 },
          { "cmp", "len", 34 },
          { "cjmp", "<", 4 },
          { "label", 3 },
          { "load", "r1", 12, 2 },
          { "mov", "v1", "r1" },
          { "cmp", "v1", 8 },
          { "cjmp", "!=", 6 },
          { "label", 5 },
          { "load", "r2", 23, 1 },
          { "cmp", "r2", 6 },
          { "cjmp", "=", "true-label" },
          { "ret-false" },
          { "label", 6 },
          { "cmp", "len", 54 },
          { "cjmp", "<", 8 },
          { "label", 7 },
          { "cmp", "v1", 56710 },
          { "cjmp", "!=", 10 },
          { "label", 9 },
          { "load", "r3", 20, 1 },
          { "mov", "v2", "r3" },
          { "cmp", "v2", 6 },
          { "cjmp", "!=", 12 },
          { "label", 11 },
          { "ret-true" } })
end
