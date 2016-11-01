-- Implements register allocation for pflua's native backend
--
-- Register allocation operates on a post-SSA pflua IR form.
--
-- The result of register allocation is a table that describes
-- the max spills/number of stack slots needed and the registers
-- for all variables in each basic block.
--
--   { num_spilled = 1
--     v1 = 1, -- %rcx
--     v2 = 2, -- %rdx
--     v3 = { spill = 0 },
--     L4 = {
--            r1 = 0, -- %rax
--            r2 = 8, -- %r8
--          } }
--
-- The tables for each block have a metatable set to look up in
-- the outer table for v? variables.
--
-- Register numbers are based on DynASM's Rq() register mapping.
--
-- The following registers are reserved and not allocated:
--   * %rdi to store the packet pointer argument
--   * %rsi to store the length argument
--
-- The allocator should first prioritize using caller-save registers
--   * %rax, %rcx, %rdx, %r8-%r11
--
-- before using callee-save registers
--   * %rbx, %r12-%r15

module(...,package.seeall)

local utils = require('pf.utils')
local verbose = os.getenv("PF_VERBOSE");

-- ops that don't read from registers and don't contribute to liveness
local non_read_ops = utils.set("ret-true", "ret-false", "label", "cjmp", "noop")

-- Update the ends of intervals based on variable occurrences in
-- the "control" ast
local function find_live_in_control(label, control, intervals)
   -- the head of an ast is always an operation name, so skip
   for i = 2, #control do
      local ast_type = type(control[i])

      if ast_type == "string" then
	 for _, interval in ipairs(intervals) do
	    if control[i] == interval.name then
	       interval.finish = label
	    end
	 end
      elseif ast_type == "table" then
	 find_live_in_control(label, control[i], intervals)
      end
   end
end

-- The lack of loops and unique register names for each load
-- in the instruction IR makes finding live intervals easy.
--
-- A live interval is a table
--   { name = String, start = number, finish = number }
--
-- The start and finish fields are indices into the instruction
-- array
--
local function live_intervals(instrs)
   local len = { name = "len", start = 1, finish = 1 }
   local order = { len }
   local intervals = { len = len }

   for idx, instr in ipairs(instrs) do
      local itype = instr[1]

      -- movs and loads are the only instructions that result in
      -- new live intervals
      if itype == "load" or itype == "mov" or itype == "mov64" then
         local name = instr[2]
	 local interval = { name = name,
			    start = idx,
			    finish = idx }

         intervals[name] = interval
         table.insert(order, interval)

         -- movs/loads also read registers, so update endpoint
         if type(instr[3]) == "string" then
            intervals[instr[3]].finish = idx
         end

      -- update liveness endpoint for instructions that read
      elseif not non_read_ops[itype] then
         for i=2, #instr do
            if type(instr[i]) == "string" then
               intervals[instr[i]].finish = idx
            end
         end
      end
   end

   -- we need the resulting allocations to be ordered by starting
   -- point, so we emit the ordered sequence rather than the map
   return order
end

-- All available registers, tied to unix x64 ABI
local caller_regs = {11, 10, 9, 8, 6, 2, 1, 0}
local callee_regs = {15, 14, 13, 12, 3}
local num_regs = #caller_regs + #callee_regs

-- Check if a register is free in the freelist
local function is_free(seq, reg)
   for _, val in ipairs(seq) do
      if val == reg then
         return true
      end
   end

   return false
end

-- Remove the given register from the freelist
local function remove_free(freelist, reg)
   for idx, reg2 in ipairs(freelist) do
      if reg2 == reg then
         table.remove(freelist, idx)
         return
      end
   end
end

-- Insert an interval sorted by increasing finish
local function insert_active(active, interval)
   local finish = interval.finish

   for idx, interval2 in ipairs(active) do
      if interval2.finish > finish then
         table.insert(active, idx, interval)
         return
      end
   end

   table.insert(active, interval)
end

-- Optimize movs from a register to the same one
local function delete_useless_movs(ir, alloc)
   for idx, instr in ipairs(ir) do
      if instr[1] == "mov" then
         if alloc[instr[2]] == alloc[instr[3]] then
            -- It's faster just to convert these to
            -- noops than to re-number the table
            ir[idx] = { "noop" }
         end
      end
   end
end

-- Do register allocation with the given IR
-- Returns a register allocation and potentially mutates
-- the ir for optimizations
function allocate(ir)
   local intervals = live_intervals(ir)
   local active = {}

   -- caller-save registers, use these first
   local free_caller = utils.dup(caller_regs)
   -- callee-save registers, if we have to
   local free_callee = utils.dup(callee_regs)

   local allocation = { len = 6, -- %rsi
                        callee_saves = {} }
   remove_free(free_caller, 6)

   local function expire_old(interval)
      local to_expire = {}

      for idx, active_interval in ipairs(active) do
         if active_interval.finish > interval.start then
            break
         else
            local name = active_interval.name
            local reg = allocation[name]

            table.insert(to_expire, idx)

            -- figure out which free list this register is supposed to be on
            if is_free(caller_regs, reg) then
               table.insert(free_caller, reg)
            elseif is_free(callee_regs, reg) then
               table.insert(free_callee, reg)
            else
               error("unknown register")
            end
         end
      end

      for i=1, #to_expire do
         table.remove(active, to_expire[#to_expire - i + 1])
      end
   end

   for _, interval in pairs(intervals) do
      local name = interval.name

      expire_old(interval)

      -- because we prefill some registers, check first if
      -- we need to allocate for this interval
      if not allocation[name] then
        if #free_caller == 0 and #free_callee == 0 then
           -- TODO: do a spill
           error("No spilling yet")
        -- newly freed registers are put at the end, so allocating from
        -- the end will tend to produce better results since we want to
        -- try eliminate movs with the same destination/source register
        elseif #free_caller ~= 0 then
           allocation[name] = free_caller[#free_caller]
           table.remove(free_caller)
        else
           local idx = #free_callee
           allocation[name] = free_callee[idx]
           table.insert(allocation.callee_saves, free_callee[idx])
           table.remove(free_callee)
        end
      end

      insert_active(active, interval)
   end

   delete_useless_movs(ir, allocation)

   if verbose then
      utils.pp({ "register_allocation", allocation })
   end

   return allocation
end

function selftest()
   local function test(instrs, expected)
      utils.assert_equals(expected, live_intervals(instrs))
   end

   -- part of `tcp`, see pf.selection
   local example_1 =
      { { "label", 0 },
        { "cmp", "len", 34 },
        { "cjmp", "<", 4 },
        { "label", 3 },
        { "load", "v1", 12, 2 },
        { "cmp", "v1", 8 },
        { "cjmp", "!=", 6 },
        { "label", 5 },
        { "load", "r1", 23, 1 },
        { "cmp", "r1", 6 },
        { "cjmp", "=", "true-label" },
        { "ret-false" },
        { "label", 6 },
        { "cmp", "len", 54 },
        { "cjmp", "<", 8 },
        { "label", 7 },
        { "cmp", "v1", 56710 },
        { "cjmp", "!=", 10 },
        { "label", 9 },
        { "load", "v2", 20, 1 },
        { "cmp", "v2", 6 },
        { "cjmp", "!=", 12 } }

   local example_2 =
      { { "label", 1 },
        { "load", "r1", 12, 2 },
        { "load", "r2", 14, 2 },
        { "mov", "r3", "r1" },
        { "mul", "r3", "r2" },
        { "cmp", "r3", 1 },
        { "cjmp", "!=", 4 },
        { "cmp", "len", 1 } }

   -- this example isn't from real code, but tests what happens when
   -- there is higher register pressure
   local example_3 =
      { { "label", 1 },
        { "load", "r1", 12, 2 },
        { "load", "r2", 14, 2 },
        { "load", "r3", 15, 2 },
        { "load", "r4", 16, 2 },
        { "load", "r5", 17, 2 },
        { "load", "r6", 18, 2 },
        { "load", "r7", 19, 2 },
        { "load", "r8", 20, 2 },
        { "load", "r9", 21, 2 },
        { "cmp", "r1", 1 },
        { "cmp", "r2", 1 },
        { "cmp", "r3", 1 },
        { "cmp", "r4", 1 },
        { "cmp", "r5", 1 },
        { "cmp", "r6", 1 },
        { "cmp", "r7", 1 },
        { "cmp", "r8", 1 },
        { "cmp", "r9", 1 } }

   -- test that tries to make movs use same dst/src
   local example_4 =
      { { "label", 1 },
        { "load", "v1", 12, 2 },
        { "cmp", "v1", 1 },
        { "load", "r1", 12, 2 },
        { "mov", "r2", "r1" },
        { "cmp", "r2", 1 },
        { "cmp", "len", 1 } }

   -- full `tcp` example from more recent instruction selection
   local example_5 =
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
        { "ret-true" },
        { "label", 12 },
        { "cmp", "len", 55 },
        { "cjmp", "<", 14 },
        { "label", 13 },
        { "cmp", "v2", 44 },
        { "cjmp", "!=", 16 },
        { "label", 15 },
        { "load", "r4", 54, 1 },
        { "cmp", "r4", 6 },
        { "cjmp", "=", "true-label" },
        { "ret-false" },
        { "label", 16 },
        { "ret-false" },
        { "label", 14 },
        { "ret-false" },
        { "label", 10 },
        { "ret-false" },
        { "label", 8 },
        { "ret-false" },
        { "label", 4 },
        { "ret-false" } }

   -- test that variables in load offsets are properly accounted for
   local example_6 =
      { { "label", 0 },
        { "mov", "r1", 5 },
        { "load", "v2", 12, 2 },
        { "load", "v1", "r1", 2 },
        { "cmp", "v1", 1 },
        { "cmp", "v2", 2 } }

   test(example_1,
        { { name = "len", start = 1, finish = 14 },
          { name = "v1", start = 5, finish = 17 },
          { name = "r1", start = 9, finish = 10 },
          { name = "v2", start = 20, finish = 21 } })

   test(example_2,
        { { name = "len", start = 1, finish = 8 },
          { name = "r1", start = 2, finish = 4 },
          { name = "r2", start = 3, finish = 5 },
          { name = "r3", start = 4, finish = 6 } })

   test(example_5,
        { { name = "len", start = 1, finish = 28 },
          { name = "r1", start = 5, finish = 6 },
          { name = "v1", start = 6, finish = 18 },
          { name = "r2", start = 10, finish = 11 },
          { name = "r3", start = 21, finish = 22 },
          { name = "v2", start = 22, finish = 31 },
          { name = "r4", start = 34, finish = 35 } })

   test(example_6,
        { { name = "len", start = 1, finish = 1 },
          { name = "r1", start = 2, finish = 4 },
          { name = "v2", start = 3, finish = 6 },
          { name = "v1", start = 4, finish = 5 } })

   local function test(instrs, expected)
      utils.assert_equals(expected, allocate(instrs))
   end

   test(example_1,
        { v1 = 0, r1 = 1, len = 6, v2 = 0, callee_saves = {} })

   -- mutates example_2
   test(example_2,
        { r1 = 0, r2 = 1, r3 = 0, len = 6, callee_saves = {} })
   utils.assert_equals(example_2,
                       { { "label", 1 },
                         { "load", "r1", 12, 2 },
                         { "load", "r2", 14, 2 },
                         { "noop" },
                         { "mul", "r3", "r2" },
                         { "cmp", "r3", 1 },
                         { "cjmp", "!=", 4 },
                         { "cmp", "len", 1 } })

   test(example_3,
        { r1 = 6, r2 = 0, r3 = 1, r4 = 2, r5 = 8, r6 = 9,
          r7 = 10, r8 = 11, r9 = 3, len = 6,
          callee_saves = { 3 } })

   test(example_4,
        { v1 = 0, r1 = 0, len = 6, r2 = 0, callee_saves = {} })

   test(example_5,
        { len = 6, r1 = 0, v1 = 0, r2 = 1, r3 = 0,
          v2 = 0, r4 = 0, callee_saves = {} })

   local function test(instrs, expected)
      utils.assert_equals(expected, allocate(instrs))
   end
end
