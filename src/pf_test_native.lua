module("pf_test_native",package.seeall)

--[[
There is no split function in Lua as it's a compact
language. This simple function is good enough. It
avoids any extra dependency.
--]]
function string:split(pat, out)
   if not out then
      out = {}
   end
   local s = 1
   local ss, se = string.find(self, pat, s)
   while ss do
      table.insert(out, string.sub(self, s, ss-1))
      s = se + 1
      ss, se = string.find(self, pat, s)
   end
   table.insert(out, string.sub(self, s))
   return out
end

--[[
There is no directory listing function in Lua as
it's a compact language. Maybe we could use lfs but
it would create a dependency. In the meanwhile this
hackish scandir version should make the job.
--]]
function scandir(dirname)
   callit = os.tmpname()
   os.execute("ls -a1 "..dirname .. " >"..callit)
   f = io.open(callit,"r")
   rv = f:read("*all")
   f:close()
   os.remove(callit)
   tabby = {}
   local from  = 1
   local delim_from, delim_to = string.find(rv, "\n", from)
   while delim_from do
      table.insert(tabby, string.sub(rv, from , delim_from-1))
      from  = delim_to + 1
      delim_from, delim_to = string.find(rv, "\n", from)
   end
   return tabby
end

-- retrieve all .ts files under ts/test directory
-- TODO: ts/tests should be some kind of conf var
function get_all_plans()
   local filetab = scandir("ts/tests")
   local plantab = {}
   for _, v in ipairs(filetab) do
      if v:sub(-3) == ".ts" then
         plantab[#plantab+1] = "ts/tests/".. v
      end
   end
   return plantab
end

function prefix(p, s)
   return s:sub(1,#p) == p
end

function get_all_tests(p)
   local plan = {}
   local current = {}
   for line in io.lines(p) do
      -- id
      if prefix("id:", line) then
         current = tonumber(line:sub(#"id:"+1))
         plan[current] = {}
      -- description
      elseif prefix("description:", line) then
         plan[current]['description'] = line:sub(#"description:"+1)
      -- filter
      elseif prefix("filter:", line) then
         plan[current]['filter'] = line:sub(#"filter:"+1)
      -- pcap_file
      elseif prefix("pcap_file:", line) then
         plan[current]['pcap_file'] = line:sub(#"pcap_file:"+1)
      -- expected_result
      elseif prefix("expected_result:", line) then
         plan[current]['expected_result'] = tonumber(line:sub(#"expected_result:"+1))
      -- enabled
      elseif prefix("enabled:", line) then
         plan[current]['enabled'] = line:sub(#"enabled:"+1) == "true"
      end
   end
   return plan
end

local function os_exec(cmd, raw)
   local f = assert(io.popen(cmd, 'r'))
   local s = assert(f:read('*a'))
   f:close()
   if raw then return s end
   s = string.gsub(s, '^%s+', '')
   s = string.gsub(s, '%s+$', '')
   s = string.gsub(s, '[\n\r]+', ' ')
   return s
end

local function assert_count(filter, file, expected)
   local actual = 0
   local et = 0
   local pass = false
   local data

   -- $ ./pf_test_native 'ip' ts/pcaps/ws/v4.pcap 43
   -- pkt_seen:43, elapsed_time: 0.000036, pass: TRUE
   local cmd = "./pf_test_native '" .. filter .. "' " .. file .. " " .. expected
   local data = os_exec(cmd, true)

   local t = data:split(", ")

   actual = tonumber(t[1]:split(":")[2])
   et     = t[2]:split(":")[2]
   pass   = t[3]:split(":")[2]

   return actual, et, pass
end

function run_test_plan(p)

   local plan = get_all_tests(p)

   -- count enabled tests
   local count = 0
   for i, v in ipairs(plan) do
      if plan[i].enabled then
         count = count + 1
      end
   end

   -- show info about the plan
   print("enabled tests: " .. count .. " of " .. #plan)

   -- execute test case
   for i, t in pairs(plan) do
      print("\nTest case running ...")
      print("id: " .. i)
      print("description: " .. t['description'])
      print("filter: " .. t['filter'])
      print("pcap_file: " .. t['pcap_file'])
      print("expected_result: " .. t['expected_result'])
      io.write("enabled: ")
      if t['enabled'] then
         print("true")
      else
         print("false")
      end
      local pkg_seen = 0
      local passed = false
      local elapsed_time = 0
      io.write("tc id " .. i)
      if t['enabled'] then
         pkg_seen, elapsed_time, passed = assert_count(t['filter'], "ts/pcaps/"..t['pcap_file'], t['expected_result'])
         if passed then
            print(" PASS")
         else
            print(" FAIL")
         end
      else
         print(" SKIP")
      end
      print("tc id " .. i .. " AVG ET " .. elapsed_time)
   end
end

function run()
   local plantab = get_all_plans()
   for _, p in ipairs(plantab) do
      print("\n[*] Running test plan: ".. p .. "\n")
      local stat = run_test_plan(p)
   end
end
