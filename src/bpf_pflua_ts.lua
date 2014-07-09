module("bpf_pflua_ts",package.seeall)

local pf = require("pf")

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
      -- pcap_pkts
      elseif prefix("pcap_pkts:", line) then
         plan[current]['pcap_pkts'] = tonumber(line:sub(#"pcap_pkts:"+1))
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

local elapsed_time

local function assert_count(filter, file, expected, dlt)
   local pred = pf.compile_pcap_filter(filter, dlt)
   local start = os.clock()
   local actual = pf.filter_count(pred, file)
   elapsed_time = os.clock() - start
   if actual == expected then
       return "PASS"
   else
       return "FAIL (".. actual.. " != ".. expected .. ")"
   end
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
      print("pcap_pkts: " .. t['pcap_pkts'])
      print("expected_result: " .. t['expected_result'])
      io.write("enabled: ")
      if t['enabled'] then
         print("true")
         print("tc id " .. i .. " " .. assert_count(t['filter'], "ts/pcaps/"..t['pcap_file'], t['expected_result'], "EN10MB"))
      else
         print("false")
         print("tc id " .. i .. " SKIP")
      end
      print("tc id " .. i .. " ET " .. elapsed_time)
      local pps = 0
      if t['pcap_pkts'] ~= 0 then
	 pps = t['pcap_pkts'] / elapsed_time
      end
      print("tc id " .. i .. " PPS " .. pps)
   end
end

function run()
   local plantab = get_all_plans()
   for _, p in ipairs(plantab) do
      print("\n[*] Running test plan: ".. p .. "\n")
      local stat = run_test_plan(p)
   end
end
