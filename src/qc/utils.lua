#!/usr/bin/env luajit
-- -*- lua -*-
module(..., package.seeall)

function choose(choices)
   local idx = math.random(#choices)
   return choices[idx]
end

function choose_with_index(choices)
   local idx = math.random(#choices)
   return choices[idx], idx
end
