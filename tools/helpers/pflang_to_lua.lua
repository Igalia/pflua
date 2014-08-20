module("pflang_to_lua", package.seeall)

package.path = package.path .. ";../src/?.lua"

local libpcap = require("pf.libpcap")
local bpf = require("pf.bpf")

function compile(expr)
    bpf.compile(libpcap.compile(expr, "EN10MB"))
end
