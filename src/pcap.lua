module("pcap",package.seeall)

local ffi  = require("ffi")
local pf  = require("pf")
local pcap = ffi.load("pcap")

-- The dlt_name is a "datalink type name" and specifies the link-level
-- wrapping to expect.  E.g., for raw ethernet frames, you would specify
-- "EN10MB" (even though you have a 10G card), which corresponds to the
-- numeric DLT_EN10MB value from pcap/bpf.h.  See
-- http://www.tcpdump.org/linktypes.html for more details on possible
-- names.
--
-- You probably want "RAW" for raw IP (v4 or v6) frames.  If you don't
-- supply a dlt_name, "RAW" is the default.
function pcap_compile (filter_str, dlt_name)

   ffi.cdef[[
      typedef struct pcap pcap_t;

      int pcap_datalink_name_to_val(const char *name);
      pcap_t *pcap_open_dead(int linktype, int snaplen);
      void pcap_perror(pcap_t *p, const char *suffix);
      int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
                       int optimize, uint32_t netmask);
   ]]

   dlt_name = dlt_name or "RAW"
   local dlt = pcap.pcap_datalink_name_to_val(dlt_name)
   assert(dlt >= 0, "bad datalink type name " .. dlt_name)
   local snaplen = 65535 -- Maximum packet size.
   local p = pcap.pcap_open_dead(dlt, snaplen)

   assert(p, "pcap_open_dead failed")

   -- pcap_compile
   local program = pf.bpf_program()
   local err = pcap.pcap_compile(p, program, filter_str, 0, 0)

   if err ~= 0 then
      pcap.pcap_perror(p, "pcap_compile failed!")
      error("pcap_compile failed")
   end

   return program
end

function dump_bytecode (prog)
   io.write(#prog .. ':\n')
   for i = 0, #prog-1 do
      io.write(string.format('  {0x%x, %u, %u, %d}\n',
                             prog[i].code, prog[i].jt, prog[i].jf, prog[i].k))
   end
   io.write("\n")
end

function selftest ()
   print("selftest: pcap")
   prog = pcap_compile("icmp")
   dump_bytecode(prog)
   print("OK")
end
