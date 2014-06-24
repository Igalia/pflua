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
   local fp  = pf.bpf_program()
   err = pcap.pcap_compile(p, fp, filter_str, 0, 0)

   if err ~= 0 then
      pcap.pcap_perror(p, "pcap_compile failed!")
   end

   local ins = pf.bpf_insn(fp.bf_len)

   -- generate bytecode
   local fp_arr = {}
   fp_arr[0] = fp.bf_len - 1
   for i = 0,fp.bf_len-2 do
      fp_arr[4*i+1] = fp.bf_insns[i+1].code
      fp_arr[4*i+2] = fp.bf_insns[i+1].jt
      fp_arr[4*i+3] = fp.bf_insns[i+1].jf
      fp_arr[4*i+4] = fp.bf_insns[i+1].k
   end

   return false, fp_arr
end

function dump_bytecode (fp_arr)
   io.write(fp_arr[0])
   for i = 1,#fp_arr-1,4 do
      io.write(",")
      io.write(fp_arr[i]   .. " ")
      io.write(fp_arr[i+1] .. " ")
      io.write(fp_arr[i+2] .. " ")
      io.write(fp_arr[i+3])
   end
   io.write("\n")
end

function selftest ()
   print("selftest: pcap")
   local err, str = pcap_compile("icmp")
   if not err then
      dump_bytecode(str)
   else
      print(str)
   end
   print("OK")
end
