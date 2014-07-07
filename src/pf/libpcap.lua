module(...,package.seeall)

local ffi = require("ffi")
local pcap -- The pcap library, lazily loaded.

-- Note: the bit module represents uint32_t values with the high-bit set
-- as negative int32_t values, so we do the same for all of our 32-bit
-- values including the "k" field in BPF instructions.

verbose = os.getenv("PF_VERBOSE");

local MAX_UINT32 = 0xffffffff

ffi.cdef[[
struct bpf_insn { uint16_t code; uint8_t jt, jf; int32_t k; };
struct bpf_program { uint32_t bf_len; struct bpf_insn *bf_insns; };

typedef struct pcap pcap_t;
int pcap_datalink_name_to_val(const char *name);
pcap_t *pcap_open_dead(int linktype, int snaplen);
void pcap_perror(pcap_t *p, const char *suffix);
int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
                 int optimize, uint32_t netmask);
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

-- The dlt_name is a "datalink type name" and specifies the link-level
-- wrapping to expect.  E.g., for raw ethernet frames, you would specify
-- "EN10MB" (even though you have a 10G card), which corresponds to the
-- numeric DLT_EN10MB value from pcap/bpf.h.  See
-- http://www.tcpdump.org/linktypes.html for more details on possible
-- names.
--
-- You probably want "RAW" for raw IP (v4 or v6) frames.  If you don't
-- supply a dlt_name, "RAW" is the default.
function compile(filter_str, dlt_name)
   if verbose then print(filter_str) end
   if not pcap then pcap = ffi.load("pcap") end

   dlt_name = dlt_name or "RAW"
   local dlt = pcap.pcap_datalink_name_to_val(dlt_name)
   assert(dlt >= 0, "bad datalink type name " .. dlt_name)
   local snaplen = 65535 -- Maximum packet size.
   local p = pcap.pcap_open_dead(dlt, snaplen)

   assert(p, "pcap_open_dead failed")

   -- pcap_compile
   local bpf = bpf_program()
   local optimize = true
   local netmask = MAX_UINT32
   local err = pcap.pcap_compile(p, bpf, filter_str, optimize, netmask)

   if err ~= 0 then
      pcap.pcap_perror(p, "pcap_compile failed!")
      error("pcap_compile failed")
   end

   return bpf
end

function selftest ()
   print("selftest: pf")

   compile("", "EN10MB")
   compile("ip", "EN10MB")
   compile("tcp", "EN10MB")
   compile("tcp port 80", "EN10MB")

   print("OK")
end
