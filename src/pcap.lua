module("pcap",package.seeall)

local ffi  = require("ffi")
local pcap = ffi.load("pcap")

function pcap_compile (filter_str)

   ffi.cdef[[
      typedef struct pcap pcap_t;

      typedef unsigned int bpf_u_int32;

      struct bpf_insn {
        unsigned short code;
        unsigned char jt;
        unsigned char jf;
        bpf_u_int32 k;
      };

      struct bpf_program {
        unsigned int bf_len;
        struct bpf_insn *bf_insns;
      };

      pcap_t *pcap_create(const char *source, char *errbuf);
      int pcap_activate(pcap_t *p);
      int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
   ]]

   -- pcap_create
   local errbuf = ffi.new("char[?]", 256)
   local p = pcap.pcap_create("any", errbuf)

   -- pcap_activate
   err = pcap.pcap_activate(p)

   if err ~= 0 then
      return true, "pcap_activate failed!"
   end

   -- pcap_compile
   local fp  = ffi.new("struct bpf_program",1)
   err = pcap.pcap_compile(p, fp, filter_str, 0, 0)

   if err ~= 0 then
      return true, "pcap_compile failed!"
   end

   local ins = ffi.new("struct bpf_insn", fp.bf_len)

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

-- pcap requires root privileges
-- run 'sudo make check' to test

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
