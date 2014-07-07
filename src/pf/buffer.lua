module(...,package.seeall)

local ffi = require("ffi")
local bit = require("bit")

local Buffer = {
   __index = {
      u8 = function(self, idx)
         return self.buf[idx]
      end,
      u16 = function(self, idx)
         -- ntohs
         return bit.bor(bit.lshift(self.buf[idx], 8), self.buf[idx+1])
      end,
      s32 = function(self, idx)
         -- ntohl
         return bit.bor(bit.lshift(self.buf[idx], 24),
                        bit.lshift(self.buf[idx+1], 16),
                        bit.lshift(self.buf[idx+2], 8),
                        self.buf[idx+3])
      end
   }
}

function from_string(str)
   local buf = { buf = ffi.cast("uint8_t*", str), str = str, length = #str }
   setmetatable(buf, Buffer)
   return buf
end

function selftest()
   print("selftest: pf.buffer")
   assert(#from_string("") == 0)
   local buf = from_string("abcd")
   assert(buf:u8(0) == string.byte("abcd", 1))
   assert(buf:u8(1) == string.byte("abcd", 2))
   assert(buf:u8(2) == string.byte("abcd", 3))
   assert(buf:u8(3) == string.byte("abcd", 4))
   assert(buf:u16(0) == bit.bor(bit.lshift(buf:u8(0),8), buf:u8(1)))
   assert(buf:u16(1) == bit.bor(bit.lshift(buf:u8(1),8), buf:u8(2)))
   assert(buf:s32(0) == bit.bor(bit.lshift(buf:u8(0),24),
                                bit.lshift(buf:u8(1),16),
                                bit.lshift(buf:u8(2),8),
                                buf:u8(3)))
   print("OK")
end
