# ether proto 255


## BPF

```
000: A = P[12:2]
001: if (A > 1500) goto 5 else goto 2
002: A = P[14:1]
003: if (A == 255) goto 4 else goto 5
004: return 65535
005: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if (runtime_u32(A)>1500) then goto L4 end
   if 15 > length then return false end
   A = P[14]
   if not (A==255) then goto L4 end
   do return true end
   ::L4::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local rshift = require("bit").rshift
local bswap = require("bit").bswap
local cast = require("ffi").cast
return function(P,length)
   if length < 15 then return false end
   if rshift(bswap(cast("uint16_t*", P+12)[0]), 16) > 1500 then return false end
   return P[14] == 255
end

```

## Native pflang compilation

```
7fed0b2db000  4883FE0F          cmp rsi, +0x0f
7fed0b2db004  7C22              jl 0x7fed0b2db028
7fed0b2db006  0FB7770C          movzx esi, word [rdi+0xc]
7fed0b2db00a  66C1CE08          ror si, 0x08
7fed0b2db00e  480FB7F6          movzx rsi, si
7fed0b2db012  4881FEDC050000    cmp rsi, 0x5dc
7fed0b2db019  7F0D              jg 0x7fed0b2db028
7fed0b2db01b  0FB6770E          movzx esi, byte [rdi+0xe]
7fed0b2db01f  4881FEFF000000    cmp rsi, 0xff
7fed0b2db026  7403              jz 0x7fed0b2db02b
7fed0b2db028  B000              mov al, 0x0
7fed0b2db02a  C3                ret
7fed0b2db02b  B001              mov al, 0x1
7fed0b2db02d  C3                ret

```

