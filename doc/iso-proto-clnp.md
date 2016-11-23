# iso proto \clnp


## BPF

```
000: A = P[12:2]
001: if (A > 1500) goto 7 else goto 2
002: A = P[14:2]
003: if (A == 65278) goto 4 else goto 7
004: A = P[17:1]
005: if (A == 129) goto 6 else goto 7
006: return 65535
007: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if (runtime_u32(A)>1500) then goto L6 end
   if 16 > length then return false end
   A = bit.bor(bit.lshift(P[14], 8), P[14+1])
   if not (A==65278) then goto L6 end
   if 18 > length then return false end
   A = P[17]
   if not (A==129) then goto L6 end
   do return true end
   ::L6::
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
   if length < 18 then return false end
   if rshift(bswap(cast("uint16_t*", P+12)[0]), 16) > 1500 then return false end
   if cast("uint16_t*", P+14)[0] ~= 65278 then return false end
   return P[17] == 129
end

```

## Native pflang compilation

```
7f2d772d6000  4883FE12          cmp rsi, +0x12
7f2d772d6004  7C2F              jl 0x7f2d772d6035
7f2d772d6006  0FB7770C          movzx esi, word [rdi+0xc]
7f2d772d600a  66C1CE08          ror si, 0x08
7f2d772d600e  480FB7F6          movzx rsi, si
7f2d772d6012  4881FEDC050000    cmp rsi, 0x5dc
7f2d772d6019  7F1A              jg 0x7f2d772d6035
7f2d772d601b  0FB7770E          movzx esi, word [rdi+0xe]
7f2d772d601f  4881FEFEFE0000    cmp rsi, 0xfefe
7f2d772d6026  750D              jnz 0x7f2d772d6035
7f2d772d6028  0FB67711          movzx esi, byte [rdi+0x11]
7f2d772d602c  4881FE81000000    cmp rsi, 0x81
7f2d772d6033  7403              jz 0x7f2d772d6038
7f2d772d6035  B000              mov al, 0x0
7f2d772d6037  C3                ret
7f2d772d6038  B001              mov al, 0x1
7f2d772d603a  C3                ret

```

