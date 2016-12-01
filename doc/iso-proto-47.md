# iso proto 47


## BPF

```
000: A = P[12:2]
001: if (A > 1500) goto 7 else goto 2
002: A = P[14:2]
003: if (A == 65278) goto 4 else goto 7
004: A = P[17:1]
005: if (A == 47) goto 6 else goto 7
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
   if not (A==47) then goto L6 end
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
   return P[17] == 47
end

```

## Native pflang compilation

```
7fc1c6e25000  4883FE12          cmp rsi, +0x12
7fc1c6e25004  7C2C              jl 0x7fc1c6e25032
7fc1c6e25006  0FB7770C          movzx esi, word [rdi+0xc]
7fc1c6e2500a  66C1CE08          ror si, 0x08
7fc1c6e2500e  480FB7F6          movzx rsi, si
7fc1c6e25012  4881FEDC050000    cmp rsi, 0x5dc
7fc1c6e25019  7F17              jg 0x7fc1c6e25032
7fc1c6e2501b  0FB7770E          movzx esi, word [rdi+0xe]
7fc1c6e2501f  4881FEFEFE0000    cmp rsi, 0xfefe
7fc1c6e25026  750A              jnz 0x7fc1c6e25032
7fc1c6e25028  0FB67711          movzx esi, byte [rdi+0x11]
7fc1c6e2502c  4883FE2F          cmp rsi, +0x2f
7fc1c6e25030  7403              jz 0x7fc1c6e25035
7fc1c6e25032  B000              mov al, 0x0
7fc1c6e25034  C3                ret
7fc1c6e25035  B001              mov al, 0x1
7fc1c6e25037  C3                ret

```

