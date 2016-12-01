# src net ffff:ffff:eeee:eeee:1:0:0:0/82


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 10
002: A = P[22:4]
003: if (A == 4294967295) goto 4 else goto 10
004: A = P[26:4]
005: if (A == 4008636142) goto 6 else goto 10
006: A = P[30:4]
007: A &= 4294950912
008: if (A == 65536) goto 9 else goto 10
009: return 65535
010: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L9 end
   if 26 > length then return false end
   A = bit.bor(bit.lshift(P[22], 24),bit.lshift(P[22+1], 16), bit.lshift(P[22+2], 8), P[22+3])
   if not (A==-1) then goto L9 end
   if 30 > length then return false end
   A = bit.bor(bit.lshift(P[26], 24),bit.lshift(P[26+1], 16), bit.lshift(P[26+2], 8), P[26+3])
   if not (A==-286331154) then goto L9 end
   if 34 > length then return false end
   A = bit.bor(bit.lshift(P[30], 24),bit.lshift(P[30+1], 16), bit.lshift(P[30+2], 8), P[30+3])
   A = bit.band(A, -16384)
   if not (A==65536) then goto L9 end
   do return true end
   ::L9::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local band = require("bit").band
local cast = require("ffi").cast
return function(P,length)
   if length < 54 then return false end
   if cast("uint16_t*", P+12)[0] ~= 56710 then return false end
   if cast("uint32_t*", P+22)[0] ~= 4294967295 then return false end
   if cast("uint32_t*", P+26)[0] ~= 4008636142 then return false end
   return band(cast("uint32_t*", P+30)[0],12648447) == 256
end

```

## Native pflang compilation

```
7f772e248000  4883FE36          cmp rsi, +0x36
7f772e248004  7C44              jl 0x7f772e24804a
7f772e248006  0FB7770C          movzx esi, word [rdi+0xc]
7f772e24800a  4881FE86DD0000    cmp rsi, 0xdd86
7f772e248011  7537              jnz 0x7f772e24804a
7f772e248013  8B7716            mov esi, [rdi+0x16]
7f772e248016  48B8FFFFFFFF0000. mov rax, 0x00000000ffffffff
7f772e248020  4839C6            cmp rsi, rax
7f772e248023  7525              jnz 0x7f772e24804a
7f772e248025  8B471A            mov eax, [rdi+0x1a]
7f772e248028  48BEEEEEEEEE0000. mov rsi, 0x00000000eeeeeeee
7f772e248032  4839F0            cmp rax, rsi
7f772e248035  7513              jnz 0x7f772e24804a
7f772e248037  8B771E            mov esi, [rdi+0x1e]
7f772e24803a  4881E6FFFFC000    and rsi, 0x00c0ffff
7f772e248041  4881FE00010000    cmp rsi, 0x100
7f772e248048  7403              jz 0x7f772e24804d
7f772e24804a  B000              mov al, 0x0
7f772e24804c  C3                ret
7f772e24804d  B001              mov al, 0x1
7f772e24804f  C3                ret

```

