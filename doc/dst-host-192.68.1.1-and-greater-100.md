# dst host 192.68.1.1 and greater 100


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 4
002: A = P[30:4]
003: if (A == 3225682177) goto 8 else goto 11
004: if (A == 2054) goto 6 else goto 5
005: if (A == 32821) goto 6 else goto 11
006: A = P[38:4]
007: if (A == 3225682177) goto 8 else goto 11
008: A = length
009: if (A >= 100) goto 10 else goto 11
010: return 65535
011: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L3 end
   if 34 > length then return false end
   A = bit.bor(bit.lshift(P[30], 24),bit.lshift(P[30+1], 16), bit.lshift(P[30+2], 8), P[30+3])
   if (A==-1069285119) then goto L7 end
   goto L10
   ::L3::
   if (A==2054) then goto L5 end
   if not (A==32821) then goto L10 end
   ::L5::
   if 42 > length then return false end
   A = bit.bor(bit.lshift(P[38], 24),bit.lshift(P[38+1], 16), bit.lshift(P[38+2], 8), P[38+3])
   if not (A==-1069285119) then goto L10 end
   ::L7::
   A = bit.tobit(length)
   if not (runtime_u32(A)>=100) then goto L10 end
   do return true end
   ::L10::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local cast = require("ffi").cast
return function(P,length)
   if length < 100 then return false end
   local v1 = cast("uint16_t*", P+12)[0]
   if v1 == 8 then
      return cast("uint32_t*", P+30)[0] == 16860352
   end
   if v1 == 1544 then goto L8 end
   do
      if v1 == 13696 then goto L8 end
      return false
   end
::L8::
   return cast("uint32_t*", P+38)[0] == 16860352
end

```

## Native pflang compilation

```
7fef1c598000  4883FE64          cmp rsi, +0x64
7fef1c598004  7C36              jl 0x7fef1c59803c
7fef1c598006  0FB7770C          movzx esi, word [rdi+0xc]
7fef1c59800a  4883FE08          cmp rsi, +0x08
7fef1c59800e  750E              jnz 0x7fef1c59801e
7fef1c598010  8B471E            mov eax, [rdi+0x1e]
7fef1c598013  4881F8C0440101    cmp rax, 0x010144c0
7fef1c59801a  7423              jz 0x7fef1c59803f
7fef1c59801c  EB1E              jmp 0x7fef1c59803c
7fef1c59801e  4881FE08060000    cmp rsi, 0x608
7fef1c598025  7409              jz 0x7fef1c598030
7fef1c598027  4881FE80350000    cmp rsi, 0x3580
7fef1c59802e  750C              jnz 0x7fef1c59803c
7fef1c598030  8B7726            mov esi, [rdi+0x26]
7fef1c598033  4881FEC0440101    cmp rsi, 0x010144c0
7fef1c59803a  7403              jz 0x7fef1c59803f
7fef1c59803c  B000              mov al, 0x0
7fef1c59803e  C3                ret
7fef1c59803f  B001              mov al, 0x1
7fef1c598041  C3                ret

```

