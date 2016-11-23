# pim[8] < 8


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 10
002: A = P[23:1]
003: if (A == 103) goto 4 else goto 10
004: A = P[20:2]
005: if (A & 8191 != 0) goto 10 else goto 6
006: X = (P[14:1] & 0xF) << 2
007: A = P[X+22:1]
008: if (A >= 8) goto 10 else goto 9
009: return 65535
010: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   local X = 0
   local T = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L9 end
   if 24 > length then return false end
   A = P[23]
   if not (A==103) then goto L9 end
   if 22 > length then return false end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L9 end
   if 14 >= length then return false end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+22))
   if T < 0 or T + 1 > length then return false end
   A = P[T]
   if (runtime_u32(A)>=8) then goto L9 end
   do return true end
   ::L9::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local lshift = require("bit").lshift
local band = require("bit").band
local cast = require("ffi").cast
return function(P,length)
   if length < 38 then return false end
   if cast("uint16_t*", P+12)[0] ~= 8 then return false end
   if P[23] ~= 103 then return false end
   if band(cast("uint16_t*", P+20)[0],65311) ~= 0 then return false end
   local v1 = lshift(band(P[14],15),2)
   if (v1 + 23) > length then return false end
   return P[(v1 + 22)] < 8
end

```

## Native pflang compilation

```
7fe14fed1000  4883FE26          cmp rsi, +0x26
7fe14fed1004  7C4A              jl 0x7fe14fed1050
7fe14fed1006  0FB7470C          movzx eax, word [rdi+0xc]
7fe14fed100a  4883F808          cmp rax, +0x08
7fe14fed100e  7540              jnz 0x7fe14fed1050
7fe14fed1010  0FB64717          movzx eax, byte [rdi+0x17]
7fe14fed1014  4883F867          cmp rax, +0x67
7fe14fed1018  7536              jnz 0x7fe14fed1050
7fe14fed101a  0FB74714          movzx eax, word [rdi+0x14]
7fe14fed101e  4881E01FFF0000    and rax, 0xff1f
7fe14fed1025  4883F800          cmp rax, +0x00
7fe14fed1029  7525              jnz 0x7fe14fed1050
7fe14fed102b  0FB6470E          movzx eax, byte [rdi+0xe]
7fe14fed102f  4883E00F          and rax, +0x0f
7fe14fed1033  48C1E002          shl rax, 0x02
7fe14fed1037  89C1              mov ecx, eax
7fe14fed1039  4883C117          add rcx, +0x17
7fe14fed103d  4839F1            cmp rcx, rsi
7fe14fed1040  7F0E              jg 0x7fe14fed1050
7fe14fed1042  4883C016          add rax, +0x16
7fe14fed1046  0FB60407          movzx eax, byte [rdi+rax]
7fe14fed104a  4883F808          cmp rax, +0x08
7fe14fed104e  7C03              jl 0x7fe14fed1053
7fe14fed1050  B000              mov al, 0x0
7fe14fed1052  C3                ret
7fe14fed1053  B001              mov al, 0x1
7fe14fed1055  C3                ret

```

