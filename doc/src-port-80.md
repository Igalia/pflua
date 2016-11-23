# src port 80


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 132) goto 6 else goto 4
004: if (A == 6) goto 6 else goto 5
005: if (A == 17) goto 6 else goto 19
006: A = P[54:2]
007: if (A == 80) goto 18 else goto 19
008: if (A == 2048) goto 9 else goto 19
009: A = P[23:1]
010: if (A == 132) goto 13 else goto 11
011: if (A == 6) goto 13 else goto 12
012: if (A == 17) goto 13 else goto 19
013: A = P[20:2]
014: if (A & 8191 != 0) goto 19 else goto 15
015: X = (P[14:1] & 0xF) << 2
016: A = P[X+14:2]
017: if (A == 80) goto 18 else goto 19
018: return 65535
019: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   local X = 0
   local T = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L7 end
   if 21 > length then return false end
   A = P[20]
   if (A==132) then goto L5 end
   if (A==6) then goto L5 end
   if not (A==17) then goto L18 end
   ::L5::
   if 56 > length then return false end
   A = bit.bor(bit.lshift(P[54], 8), P[54+1])
   if (A==80) then goto L17 end
   goto L18
   ::L7::
   if not (A==2048) then goto L18 end
   if 24 > length then return false end
   A = P[23]
   if (A==132) then goto L12 end
   if (A==6) then goto L12 end
   if not (A==17) then goto L18 end
   ::L12::
   if 22 > length then return false end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L18 end
   if 14 >= length then return false end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+14))
   if T < 0 or T + 2 > length then return false end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if not (A==80) then goto L18 end
   ::L17::
   do return true end
   ::L18::
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
   if length < 34 then return false end
   local v1 = cast("uint16_t*", P+12)[0]
   if v1 == 8 then
      local v2 = P[23]
      if v2 == 6 then goto L8 end
      do
         if v2 == 17 then goto L8 end
         if v2 == 132 then goto L8 end
         return false
      end
::L8::
      if band(cast("uint16_t*", P+20)[0],65311) ~= 0 then return false end
      local v3 = lshift(band(P[14],15),2)
      if (v3 + 16) > length then return false end
      return cast("uint16_t*", P+(v3 + 14))[0] == 20480
   else
      if length < 56 then return false end
      if v1 ~= 56710 then return false end
      local v4 = P[20]
      if v4 == 6 then goto L22 end
      do
         if v4 ~= 44 then goto L25 end
         do
            if P[54] == 6 then goto L22 end
            goto L25
         end
::L25::
         if v4 == 17 then goto L22 end
         if v4 ~= 44 then goto L31 end
         do
            if P[54] == 17 then goto L22 end
            goto L31
         end
::L31::
         if v4 == 132 then goto L22 end
         if v4 ~= 44 then return false end
         if P[54] == 132 then goto L22 end
         return false
      end
::L22::
      return cast("uint16_t*", P+54)[0] == 20480
   end
end

```

## Native pflang compilation

```
7f18bf2dd000  4883FE22          cmp rsi, +0x22
7f18bf2dd004  0F8CE1000000      jl 0x7f18bf2dd0eb
7f18bf2dd00a  0FB7470C          movzx eax, word [rdi+0xc]
7f18bf2dd00e  4883F808          cmp rax, +0x08
7f18bf2dd012  7567              jnz 0x7f18bf2dd07b
7f18bf2dd014  0FB64F17          movzx ecx, byte [rdi+0x17]
7f18bf2dd018  4883F906          cmp rcx, +0x06
7f18bf2dd01c  7413              jz 0x7f18bf2dd031
7f18bf2dd01e  4883F911          cmp rcx, +0x11
7f18bf2dd022  740D              jz 0x7f18bf2dd031
7f18bf2dd024  4881F984000000    cmp rcx, 0x84
7f18bf2dd02b  0F85BA000000      jnz 0x7f18bf2dd0eb
7f18bf2dd031  0FB74F14          movzx ecx, word [rdi+0x14]
7f18bf2dd035  4881E11FFF0000    and rcx, 0xff1f
7f18bf2dd03c  4883F900          cmp rcx, +0x00
7f18bf2dd040  0F85A5000000      jnz 0x7f18bf2dd0eb
7f18bf2dd046  0FB64F0E          movzx ecx, byte [rdi+0xe]
7f18bf2dd04a  4883E10F          and rcx, +0x0f
7f18bf2dd04e  48C1E102          shl rcx, 0x02
7f18bf2dd052  89CA              mov edx, ecx
7f18bf2dd054  4883C210          add rdx, +0x10
7f18bf2dd058  4839F2            cmp rdx, rsi
7f18bf2dd05b  0F8F8A000000      jg 0x7f18bf2dd0eb
7f18bf2dd061  4883C10E          add rcx, +0x0e
7f18bf2dd065  0FB70C0F          movzx ecx, word [rdi+rcx]
7f18bf2dd069  4881F900500000    cmp rcx, 0x5000
7f18bf2dd070  0F8478000000      jz 0x7f18bf2dd0ee
7f18bf2dd076  E970000000        jmp 0x7f18bf2dd0eb
7f18bf2dd07b  4883FE38          cmp rsi, +0x38
7f18bf2dd07f  0F8C66000000      jl 0x7f18bf2dd0eb
7f18bf2dd085  4881F886DD0000    cmp rax, 0xdd86
7f18bf2dd08c  0F8559000000      jnz 0x7f18bf2dd0eb
7f18bf2dd092  0FB64714          movzx eax, byte [rdi+0x14]
7f18bf2dd096  4883F806          cmp rax, +0x06
7f18bf2dd09a  7442              jz 0x7f18bf2dd0de
7f18bf2dd09c  4883F82C          cmp rax, +0x2c
7f18bf2dd0a0  750A              jnz 0x7f18bf2dd0ac
7f18bf2dd0a2  0FB67736          movzx esi, byte [rdi+0x36]
7f18bf2dd0a6  4883FE06          cmp rsi, +0x06
7f18bf2dd0aa  7432              jz 0x7f18bf2dd0de
7f18bf2dd0ac  4883F811          cmp rax, +0x11
7f18bf2dd0b0  742C              jz 0x7f18bf2dd0de
7f18bf2dd0b2  4883F82C          cmp rax, +0x2c
7f18bf2dd0b6  750A              jnz 0x7f18bf2dd0c2
7f18bf2dd0b8  0FB67736          movzx esi, byte [rdi+0x36]
7f18bf2dd0bc  4883FE11          cmp rsi, +0x11
7f18bf2dd0c0  741C              jz 0x7f18bf2dd0de
7f18bf2dd0c2  4881F884000000    cmp rax, 0x84
7f18bf2dd0c9  7413              jz 0x7f18bf2dd0de
7f18bf2dd0cb  4883F82C          cmp rax, +0x2c
7f18bf2dd0cf  751A              jnz 0x7f18bf2dd0eb
7f18bf2dd0d1  0FB64736          movzx eax, byte [rdi+0x36]
7f18bf2dd0d5  4881F884000000    cmp rax, 0x84
7f18bf2dd0dc  750D              jnz 0x7f18bf2dd0eb
7f18bf2dd0de  0FB74736          movzx eax, word [rdi+0x36]
7f18bf2dd0e2  4881F800500000    cmp rax, 0x5000
7f18bf2dd0e9  7403              jz 0x7f18bf2dd0ee
7f18bf2dd0eb  B000              mov al, 0x0
7f18bf2dd0ed  C3                ret
7f18bf2dd0ee  B001              mov al, 0x1
7f18bf2dd0f0  C3                ret

```

