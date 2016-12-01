# tcp port 80


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 6) goto 4 else goto 19
004: A = P[54:2]
005: if (A == 80) goto 18 else goto 6
006: A = P[56:2]
007: if (A == 80) goto 18 else goto 19
008: if (A == 2048) goto 9 else goto 19
009: A = P[23:1]
010: if (A == 6) goto 11 else goto 19
011: A = P[20:2]
012: if (A & 8191 != 0) goto 19 else goto 13
013: X = (P[14:1] & 0xF) << 2
014: A = P[X+14:2]
015: if (A == 80) goto 18 else goto 16
016: A = P[X+16:2]
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
   if not (A==6) then goto L18 end
   if 56 > length then return false end
   A = bit.bor(bit.lshift(P[54], 8), P[54+1])
   if (A==80) then goto L17 end
   if 58 > length then return false end
   A = bit.bor(bit.lshift(P[56], 8), P[56+1])
   if (A==80) then goto L17 end
   goto L18
   ::L7::
   if not (A==2048) then goto L18 end
   if 24 > length then return false end
   A = P[23]
   if not (A==6) then goto L18 end
   if 22 > length then return false end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L18 end
   if 14 >= length then return false end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+14))
   if T < 0 or T + 2 > length then return false end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if (A==80) then goto L17 end
   T = bit.tobit((X+16))
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
      if P[23] ~= 6 then return false end
      if band(cast("uint16_t*", P+20)[0],65311) ~= 0 then return false end
      local v2 = lshift(band(P[14],15),2)
      local v3 = (v2 + 16)
      if v3 > length then return false end
      if cast("uint16_t*", P+(v2 + 14))[0] == 20480 then return true end
      if (v2 + 18) > length then return false end
      return cast("uint16_t*", P+v3)[0] == 20480
   else
      if length < 56 then return false end
      if v1 ~= 56710 then return false end
      local v4 = P[20]
      if v4 == 6 then goto L22 end
      do
         if v4 ~= 44 then return false end
         if P[54] == 6 then goto L22 end
         return false
      end
::L22::
      if cast("uint16_t*", P+54)[0] == 20480 then return true end
      if length < 58 then return false end
      return cast("uint16_t*", P+56)[0] == 20480
   end
end

```

## Native pflang compilation

```
7fbe86845000  4883FE22          cmp rsi, +0x22
7fbe86845004  0F8CC2000000      jl 0x7fbe868450cc
7fbe8684500a  0FB7470C          movzx eax, word [rdi+0xc]
7fbe8684500e  4883F808          cmp rax, +0x08
7fbe86845012  756F              jnz 0x7fbe86845083
7fbe86845014  0FB64F17          movzx ecx, byte [rdi+0x17]
7fbe86845018  4883F906          cmp rcx, +0x06
7fbe8684501c  0F85AA000000      jnz 0x7fbe868450cc
7fbe86845022  0FB74F14          movzx ecx, word [rdi+0x14]
7fbe86845026  4881E11FFF0000    and rcx, 0xff1f
7fbe8684502d  4883F900          cmp rcx, +0x00
7fbe86845031  0F8595000000      jnz 0x7fbe868450cc
7fbe86845037  0FB64F0E          movzx ecx, byte [rdi+0xe]
7fbe8684503b  4883E10F          and rcx, +0x0f
7fbe8684503f  48C1E102          shl rcx, 0x02
7fbe86845043  89CA              mov edx, ecx
7fbe86845045  4883C210          add rdx, +0x10
7fbe86845049  4839F2            cmp rdx, rsi
7fbe8684504c  0F8F7A000000      jg 0x7fbe868450cc
7fbe86845052  4189C8            mov r8d, ecx
7fbe86845055  4983C00E          add r8, +0x0e
7fbe86845059  460FB70407        movzx r8d, word [rdi+r8]
7fbe8684505e  4981F800500000    cmp r8, 0x5000
7fbe86845065  0F8464000000      jz 0x7fbe868450cf
7fbe8684506b  4883C112          add rcx, +0x12
7fbe8684506f  4839F1            cmp rcx, rsi
7fbe86845072  7F58              jg 0x7fbe868450cc
7fbe86845074  0FB71417          movzx edx, word [rdi+rdx]
7fbe86845078  4881FA00500000    cmp rdx, 0x5000
7fbe8684507f  744E              jz 0x7fbe868450cf
7fbe86845081  EB49              jmp 0x7fbe868450cc
7fbe86845083  4883FE38          cmp rsi, +0x38
7fbe86845087  7C43              jl 0x7fbe868450cc
7fbe86845089  4881F886DD0000    cmp rax, 0xdd86
7fbe86845090  753A              jnz 0x7fbe868450cc
7fbe86845092  0FB64714          movzx eax, byte [rdi+0x14]
7fbe86845096  4883F806          cmp rax, +0x06
7fbe8684509a  7410              jz 0x7fbe868450ac
7fbe8684509c  4883F82C          cmp rax, +0x2c
7fbe868450a0  752A              jnz 0x7fbe868450cc
7fbe868450a2  0FB64736          movzx eax, byte [rdi+0x36]
7fbe868450a6  4883F806          cmp rax, +0x06
7fbe868450aa  7520              jnz 0x7fbe868450cc
7fbe868450ac  0FB74736          movzx eax, word [rdi+0x36]
7fbe868450b0  4881F800500000    cmp rax, 0x5000
7fbe868450b7  7416              jz 0x7fbe868450cf
7fbe868450b9  4883FE3A          cmp rsi, +0x3a
7fbe868450bd  7C0D              jl 0x7fbe868450cc
7fbe868450bf  0FB77738          movzx esi, word [rdi+0x38]
7fbe868450c3  4881FE00500000    cmp rsi, 0x5000
7fbe868450ca  7403              jz 0x7fbe868450cf
7fbe868450cc  B000              mov al, 0x0
7fbe868450ce  C3                ret
7fbe868450cf  B001              mov al, 0x1
7fbe868450d1  C3                ret

```

