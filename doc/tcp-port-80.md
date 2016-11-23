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
7f117b103000  4883FE22          cmp rsi, +0x22
7f117b103004  0F8CC9000000      jl 0x7f117b1030d3
7f117b10300a  0FB7470C          movzx eax, word [rdi+0xc]
7f117b10300e  4883F808          cmp rax, +0x08
7f117b103012  7574              jnz 0x7f117b103088
7f117b103014  0FB64F17          movzx ecx, byte [rdi+0x17]
7f117b103018  4883F906          cmp rcx, +0x06
7f117b10301c  0F85B1000000      jnz 0x7f117b1030d3
7f117b103022  0FB74F14          movzx ecx, word [rdi+0x14]
7f117b103026  4881E11FFF0000    and rcx, 0xff1f
7f117b10302d  4883F900          cmp rcx, +0x00
7f117b103031  0F859C000000      jnz 0x7f117b1030d3
7f117b103037  0FB64F0E          movzx ecx, byte [rdi+0xe]
7f117b10303b  4883E10F          and rcx, +0x0f
7f117b10303f  48C1E102          shl rcx, 0x02
7f117b103043  89CA              mov edx, ecx
7f117b103045  4883C210          add rdx, +0x10
7f117b103049  4839F2            cmp rdx, rsi
7f117b10304c  0F8F81000000      jg 0x7f117b1030d3
7f117b103052  4189C8            mov r8d, ecx
7f117b103055  4983C00E          add r8, +0x0e
7f117b103059  460FB70407        movzx r8d, word [rdi+r8]
7f117b10305e  4981F800500000    cmp r8, 0x5000
7f117b103065  7505              jnz 0x7f117b10306c
7f117b103067  E96A000000        jmp 0x7f117b1030d6
7f117b10306c  4883C112          add rcx, +0x12
7f117b103070  4839F1            cmp rcx, rsi
7f117b103073  0F8F5A000000      jg 0x7f117b1030d3
7f117b103079  0FB71417          movzx edx, word [rdi+rdx]
7f117b10307d  4881FA00500000    cmp rdx, 0x5000
7f117b103084  7450              jz 0x7f117b1030d6
7f117b103086  EB4B              jmp 0x7f117b1030d3
7f117b103088  4883FE38          cmp rsi, +0x38
7f117b10308c  7C45              jl 0x7f117b1030d3
7f117b10308e  4881F886DD0000    cmp rax, 0xdd86
7f117b103095  753C              jnz 0x7f117b1030d3
7f117b103097  0FB64714          movzx eax, byte [rdi+0x14]
7f117b10309b  4883F806          cmp rax, +0x06
7f117b10309f  7410              jz 0x7f117b1030b1
7f117b1030a1  4883F82C          cmp rax, +0x2c
7f117b1030a5  752C              jnz 0x7f117b1030d3
7f117b1030a7  0FB64736          movzx eax, byte [rdi+0x36]
7f117b1030ab  4883F806          cmp rax, +0x06
7f117b1030af  7522              jnz 0x7f117b1030d3
7f117b1030b1  0FB74736          movzx eax, word [rdi+0x36]
7f117b1030b5  4881F800500000    cmp rax, 0x5000
7f117b1030bc  7502              jnz 0x7f117b1030c0
7f117b1030be  EB16              jmp 0x7f117b1030d6
7f117b1030c0  4883FE3A          cmp rsi, +0x3a
7f117b1030c4  7C0D              jl 0x7f117b1030d3
7f117b1030c6  0FB77738          movzx esi, word [rdi+0x38]
7f117b1030ca  4881FE00500000    cmp rsi, 0x5000
7f117b1030d1  7403              jz 0x7f117b1030d6
7f117b1030d3  B000              mov al, 0x0
7f117b1030d5  C3                ret
7f117b1030d6  B001              mov al, 0x1
7f117b1030d8  C3                ret

```

