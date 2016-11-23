# portrange 0-6000


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 11
002: A = P[20:1]
003: if (A == 132) goto 6 else goto 4
004: if (A == 6) goto 6 else goto 5
005: if (A == 17) goto 6 else goto 26
006: A = P[54:2]
007: if (A >= 0) goto 8 else goto 9
008: if (A > 6000) goto 9 else goto 25
009: A = P[56:2]
010: if (A >= 0) goto 24 else goto 26
011: if (A == 2048) goto 12 else goto 26
012: A = P[23:1]
013: if (A == 132) goto 16 else goto 14
014: if (A == 6) goto 16 else goto 15
015: if (A == 17) goto 16 else goto 26
016: A = P[20:2]
017: if (A & 8191 != 0) goto 26 else goto 18
018: X = (P[14:1] & 0xF) << 2
019: A = P[X+14:2]
020: if (A >= 0) goto 21 else goto 22
021: if (A > 6000) goto 22 else goto 25
022: A = P[X+16:2]
023: if (A >= 0) goto 24 else goto 26
024: if (A > 6000) goto 26 else goto 25
025: return 65535
026: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   local X = 0
   local T = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L10 end
   if 21 > length then return false end
   A = P[20]
   if (A==132) then goto L5 end
   if (A==6) then goto L5 end
   if not (A==17) then goto L25 end
   ::L5::
   if 56 > length then return false end
   A = bit.bor(bit.lshift(P[54], 8), P[54+1])
   if not (runtime_u32(A)>=0) then goto L8 end
   if not (runtime_u32(A)>6000) then goto L24 end
   ::L8::
   if 58 > length then return false end
   A = bit.bor(bit.lshift(P[56], 8), P[56+1])
   if (runtime_u32(A)>=0) then goto L23 end
   goto L25
   ::L10::
   if not (A==2048) then goto L25 end
   if 24 > length then return false end
   A = P[23]
   if (A==132) then goto L15 end
   if (A==6) then goto L15 end
   if not (A==17) then goto L25 end
   ::L15::
   if 22 > length then return false end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L25 end
   if 14 >= length then return false end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+14))
   if T < 0 or T + 2 > length then return false end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if not (runtime_u32(A)>=0) then goto L21 end
   if not (runtime_u32(A)>6000) then goto L24 end
   ::L21::
   T = bit.tobit((X+16))
   if T < 0 or T + 2 > length then return false end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if not (runtime_u32(A)>=0) then goto L25 end
   ::L23::
   if (runtime_u32(A)>6000) then goto L25 end
   ::L24::
   do return true end
   ::L25::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local rshift = require("bit").rshift
local bswap = require("bit").bswap
local cast = require("ffi").cast
local lshift = require("bit").lshift
local band = require("bit").band
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
      local v4 = (v3 + 16)
      if v4 > length then return false end
      if rshift(bswap(cast("uint16_t*", P+(v3 + 14))[0]), 16) <= 6000 then return true end
      if (v3 + 18) > length then return false end
      return rshift(bswap(cast("uint16_t*", P+v4)[0]), 16) <= 6000
   else
      if length < 56 then return false end
      if v1 ~= 56710 then return false end
      local v5 = P[20]
      if v5 == 6 then goto L26 end
      do
         if v5 ~= 44 then goto L29 end
         do
            if P[54] == 6 then goto L26 end
            goto L29
         end
::L29::
         if v5 == 17 then goto L26 end
         if v5 ~= 44 then goto L35 end
         do
            if P[54] == 17 then goto L26 end
            goto L35
         end
::L35::
         if v5 == 132 then goto L26 end
         if v5 ~= 44 then return false end
         if P[54] == 132 then goto L26 end
         return false
      end
::L26::
      if rshift(bswap(cast("uint16_t*", P+54)[0]), 16) <= 6000 then return true end
      if length < 58 then return false end
      return rshift(bswap(cast("uint16_t*", P+56)[0]), 16) <= 6000
   end
end

```

## Native pflang compilation

```
7f9924bdb000  4883FE22          cmp rsi, +0x22
7f9924bdb004  0F8C3E010000      jl 0x7f9924bdb148
7f9924bdb00a  0FB7470C          movzx eax, word [rdi+0xc]
7f9924bdb00e  4883F808          cmp rax, +0x08
7f9924bdb012  0F859B000000      jnz 0x7f9924bdb0b3
7f9924bdb018  0FB64F17          movzx ecx, byte [rdi+0x17]
7f9924bdb01c  4883F906          cmp rcx, +0x06
7f9924bdb020  7413              jz 0x7f9924bdb035
7f9924bdb022  4883F911          cmp rcx, +0x11
7f9924bdb026  740D              jz 0x7f9924bdb035
7f9924bdb028  4881F984000000    cmp rcx, 0x84
7f9924bdb02f  0F8513010000      jnz 0x7f9924bdb148
7f9924bdb035  0FB74F14          movzx ecx, word [rdi+0x14]
7f9924bdb039  4881E11FFF0000    and rcx, 0xff1f
7f9924bdb040  4883F900          cmp rcx, +0x00
7f9924bdb044  0F85FE000000      jnz 0x7f9924bdb148
7f9924bdb04a  0FB64F0E          movzx ecx, byte [rdi+0xe]
7f9924bdb04e  4883E10F          and rcx, +0x0f
7f9924bdb052  48C1E102          shl rcx, 0x02
7f9924bdb056  89CA              mov edx, ecx
7f9924bdb058  4883C210          add rdx, +0x10
7f9924bdb05c  4839F2            cmp rdx, rsi
7f9924bdb05f  0F8FE3000000      jg 0x7f9924bdb148
7f9924bdb065  4189C8            mov r8d, ecx
7f9924bdb068  4983C00E          add r8, +0x0e
7f9924bdb06c  460FB70407        movzx r8d, word [rdi+r8]
7f9924bdb071  6641C1C808        ror r8w, 0x08
7f9924bdb076  4D0FB7C0          movzx r8, r8w
7f9924bdb07a  4981F870170000    cmp r8, 0x1770
7f9924bdb081  7F05              jg 0x7f9924bdb088
7f9924bdb083  E9C3000000        jmp 0x7f9924bdb14b
7f9924bdb088  4883C112          add rcx, +0x12
7f9924bdb08c  4839F1            cmp rcx, rsi
7f9924bdb08f  0F8FB3000000      jg 0x7f9924bdb148
7f9924bdb095  0FB71417          movzx edx, word [rdi+rdx]
7f9924bdb099  66C1CA08          ror dx, 0x08
7f9924bdb09d  480FB7D2          movzx rdx, dx
7f9924bdb0a1  4881FA70170000    cmp rdx, 0x1770
7f9924bdb0a8  0F8E9D000000      jle 0x7f9924bdb14b
7f9924bdb0ae  E995000000        jmp 0x7f9924bdb148
7f9924bdb0b3  4883FE38          cmp rsi, +0x38
7f9924bdb0b7  0F8C8B000000      jl 0x7f9924bdb148
7f9924bdb0bd  4881F886DD0000    cmp rax, 0xdd86
7f9924bdb0c4  0F857E000000      jnz 0x7f9924bdb148
7f9924bdb0ca  0FB64714          movzx eax, byte [rdi+0x14]
7f9924bdb0ce  4883F806          cmp rax, +0x06
7f9924bdb0d2  7442              jz 0x7f9924bdb116
7f9924bdb0d4  4883F82C          cmp rax, +0x2c
7f9924bdb0d8  750A              jnz 0x7f9924bdb0e4
7f9924bdb0da  0FB65736          movzx edx, byte [rdi+0x36]
7f9924bdb0de  4883FA06          cmp rdx, +0x06
7f9924bdb0e2  7432              jz 0x7f9924bdb116
7f9924bdb0e4  4883F811          cmp rax, +0x11
7f9924bdb0e8  742C              jz 0x7f9924bdb116
7f9924bdb0ea  4883F82C          cmp rax, +0x2c
7f9924bdb0ee  750A              jnz 0x7f9924bdb0fa
7f9924bdb0f0  0FB65736          movzx edx, byte [rdi+0x36]
7f9924bdb0f4  4883FA11          cmp rdx, +0x11
7f9924bdb0f8  741C              jz 0x7f9924bdb116
7f9924bdb0fa  4881F884000000    cmp rax, 0x84
7f9924bdb101  7413              jz 0x7f9924bdb116
7f9924bdb103  4883F82C          cmp rax, +0x2c
7f9924bdb107  753F              jnz 0x7f9924bdb148
7f9924bdb109  0FB64736          movzx eax, byte [rdi+0x36]
7f9924bdb10d  4881F884000000    cmp rax, 0x84
7f9924bdb114  7532              jnz 0x7f9924bdb148
7f9924bdb116  0FB74736          movzx eax, word [rdi+0x36]
7f9924bdb11a  66C1C808          ror ax, 0x08
7f9924bdb11e  480FB7C0          movzx rax, ax
7f9924bdb122  4881F870170000    cmp rax, 0x1770
7f9924bdb129  7F02              jg 0x7f9924bdb12d
7f9924bdb12b  EB1E              jmp 0x7f9924bdb14b
7f9924bdb12d  4883FE3A          cmp rsi, +0x3a
7f9924bdb131  7C15              jl 0x7f9924bdb148
7f9924bdb133  0FB77738          movzx esi, word [rdi+0x38]
7f9924bdb137  66C1CE08          ror si, 0x08
7f9924bdb13b  480FB7F6          movzx rsi, si
7f9924bdb13f  4881FE70170000    cmp rsi, 0x1770
7f9924bdb146  7E03              jle 0x7f9924bdb14b
7f9924bdb148  B000              mov al, 0x0
7f9924bdb14a  C3                ret
7f9924bdb14b  B001              mov al, 0x1
7f9924bdb14d  C3                ret

```

