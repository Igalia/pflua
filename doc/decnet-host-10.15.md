# decnet host 10.15


## BPF

```
000: A = P[12:2]
001: if (A == 24579) goto 2 else goto 43
002: A = P[16:1]
003: A &= 7
004: if (A == 2) goto 5 else goto 7
005: A = P[19:2]
006: if (A == 3880) goto 42 else goto 7
007: A = P[16:2]
008: A &= 65287
009: if (A == 33026) goto 10 else goto 12
010: A = P[20:2]
011: if (A == 3880) goto 42 else goto 12
012: A = P[16:1]
013: A &= 7
014: if (A == 6) goto 15 else goto 17
015: A = P[31:2]
016: if (A == 3880) goto 42 else goto 17
017: A = P[16:2]
018: A &= 65287
019: if (A == 33030) goto 20 else goto 22
020: A = P[32:2]
021: if (A == 3880) goto 42 else goto 22
022: A = P[16:1]
023: A &= 7
024: if (A == 2) goto 25 else goto 27
025: A = P[17:2]
026: if (A == 3880) goto 42 else goto 27
027: A = P[16:2]
028: A &= 65287
029: if (A == 33026) goto 30 else goto 32
030: A = P[18:2]
031: if (A == 3880) goto 42 else goto 32
032: A = P[16:1]
033: A &= 7
034: if (A == 6) goto 35 else goto 37
035: A = P[23:2]
036: if (A == 3880) goto 42 else goto 37
037: A = P[16:2]
038: A &= 65287
039: if (A == 33030) goto 40 else goto 43
040: A = P[24:2]
041: if (A == 3880) goto 42 else goto 43
042: return 65535
043: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==24579) then goto L42 end
   if 17 > length then return false end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==2) then goto L6 end
   if 21 > length then return false end
   A = bit.bor(bit.lshift(P[19], 8), P[19+1])
   if (A==3880) then goto L41 end
   ::L6::
   if 18 > length then return false end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33026) then goto L11 end
   if 22 > length then return false end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if (A==3880) then goto L41 end
   ::L11::
   if 17 > length then return false end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==6) then goto L16 end
   if 33 > length then return false end
   A = bit.bor(bit.lshift(P[31], 8), P[31+1])
   if (A==3880) then goto L41 end
   ::L16::
   if 18 > length then return false end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33030) then goto L21 end
   if 34 > length then return false end
   A = bit.bor(bit.lshift(P[32], 8), P[32+1])
   if (A==3880) then goto L41 end
   ::L21::
   if 17 > length then return false end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==2) then goto L26 end
   if 19 > length then return false end
   A = bit.bor(bit.lshift(P[17], 8), P[17+1])
   if (A==3880) then goto L41 end
   ::L26::
   if 18 > length then return false end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33026) then goto L31 end
   if 20 > length then return false end
   A = bit.bor(bit.lshift(P[18], 8), P[18+1])
   if (A==3880) then goto L41 end
   ::L31::
   if 17 > length then return false end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==6) then goto L36 end
   if 25 > length then return false end
   A = bit.bor(bit.lshift(P[23], 8), P[23+1])
   if (A==3880) then goto L41 end
   ::L36::
   if 18 > length then return false end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33030) then goto L42 end
   if 26 > length then return false end
   A = bit.bor(bit.lshift(P[24], 8), P[24+1])
   if not (A==3880) then goto L42 end
   ::L41::
   do return true end
   ::L42::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local band = require("bit").band
local cast = require("ffi").cast
return function(P,length)
   if length < 21 then return false end
   local v1 = band(P[16],7)
   if v1 == 2 then
      if cast("uint16_t*", P+19)[0] == 3850 then return true end
      return cast("uint16_t*", P+17)[0] == 3850
   else
      if length < 22 then return false end
      local v2 = band(cast("uint16_t*", P+16)[0],2047)
      if v2 == 641 then
         if cast("uint16_t*", P+20)[0] == 3850 then return true end
         return cast("uint16_t*", P+18)[0] == 3850
      else
         if length < 33 then return false end
         if v1 == 6 then
            if cast("uint16_t*", P+31)[0] == 3850 then return true end
            return cast("uint16_t*", P+23)[0] == 3850
         else
            if length < 34 then return false end
            if v2 ~= 1665 then return false end
            if cast("uint16_t*", P+32)[0] == 3850 then return true end
            return cast("uint16_t*", P+24)[0] == 3850
         end
      end
   end
end

```

## Native pflang compilation

```
7efeeea6d000  4883FE15          cmp rsi, +0x15
7efeeea6d004  0F8CCE000000      jl 0x7efeeea6d0d8
7efeeea6d00a  0FB64710          movzx eax, byte [rdi+0x10]
7efeeea6d00e  4883E007          and rax, +0x07
7efeeea6d012  4883F802          cmp rax, +0x02
7efeeea6d016  7528              jnz 0x7efeeea6d040
7efeeea6d018  0FB74F13          movzx ecx, word [rdi+0x13]
7efeeea6d01c  4881F90A0F0000    cmp rcx, 0xf0a
7efeeea6d023  7505              jnz 0x7efeeea6d02a
7efeeea6d025  E9B1000000        jmp 0x7efeeea6d0db
7efeeea6d02a  0FB74F11          movzx ecx, word [rdi+0x11]
7efeeea6d02e  4881F90A0F0000    cmp rcx, 0xf0a
7efeeea6d035  0F84A0000000      jz 0x7efeeea6d0db
7efeeea6d03b  E998000000        jmp 0x7efeeea6d0d8
7efeeea6d040  4883FE16          cmp rsi, +0x16
7efeeea6d044  0F8C8E000000      jl 0x7efeeea6d0d8
7efeeea6d04a  0FB74F10          movzx ecx, word [rdi+0x10]
7efeeea6d04e  4881E1FF070000    and rcx, 0x7ff
7efeeea6d055  4881F981020000    cmp rcx, 0x281
7efeeea6d05c  7525              jnz 0x7efeeea6d083
7efeeea6d05e  0FB75714          movzx edx, word [rdi+0x14]
7efeeea6d062  4881FA0A0F0000    cmp rdx, 0xf0a
7efeeea6d069  7505              jnz 0x7efeeea6d070
7efeeea6d06b  E96B000000        jmp 0x7efeeea6d0db
7efeeea6d070  0FB75712          movzx edx, word [rdi+0x12]
7efeeea6d074  4881FA0A0F0000    cmp rdx, 0xf0a
7efeeea6d07b  0F845A000000      jz 0x7efeeea6d0db
7efeeea6d081  EB55              jmp 0x7efeeea6d0d8
7efeeea6d083  4883FE21          cmp rsi, +0x21
7efeeea6d087  7C4F              jl 0x7efeeea6d0d8
7efeeea6d089  4883F806          cmp rax, +0x06
7efeeea6d08d  751E              jnz 0x7efeeea6d0ad
7efeeea6d08f  0FB7471F          movzx eax, word [rdi+0x1f]
7efeeea6d093  4881F80A0F0000    cmp rax, 0xf0a
7efeeea6d09a  7502              jnz 0x7efeeea6d09e
7efeeea6d09c  EB3D              jmp 0x7efeeea6d0db
7efeeea6d09e  0FB74717          movzx eax, word [rdi+0x17]
7efeeea6d0a2  4881F80A0F0000    cmp rax, 0xf0a
7efeeea6d0a9  7430              jz 0x7efeeea6d0db
7efeeea6d0ab  EB2B              jmp 0x7efeeea6d0d8
7efeeea6d0ad  4883FE22          cmp rsi, +0x22
7efeeea6d0b1  7C25              jl 0x7efeeea6d0d8
7efeeea6d0b3  4881F981060000    cmp rcx, 0x681
7efeeea6d0ba  751C              jnz 0x7efeeea6d0d8
7efeeea6d0bc  0FB74F20          movzx ecx, word [rdi+0x20]
7efeeea6d0c0  4881F90A0F0000    cmp rcx, 0xf0a
7efeeea6d0c7  7502              jnz 0x7efeeea6d0cb
7efeeea6d0c9  EB10              jmp 0x7efeeea6d0db
7efeeea6d0cb  0FB74F18          movzx ecx, word [rdi+0x18]
7efeeea6d0cf  4881F90A0F0000    cmp rcx, 0xf0a
7efeeea6d0d6  7403              jz 0x7efeeea6d0db
7efeeea6d0d8  B000              mov al, 0x0
7efeeea6d0da  C3                ret
7efeeea6d0db  B001              mov al, 0x1
7efeeea6d0dd  C3                ret

```

