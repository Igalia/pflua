# src host 192.68.1.1 and less 100


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 4
002: A = P[26:4]
003: if (A == 3225682177) goto 8 else goto 11
004: if (A == 2054) goto 6 else goto 5
005: if (A == 32821) goto 6 else goto 11
006: A = P[28:4]
007: if (A == 3225682177) goto 8 else goto 11
008: A = length
009: if (A > 100) goto 11 else goto 10
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
   if 30 > length then return false end
   A = bit.bor(bit.lshift(P[26], 24),bit.lshift(P[26+1], 16), bit.lshift(P[26+2], 8), P[26+3])
   if (A==-1069285119) then goto L7 end
   goto L10
   ::L3::
   if (A==2054) then goto L5 end
   if not (A==32821) then goto L10 end
   ::L5::
   if 32 > length then return false end
   A = bit.bor(bit.lshift(P[28], 24),bit.lshift(P[28+1], 16), bit.lshift(P[28+2], 8), P[28+3])
   if not (A==-1069285119) then goto L10 end
   ::L7::
   A = bit.tobit(length)
   if (runtime_u32(A)>100) then goto L10 end
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
   if length < 34 then return false end
   local v1 = cast("uint16_t*", P+12)[0]
   if v1 == 8 then
      if cast("uint32_t*", P+26)[0] == 16860352 then goto L6 end
      goto L7
   else
      if length < 42 then return false end
      if v1 == 1544 then goto L12 end
      do
         if v1 == 13696 then goto L12 end
         return false
      end
::L12::
      if cast("uint32_t*", P+28)[0] == 16860352 then goto L6 end
      goto L7
   end
::L6::
   do
      return length <= 100
   end
::L7::
   return false
end

```

## Native pflang compilation

```
7faa9eb0a000  4883FE22          cmp rsi, +0x22
7faa9eb0a004  7C42              jl 0x7faa9eb0a048
7faa9eb0a006  0FB7470C          movzx eax, word [rdi+0xc]
7faa9eb0a00a  4883F808          cmp rax, +0x08
7faa9eb0a00e  750E              jnz 0x7faa9eb0a01e
7faa9eb0a010  8B4F1A            mov ecx, [rdi+0x1a]
7faa9eb0a013  4881F9C0440101    cmp rcx, 0x010144c0
7faa9eb0a01a  7426              jz 0x7faa9eb0a042
7faa9eb0a01c  EB2A              jmp 0x7faa9eb0a048
7faa9eb0a01e  4883FE2A          cmp rsi, +0x2a
7faa9eb0a022  7C24              jl 0x7faa9eb0a048
7faa9eb0a024  4881F808060000    cmp rax, 0x608
7faa9eb0a02b  7409              jz 0x7faa9eb0a036
7faa9eb0a02d  4881F880350000    cmp rax, 0x3580
7faa9eb0a034  7512              jnz 0x7faa9eb0a048
7faa9eb0a036  8B471C            mov eax, [rdi+0x1c]
7faa9eb0a039  4881F8C0440101    cmp rax, 0x010144c0
7faa9eb0a040  7506              jnz 0x7faa9eb0a048
7faa9eb0a042  4883FE64          cmp rsi, +0x64
7faa9eb0a046  7E03              jle 0x7faa9eb0a04b
7faa9eb0a048  B000              mov al, 0x0
7faa9eb0a04a  C3                ret
7faa9eb0a04b  B001              mov al, 0x1
7faa9eb0a04d  C3                ret

```

