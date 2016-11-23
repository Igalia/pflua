# host 127.0.0.1


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 6
002: A = P[26:4]
003: if (A == 2130706433) goto 12 else goto 4
004: A = P[30:4]
005: if (A == 2130706433) goto 12 else goto 13
006: if (A == 2054) goto 8 else goto 7
007: if (A == 32821) goto 8 else goto 13
008: A = P[28:4]
009: if (A == 2130706433) goto 12 else goto 10
010: A = P[38:4]
011: if (A == 2130706433) goto 12 else goto 13
012: return 65535
013: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L5 end
   if 30 > length then return false end
   A = bit.bor(bit.lshift(P[26], 24),bit.lshift(P[26+1], 16), bit.lshift(P[26+2], 8), P[26+3])
   if (A==2130706433) then goto L11 end
   if 34 > length then return false end
   A = bit.bor(bit.lshift(P[30], 24),bit.lshift(P[30+1], 16), bit.lshift(P[30+2], 8), P[30+3])
   if (A==2130706433) then goto L11 end
   goto L12
   ::L5::
   if (A==2054) then goto L7 end
   if not (A==32821) then goto L12 end
   ::L7::
   if 32 > length then return false end
   A = bit.bor(bit.lshift(P[28], 24),bit.lshift(P[28+1], 16), bit.lshift(P[28+2], 8), P[28+3])
   if (A==2130706433) then goto L11 end
   if 42 > length then return false end
   A = bit.bor(bit.lshift(P[38], 24),bit.lshift(P[38+1], 16), bit.lshift(P[38+2], 8), P[38+3])
   if not (A==2130706433) then goto L12 end
   ::L11::
   do return true end
   ::L12::
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
      if cast("uint32_t*", P+26)[0] == 16777343 then return true end
      return cast("uint32_t*", P+30)[0] == 16777343
   else
      if length < 42 then return false end
      if v1 == 1544 then goto L12 end
      do
         if v1 == 13696 then goto L12 end
         return false
      end
::L12::
      if cast("uint32_t*", P+28)[0] == 16777343 then return true end
      return cast("uint32_t*", P+38)[0] == 16777343
   end
end

```

## Native pflang compilation

```
7f0e14af5000  4883FE22          cmp rsi, +0x22
7f0e14af5004  0F8C58000000      jl 0x7f0e14af5062
7f0e14af500a  0FB7470C          movzx eax, word [rdi+0xc]
7f0e14af500e  4883F808          cmp rax, +0x08
7f0e14af5012  751C              jnz 0x7f0e14af5030
7f0e14af5014  8B4F1A            mov ecx, [rdi+0x1a]
7f0e14af5017  4881F97F000001    cmp rcx, 0x0100007f
7f0e14af501e  7502              jnz 0x7f0e14af5022
7f0e14af5020  EB43              jmp 0x7f0e14af5065
7f0e14af5022  8B4F1E            mov ecx, [rdi+0x1e]
7f0e14af5025  4881F97F000001    cmp rcx, 0x0100007f
7f0e14af502c  7437              jz 0x7f0e14af5065
7f0e14af502e  EB32              jmp 0x7f0e14af5062
7f0e14af5030  4883FE2A          cmp rsi, +0x2a
7f0e14af5034  7C2C              jl 0x7f0e14af5062
7f0e14af5036  4881F808060000    cmp rax, 0x608
7f0e14af503d  7409              jz 0x7f0e14af5048
7f0e14af503f  4881F880350000    cmp rax, 0x3580
7f0e14af5046  751A              jnz 0x7f0e14af5062
7f0e14af5048  8B471C            mov eax, [rdi+0x1c]
7f0e14af504b  4881F87F000001    cmp rax, 0x0100007f
7f0e14af5052  7502              jnz 0x7f0e14af5056
7f0e14af5054  EB0F              jmp 0x7f0e14af5065
7f0e14af5056  8B4726            mov eax, [rdi+0x26]
7f0e14af5059  4881F87F000001    cmp rax, 0x0100007f
7f0e14af5060  7403              jz 0x7f0e14af5065
7f0e14af5062  B000              mov al, 0x0
7f0e14af5064  C3                ret
7f0e14af5065  B001              mov al, 0x1
7f0e14af5067  C3                ret

```

