# proto 47


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 4
002: A = P[23:1]
003: if (A == 47) goto 10 else goto 11
004: if (A == 34525) goto 5 else goto 11
005: A = P[20:1]
006: if (A == 47) goto 10 else goto 7
007: if (A == 44) goto 8 else goto 11
008: A = P[54:1]
009: if (A == 47) goto 10 else goto 11
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
   if 24 > length then return false end
   A = P[23]
   if (A==47) then goto L9 end
   goto L10
   ::L3::
   if not (A==34525) then goto L10 end
   if 21 > length then return false end
   A = P[20]
   if (A==47) then goto L9 end
   if not (A==44) then goto L10 end
   if 55 > length then return false end
   A = P[54]
   if not (A==47) then goto L10 end
   ::L9::
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
   if v1 ~= 8 then goto L7 end
   do
      if P[23] == 47 then return true end
      goto L7
   end
::L7::
   if length < 54 then return false end
   if v1 ~= 56710 then return false end
   local v2 = P[20]
   if v2 == 47 then return true end
   if length < 55 then return false end
   if v2 ~= 44 then return false end
   return P[54] == 47
end

```

## Native pflang compilation

```
7fde5d687000  4883FE22          cmp rsi, +0x22
7fde5d687004  7C43              jl 0x7fde5d687049
7fde5d687006  0FB7470C          movzx eax, word [rdi+0xc]
7fde5d68700a  4883F808          cmp rax, +0x08
7fde5d68700e  750A              jnz 0x7fde5d68701a
7fde5d687010  0FB64F17          movzx ecx, byte [rdi+0x17]
7fde5d687014  4883F92F          cmp rcx, +0x2f
7fde5d687018  7432              jz 0x7fde5d68704c
7fde5d68701a  4883FE36          cmp rsi, +0x36
7fde5d68701e  7C29              jl 0x7fde5d687049
7fde5d687020  4881F886DD0000    cmp rax, 0xdd86
7fde5d687027  7520              jnz 0x7fde5d687049
7fde5d687029  0FB64714          movzx eax, byte [rdi+0x14]
7fde5d68702d  4883F82F          cmp rax, +0x2f
7fde5d687031  7419              jz 0x7fde5d68704c
7fde5d687033  4883FE37          cmp rsi, +0x37
7fde5d687037  7C10              jl 0x7fde5d687049
7fde5d687039  4883F82C          cmp rax, +0x2c
7fde5d68703d  750A              jnz 0x7fde5d687049
7fde5d68703f  0FB64736          movzx eax, byte [rdi+0x36]
7fde5d687043  4883F82F          cmp rax, +0x2f
7fde5d687047  7403              jz 0x7fde5d68704c
7fde5d687049  B000              mov al, 0x0
7fde5d68704b  C3                ret
7fde5d68704c  B001              mov al, 0x1
7fde5d68704e  C3                ret

```

