# proto \sctp


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 4
002: A = P[23:1]
003: if (A == 132) goto 10 else goto 11
004: if (A == 34525) goto 5 else goto 11
005: A = P[20:1]
006: if (A == 132) goto 10 else goto 7
007: if (A == 44) goto 8 else goto 11
008: A = P[54:1]
009: if (A == 132) goto 10 else goto 11
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
   if (A==132) then goto L9 end
   goto L10
   ::L3::
   if not (A==34525) then goto L10 end
   if 21 > length then return false end
   A = P[20]
   if (A==132) then goto L9 end
   if not (A==44) then goto L10 end
   if 55 > length then return false end
   A = P[54]
   if not (A==132) then goto L10 end
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
      if P[23] == 132 then return true end
      goto L7
   end
::L7::
   if length < 54 then return false end
   if v1 ~= 56710 then return false end
   local v2 = P[20]
   if v2 == 132 then return true end
   if length < 55 then return false end
   if v2 ~= 44 then return false end
   return P[54] == 132
end

```

## Native pflang compilation

```
7fc73f3c2000  4883FE22          cmp rsi, +0x22
7fc73f3c2004  7C4C              jl 0x7fc73f3c2052
7fc73f3c2006  0FB7470C          movzx eax, word [rdi+0xc]
7fc73f3c200a  4883F808          cmp rax, +0x08
7fc73f3c200e  750D              jnz 0x7fc73f3c201d
7fc73f3c2010  0FB64F17          movzx ecx, byte [rdi+0x17]
7fc73f3c2014  4881F984000000    cmp rcx, 0x84
7fc73f3c201b  7438              jz 0x7fc73f3c2055
7fc73f3c201d  4883FE36          cmp rsi, +0x36
7fc73f3c2021  7C2F              jl 0x7fc73f3c2052
7fc73f3c2023  4881F886DD0000    cmp rax, 0xdd86
7fc73f3c202a  7526              jnz 0x7fc73f3c2052
7fc73f3c202c  0FB64714          movzx eax, byte [rdi+0x14]
7fc73f3c2030  4881F884000000    cmp rax, 0x84
7fc73f3c2037  741C              jz 0x7fc73f3c2055
7fc73f3c2039  4883FE37          cmp rsi, +0x37
7fc73f3c203d  7C13              jl 0x7fc73f3c2052
7fc73f3c203f  4883F82C          cmp rax, +0x2c
7fc73f3c2043  750D              jnz 0x7fc73f3c2052
7fc73f3c2045  0FB64736          movzx eax, byte [rdi+0x36]
7fc73f3c2049  4881F884000000    cmp rax, 0x84
7fc73f3c2050  7403              jz 0x7fc73f3c2055
7fc73f3c2052  B000              mov al, 0x0
7fc73f3c2054  C3                ret
7fc73f3c2055  B001              mov al, 0x1
7fc73f3c2057  C3                ret

```

