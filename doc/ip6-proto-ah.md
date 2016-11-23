# ip6 proto \ah


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 51) goto 7 else goto 4
004: if (A == 44) goto 5 else goto 8
005: A = P[54:1]
006: if (A == 51) goto 7 else goto 8
007: return 65535
008: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L7 end
   if 21 > length then return false end
   A = P[20]
   if (A==51) then goto L6 end
   if not (A==44) then goto L7 end
   if 55 > length then return false end
   A = P[54]
   if not (A==51) then goto L7 end
   ::L6::
   do return true end
   ::L7::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local cast = require("ffi").cast
return function(P,length)
   if length < 54 then return false end
   if cast("uint16_t*", P+12)[0] ~= 56710 then return false end
   local v1 = P[20]
   if v1 == 51 then return true end
   if length < 55 then return false end
   if v1 ~= 44 then return false end
   return P[54] == 51
end

```

## Native pflang compilation

```
7f1ec28f2000  4883FE36          cmp rsi, +0x36
7f1ec28f2004  7C2F              jl 0x7f1ec28f2035
7f1ec28f2006  0FB7470C          movzx eax, word [rdi+0xc]
7f1ec28f200a  4881F886DD0000    cmp rax, 0xdd86
7f1ec28f2011  7522              jnz 0x7f1ec28f2035
7f1ec28f2013  0FB64714          movzx eax, byte [rdi+0x14]
7f1ec28f2017  4883F833          cmp rax, +0x33
7f1ec28f201b  7502              jnz 0x7f1ec28f201f
7f1ec28f201d  EB19              jmp 0x7f1ec28f2038
7f1ec28f201f  4883FE37          cmp rsi, +0x37
7f1ec28f2023  7C10              jl 0x7f1ec28f2035
7f1ec28f2025  4883F82C          cmp rax, +0x2c
7f1ec28f2029  750A              jnz 0x7f1ec28f2035
7f1ec28f202b  0FB64736          movzx eax, byte [rdi+0x36]
7f1ec28f202f  4883F833          cmp rax, +0x33
7f1ec28f2033  7403              jz 0x7f1ec28f2038
7f1ec28f2035  B000              mov al, 0x0
7f1ec28f2037  C3                ret
7f1ec28f2038  B001              mov al, 0x1
7f1ec28f203a  C3                ret

```

