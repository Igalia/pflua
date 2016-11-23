# sctp


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 7
002: A = P[20:1]
003: if (A == 132) goto 10 else goto 4
004: if (A == 44) goto 5 else goto 11
005: A = P[54:1]
006: if (A == 132) goto 10 else goto 11
007: if (A == 2048) goto 8 else goto 11
008: A = P[23:1]
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
   if not (A==34525) then goto L6 end
   if 21 > length then return false end
   A = P[20]
   if (A==132) then goto L9 end
   if not (A==44) then goto L10 end
   if 55 > length then return false end
   A = P[54]
   if (A==132) then goto L9 end
   goto L10
   ::L6::
   if not (A==2048) then goto L10 end
   if 24 > length then return false end
   A = P[23]
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
   if v1 == 8 then
      return P[23] == 132
   end
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
7f5f7444d000  4883FE22          cmp rsi, +0x22
7f5f7444d004  7C50              jl 0x7f5f7444d056
7f5f7444d006  0FB7470C          movzx eax, word [rdi+0xc]
7f5f7444d00a  4883F808          cmp rax, +0x08
7f5f7444d00e  750F              jnz 0x7f5f7444d01f
7f5f7444d010  0FB64F17          movzx ecx, byte [rdi+0x17]
7f5f7444d014  4881F984000000    cmp rcx, 0x84
7f5f7444d01b  743C              jz 0x7f5f7444d059
7f5f7444d01d  EB37              jmp 0x7f5f7444d056
7f5f7444d01f  4883FE36          cmp rsi, +0x36
7f5f7444d023  7C31              jl 0x7f5f7444d056
7f5f7444d025  4881F886DD0000    cmp rax, 0xdd86
7f5f7444d02c  7528              jnz 0x7f5f7444d056
7f5f7444d02e  0FB64714          movzx eax, byte [rdi+0x14]
7f5f7444d032  4881F884000000    cmp rax, 0x84
7f5f7444d039  7502              jnz 0x7f5f7444d03d
7f5f7444d03b  EB1C              jmp 0x7f5f7444d059
7f5f7444d03d  4883FE37          cmp rsi, +0x37
7f5f7444d041  7C13              jl 0x7f5f7444d056
7f5f7444d043  4883F82C          cmp rax, +0x2c
7f5f7444d047  750D              jnz 0x7f5f7444d056
7f5f7444d049  0FB64736          movzx eax, byte [rdi+0x36]
7f5f7444d04d  4881F884000000    cmp rax, 0x84
7f5f7444d054  7403              jz 0x7f5f7444d059
7f5f7444d056  B000              mov al, 0x0
7f5f7444d058  C3                ret
7f5f7444d059  B001              mov al, 0x1
7f5f7444d05b  C3                ret

```

