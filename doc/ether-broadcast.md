# ether broadcast


## BPF

```
000: A = P[2:4]
001: if (A == 4294967295) goto 2 else goto 5
002: A = P[0:2]
003: if (A == 65535) goto 4 else goto 5
004: return 65535
005: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 6 > length then return false end
   A = bit.bor(bit.lshift(P[2], 24),bit.lshift(P[2+1], 16), bit.lshift(P[2+2], 8), P[2+3])
   if not (A==-1) then goto L4 end
   if 2 > length then return false end
   A = bit.bor(bit.lshift(P[0], 8), P[0+1])
   if not (A==65535) then goto L4 end
   do return true end
   ::L4::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local cast = require("ffi").cast
return function(P,length)
   if length < 6 then return false end
   if cast("uint16_t*", P+0)[0] ~= 65535 then return false end
   return cast("uint32_t*", P+2)[0] == 4294967295
end

```

## Native pflang compilation

```
7f61df45c000  4883FE06          cmp rsi, +0x06
7f61df45c004  7C1E              jl 0x7f61df45c024
7f61df45c006  0FB737            movzx esi, word [rdi]
7f61df45c009  4881FEFFFF0000    cmp rsi, 0xffff
7f61df45c010  7512              jnz 0x7f61df45c024
7f61df45c012  8B7702            mov esi, [rdi+0x2]
7f61df45c015  48B8FFFFFFFF0000. mov rax, 0x00000000ffffffff
7f61df45c01f  4839C6            cmp rsi, rax
7f61df45c022  7403              jz 0x7f61df45c027
7f61df45c024  B000              mov al, 0x0
7f61df45c026  C3                ret
7f61df45c027  B001              mov al, 0x1
7f61df45c029  C3                ret

```

