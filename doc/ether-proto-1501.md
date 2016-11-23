# ether proto 1501


## BPF

```
000: A = P[12:2]
001: if (A == 1501) goto 2 else goto 3
002: return 65535
003: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==1501) then goto L2 end
   do return true end
   ::L2::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local cast = require("ffi").cast
return function(P,length)
   if length < 14 then return false end
   return cast("uint16_t*", P+12)[0] == 56581
end

```

## Native pflang compilation

```
7f01050c6000  4883FE0E          cmp rsi, +0x0e
7f01050c6004  7C0D              jl 0x7f01050c6013
7f01050c6006  0FB7770C          movzx esi, word [rdi+0xc]
7f01050c600a  4881FE05DD0000    cmp rsi, 0xdd05
7f01050c6011  7403              jz 0x7f01050c6016
7f01050c6013  B000              mov al, 0x0
7f01050c6015  C3                ret
7f01050c6016  B001              mov al, 0x1
7f01050c6018  C3                ret

```

