# ether proto \decnet


## BPF

```
000: A = P[12:2]
001: if (A == 24579) goto 2 else goto 3
002: return 65535
003: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==24579) then goto L2 end
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
   return cast("uint16_t*", P+12)[0] == 864
end

```

## Native pflang compilation

```
7f0378b38000  4883FE0E          cmp rsi, +0x0e
7f0378b38004  7C0D              jl 0x7f0378b38013
7f0378b38006  0FB7770C          movzx esi, word [rdi+0xc]
7f0378b3800a  4881FE60030000    cmp rsi, 0x360
7f0378b38011  7403              jz 0x7f0378b38016
7f0378b38013  B000              mov al, 0x0
7f0378b38015  C3                ret
7f0378b38016  B001              mov al, 0x1
7f0378b38018  C3                ret

```

