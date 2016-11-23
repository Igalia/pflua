# ether multicast


## BPF

```
000: A = P[0:1]
001: if (A & 1 != 0) goto 2 else goto 3
002: return 65535
003: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 1 > length then return false end
   A = P[0]
   if (bit.band(A, 1)==0) then goto L2 end
   do return true end
   ::L2::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local band = require("bit").band
return function(P,length)
   if length < 1 then return false end
   return band(P[0],1) ~= 0
end

```

## Native pflang compilation

```
7f0ef84b0000  4883FE01          cmp rsi, +0x01
7f0ef84b0004  7C0D              jl 0x7f0ef84b0013
7f0ef84b0006  0FB637            movzx esi, byte [rdi]
7f0ef84b0009  4883E601          and rsi, +0x01
7f0ef84b000d  4883FE00          cmp rsi, +0x00
7f0ef84b0011  7503              jnz 0x7f0ef84b0016
7f0ef84b0013  B000              mov al, 0x0
7f0ef84b0015  C3                ret
7f0ef84b0016  B001              mov al, 0x1
7f0ef84b0018  C3                ret

```

