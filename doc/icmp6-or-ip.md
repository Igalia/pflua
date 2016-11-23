# icmp6 or ip


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 7
002: A = P[20:1]
003: if (A == 58) goto 8 else goto 4
004: if (A == 44) goto 5 else goto 9
005: A = P[54:1]
006: if (A == 58) goto 8 else goto 9
007: if (A == 2048) goto 8 else goto 9
008: return 65535
009: return 0
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
   if (A==58) then goto L7 end
   if not (A==44) then goto L8 end
   if 55 > length then return false end
   A = P[54]
   if (A==58) then goto L7 end
   goto L8
   ::L6::
   if not (A==2048) then goto L8 end
   ::L7::
   do return true end
   ::L8::
   do return false end
   error("end of bpf")
end
```


## Direct pflang compilation

```
local cast = require("ffi").cast
return function(P,length)
   if length < 14 then return false end
   if length < 54 then goto L7 end
   do
      if cast("uint16_t*", P+12)[0] ~= 56710 then goto L7 end
      local v1 = P[20]
      if v1 == 58 then return true end
      if length < 55 then goto L7 end
      if v1 ~= 44 then goto L7 end
      if P[54] == 58 then return true end
      goto L7
   end
::L7::
   return cast("uint16_t*", P+12)[0] == 8
end

```

## Native pflang compilation

```
7fb5a6be9000  4883FE0E          cmp rsi, +0x0e
7fb5a6be9004  7C41              jl 0x7fb5a6be9047
7fb5a6be9006  4883FE36          cmp rsi, +0x36
7fb5a6be900a  7C31              jl 0x7fb5a6be903d
7fb5a6be900c  0FB7470C          movzx eax, word [rdi+0xc]
7fb5a6be9010  4881F886DD0000    cmp rax, 0xdd86
7fb5a6be9017  7524              jnz 0x7fb5a6be903d
7fb5a6be9019  0FB64714          movzx eax, byte [rdi+0x14]
7fb5a6be901d  4883F83A          cmp rax, +0x3a
7fb5a6be9021  7502              jnz 0x7fb5a6be9025
7fb5a6be9023  EB25              jmp 0x7fb5a6be904a
7fb5a6be9025  4883FE37          cmp rsi, +0x37
7fb5a6be9029  7C12              jl 0x7fb5a6be903d
7fb5a6be902b  4883F82C          cmp rax, +0x2c
7fb5a6be902f  750C              jnz 0x7fb5a6be903d
7fb5a6be9031  0FB64736          movzx eax, byte [rdi+0x36]
7fb5a6be9035  4883F83A          cmp rax, +0x3a
7fb5a6be9039  7502              jnz 0x7fb5a6be903d
7fb5a6be903b  EB0D              jmp 0x7fb5a6be904a
7fb5a6be903d  0FB7470C          movzx eax, word [rdi+0xc]
7fb5a6be9041  4883F808          cmp rax, +0x08
7fb5a6be9045  7403              jz 0x7fb5a6be904a
7fb5a6be9047  B000              mov al, 0x0
7fb5a6be9049  C3                ret
7fb5a6be904a  B001              mov al, 0x1
7fb5a6be904c  C3                ret

```

