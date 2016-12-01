# icmp or tcp or udp


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 5
002: A = P[23:1]
003: if (A == 1) goto 12 else goto 4
004: if (A == 6) goto 12 else goto 11
005: if (A == 34525) goto 6 else goto 13
006: A = P[20:1]
007: if (A == 6) goto 12 else goto 8
008: if (A == 44) goto 9 else goto 11
009: A = P[54:1]
010: if (A == 6) goto 12 else goto 11
011: if (A == 17) goto 12 else goto 13
012: return 65535
013: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return false end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L4 end
   if 24 > length then return false end
   A = P[23]
   if (A==1) then goto L11 end
   if (A==6) then goto L11 end
   goto L10
   ::L4::
   if not (A==34525) then goto L12 end
   if 21 > length then return false end
   A = P[20]
   if (A==6) then goto L11 end
   if not (A==44) then goto L10 end
   if 55 > length then return false end
   A = P[54]
   if (A==6) then goto L11 end
   ::L10::
   if not (A==17) then goto L12 end
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
      local v2 = P[23]
      if v2 == 1 then return true end
      if v2 == 6 then return true end
      return v2 == 17
   else
      if length < 54 then return false end
      if v1 ~= 56710 then return false end
      local v3 = P[20]
      if v3 == 1 then return true end
      if length < 55 then goto L19 end
      do
         if v3 ~= 44 then goto L19 end
         if P[54] == 1 then return true end
         goto L19
      end
::L19::
      if v3 == 6 then return true end
      if length < 55 then goto L17 end
      do
         if v3 ~= 44 then goto L17 end
         if P[54] == 6 then return true end
         goto L17
      end
::L17::
      if v3 == 17 then return true end
      if length < 55 then return false end
      if v3 ~= 44 then return false end
      return P[54] == 17
   end
end

```

## Native pflang compilation

```
7f2faa4a1000  4883FE22          cmp rsi, +0x22
7f2faa4a1004  0F8CA0000000      jl 0x7f2faa4a10aa
7f2faa4a100a  0FB7470C          movzx eax, word [rdi+0xc]
7f2faa4a100e  4883F808          cmp rax, +0x08
7f2faa4a1012  7527              jnz 0x7f2faa4a103b
7f2faa4a1014  0FB64F17          movzx ecx, byte [rdi+0x17]
7f2faa4a1018  4883F901          cmp rcx, +0x01
7f2faa4a101c  0F848B000000      jz 0x7f2faa4a10ad
7f2faa4a1022  4883F906          cmp rcx, +0x06
7f2faa4a1026  0F8481000000      jz 0x7f2faa4a10ad
7f2faa4a102c  4883F911          cmp rcx, +0x11
7f2faa4a1030  0F8477000000      jz 0x7f2faa4a10ad
7f2faa4a1036  E96F000000        jmp 0x7f2faa4a10aa
7f2faa4a103b  4883FE36          cmp rsi, +0x36
7f2faa4a103f  0F8C65000000      jl 0x7f2faa4a10aa
7f2faa4a1045  4881F886DD0000    cmp rax, 0xdd86
7f2faa4a104c  0F8558000000      jnz 0x7f2faa4a10aa
7f2faa4a1052  0FB64714          movzx eax, byte [rdi+0x14]
7f2faa4a1056  4883F801          cmp rax, +0x01
7f2faa4a105a  7451              jz 0x7f2faa4a10ad
7f2faa4a105c  4883FE37          cmp rsi, +0x37
7f2faa4a1060  7C10              jl 0x7f2faa4a1072
7f2faa4a1062  4883F82C          cmp rax, +0x2c
7f2faa4a1066  750A              jnz 0x7f2faa4a1072
7f2faa4a1068  0FB64F36          movzx ecx, byte [rdi+0x36]
7f2faa4a106c  4883F901          cmp rcx, +0x01
7f2faa4a1070  743B              jz 0x7f2faa4a10ad
7f2faa4a1072  4883F806          cmp rax, +0x06
7f2faa4a1076  7435              jz 0x7f2faa4a10ad
7f2faa4a1078  4883FE37          cmp rsi, +0x37
7f2faa4a107c  7C10              jl 0x7f2faa4a108e
7f2faa4a107e  4883F82C          cmp rax, +0x2c
7f2faa4a1082  750A              jnz 0x7f2faa4a108e
7f2faa4a1084  0FB64F36          movzx ecx, byte [rdi+0x36]
7f2faa4a1088  4883F906          cmp rcx, +0x06
7f2faa4a108c  741F              jz 0x7f2faa4a10ad
7f2faa4a108e  4883F811          cmp rax, +0x11
7f2faa4a1092  7419              jz 0x7f2faa4a10ad
7f2faa4a1094  4883FE37          cmp rsi, +0x37
7f2faa4a1098  7C10              jl 0x7f2faa4a10aa
7f2faa4a109a  4883F82C          cmp rax, +0x2c
7f2faa4a109e  750A              jnz 0x7f2faa4a10aa
7f2faa4a10a0  0FB64736          movzx eax, byte [rdi+0x36]
7f2faa4a10a4  4883F811          cmp rax, +0x11
7f2faa4a10a8  7403              jz 0x7f2faa4a10ad
7f2faa4a10aa  B000              mov al, 0x0
7f2faa4a10ac  C3                ret
7f2faa4a10ad  B001              mov al, 0x1
7f2faa4a10af  C3                ret

```

