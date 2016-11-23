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
7f7978204000  4883FE22          cmp rsi, +0x22
7f7978204004  0F8CAF000000      jl 0x7f79782040b9
7f797820400a  0FB7470C          movzx eax, word [rdi+0xc]
7f797820400e  4883F808          cmp rax, +0x08
7f7978204012  7529              jnz 0x7f797820403d
7f7978204014  0FB64F17          movzx ecx, byte [rdi+0x17]
7f7978204018  4883F901          cmp rcx, +0x01
7f797820401c  7505              jnz 0x7f7978204023
7f797820401e  E999000000        jmp 0x7f79782040bc
7f7978204023  4883F906          cmp rcx, +0x06
7f7978204027  7505              jnz 0x7f797820402e
7f7978204029  E98E000000        jmp 0x7f79782040bc
7f797820402e  4883F911          cmp rcx, +0x11
7f7978204032  0F8484000000      jz 0x7f79782040bc
7f7978204038  E97C000000        jmp 0x7f79782040b9
7f797820403d  4883FE36          cmp rsi, +0x36
7f7978204041  0F8C72000000      jl 0x7f79782040b9
7f7978204047  4881F886DD0000    cmp rax, 0xdd86
7f797820404e  0F8565000000      jnz 0x7f79782040b9
7f7978204054  0FB64714          movzx eax, byte [rdi+0x14]
7f7978204058  4883F801          cmp rax, +0x01
7f797820405c  7505              jnz 0x7f7978204063
7f797820405e  E959000000        jmp 0x7f79782040bc
7f7978204063  4883FE37          cmp rsi, +0x37
7f7978204067  7C12              jl 0x7f797820407b
7f7978204069  4883F82C          cmp rax, +0x2c
7f797820406d  750C              jnz 0x7f797820407b
7f797820406f  0FB64F36          movzx ecx, byte [rdi+0x36]
7f7978204073  4883F901          cmp rcx, +0x01
7f7978204077  7502              jnz 0x7f797820407b
7f7978204079  EB41              jmp 0x7f79782040bc
7f797820407b  4883F806          cmp rax, +0x06
7f797820407f  7502              jnz 0x7f7978204083
7f7978204081  EB39              jmp 0x7f79782040bc
7f7978204083  4883FE37          cmp rsi, +0x37
7f7978204087  7C12              jl 0x7f797820409b
7f7978204089  4883F82C          cmp rax, +0x2c
7f797820408d  750C              jnz 0x7f797820409b
7f797820408f  0FB64F36          movzx ecx, byte [rdi+0x36]
7f7978204093  4883F906          cmp rcx, +0x06
7f7978204097  7502              jnz 0x7f797820409b
7f7978204099  EB21              jmp 0x7f79782040bc
7f797820409b  4883F811          cmp rax, +0x11
7f797820409f  7502              jnz 0x7f79782040a3
7f79782040a1  EB19              jmp 0x7f79782040bc
7f79782040a3  4883FE37          cmp rsi, +0x37
7f79782040a7  7C10              jl 0x7f79782040b9
7f79782040a9  4883F82C          cmp rax, +0x2c
7f79782040ad  750A              jnz 0x7f79782040b9
7f79782040af  0FB64736          movzx eax, byte [rdi+0x36]
7f79782040b3  4883F811          cmp rax, +0x11
7f79782040b7  7403              jz 0x7f79782040bc
7f79782040b9  B000              mov al, 0x0
7f79782040bb  C3                ret
7f79782040bc  B001              mov al, 0x1
7f79782040be  C3                ret

```

