# ether[&tcp[0]] = tcp[0]


## BPF

```
Filter failed to compile: ../src/pf/libpcap.lua:66: pcap_compile failed```


## BPF cross-compiled to Lua

```
Filter failed to compile: ../src/pf/libpcap.lua:66: pcap_compile failed
```


## Direct pflang compilation

```
local lshift = require("bit").lshift
local band = require("bit").band
local cast = require("ffi").cast
return function(P,length)
   if length < 54 then return false end
   if cast("uint16_t*", P+12)[0] ~= 8 then return false end
   if P[23] ~= 6 then return false end
   if band(cast("uint16_t*", P+20)[0],65311) ~= 0 then return false end
   local v1 = lshift(band(P[14],15),2)
   if (v1 + 15) > length then return false end
   local v2 = P[(v1 + 14)]
   return v2 == v2
end

```

## Native pflang compilation

```
7f033fccf000  4883FE36          cmp rsi, +0x36
7f033fccf004  7C49              jl 0x7f033fccf04f
7f033fccf006  0FB7470C          movzx eax, word [rdi+0xc]
7f033fccf00a  4883F808          cmp rax, +0x08
7f033fccf00e  753F              jnz 0x7f033fccf04f
7f033fccf010  0FB64717          movzx eax, byte [rdi+0x17]
7f033fccf014  4883F806          cmp rax, +0x06
7f033fccf018  7535              jnz 0x7f033fccf04f
7f033fccf01a  0FB74714          movzx eax, word [rdi+0x14]
7f033fccf01e  4881E01FFF0000    and rax, 0xff1f
7f033fccf025  4883F800          cmp rax, +0x00
7f033fccf029  7524              jnz 0x7f033fccf04f
7f033fccf02b  0FB6470E          movzx eax, byte [rdi+0xe]
7f033fccf02f  4883E00F          and rax, +0x0f
7f033fccf033  48C1E002          shl rax, 0x02
7f033fccf037  89C1              mov ecx, eax
7f033fccf039  4883C10F          add rcx, +0x0f
7f033fccf03d  4839F1            cmp rcx, rsi
7f033fccf040  7F0D              jg 0x7f033fccf04f
7f033fccf042  4883C00E          add rax, +0x0e
7f033fccf046  0FB60407          movzx eax, byte [rdi+rax]
7f033fccf04a  4839C0            cmp rax, rax
7f033fccf04d  7403              jz 0x7f033fccf052
7f033fccf04f  B000              mov al, 0x0
7f033fccf051  C3                ret
7f033fccf052  B001              mov al, 0x1
7f033fccf054  C3                ret

```

