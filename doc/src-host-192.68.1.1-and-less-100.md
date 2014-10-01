# src host 192.68.1.1 and less 100


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 4
002: A = P[26:4]
003: if (A == -1069285119) goto 8 else goto 11
004: if (A == 2054) goto 6 else goto 5
005: if (A == 32821) goto 6 else goto 11
006: A = P[28:4]
007: if (A == -1069285119) goto 8 else goto 11
008: A = length
009: if (A > 100) goto 11 else goto 10
010: return 65535
011: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L3 end
   if 30 > length then return 0 end
   A = bit.bor(bit.lshift(P[26], 24),bit.lshift(P[26+1], 16), bit.lshift(P[26+2], 8), P[26+3])
   if (A==-1069285119) then goto L7 end
   goto L10
   ::L3::
   if (A==2054) then goto L5 end
   if not (A==32821) then goto L10 end
   ::L5::
   if 32 > length then return 0 end
   A = bit.bor(bit.lshift(P[28], 24),bit.lshift(P[28+1], 16), bit.lshift(P[28+2], 8), P[28+3])
   if not (A==-1069285119) then goto L10 end
   ::L7::
   A = bit.tobit(length)
   if (runtime_u32(A)>100) then goto L10 end
   do return 65535 end
   ::L10::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (length >= 34) then do return false end end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 8) then goto L4 end
      do
         local v2 = ffi.cast("uint32_t*", P+26)[0]
         if v2 == 16860352 then goto L2 end
         do do return false end end
      end
::L4::
      do
         if not (length >= 42) then do return false end end
         do
            if v1 == 1544 then goto L6 end
            do
               if not (v1 == 13696) then do return false end end
            end
::L6::
            do
               local v3 = ffi.cast("uint32_t*", P+28)[0]
               if not (v3 == 16860352) then do return false end end
            end
         end
      end
::L2::
      do
         do return length <= 100 end
      end
   end
end
```

