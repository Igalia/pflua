# net ::0/16


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 7
002: A = P[22:4]
003: if (A & -65536 != 0) goto 4 else goto 6
004: A = P[38:4]
005: if (A & -65536 != 0) goto 7 else goto 6
006: return 65535
007: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L6 end
   if 26 > length then return 0 end
   A = bit.bor(bit.lshift(P[22], 24),bit.lshift(P[22+1], 16), bit.lshift(P[22+2], 8), P[22+3])
   if (bit.band(A, -65536)==0) then goto L5 end
   if 42 > length then return 0 end
   A = bit.bor(bit.lshift(P[38], 24),bit.lshift(P[38+1], 16), bit.lshift(P[38+2], 8), P[38+3])
   if not (bit.band(A, -65536)==0) then goto L6 end
   ::L5::
   do return 65535 end
   ::L6::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (length >= 54) then do return false end end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 56710) then do return false end end
      do
         local v2 = ffi.cast("uint32_t*", P+22)[0]
         local v3 = bit.band(v2,65535)
         if v3 == 0 then do return true end end
         do
            local v4 = ffi.cast("uint32_t*", P+38)[0]
            local v5 = bit.band(v4,65535)
            do return v5 == 0 end
         end
      end
   end
end
```

