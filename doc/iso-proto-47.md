# iso proto 47


## BPF

```
000: A = P[12:2]
001: if (A > 1500) goto 7 else goto 2
002: A = P[14:2]
003: if (A == 65278) goto 4 else goto 7
004: A = P[17:1]
005: if (A == 47) goto 6 else goto 7
006: return 65535
007: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if (runtime_u32(A)>1500) then goto L6 end
   if 16 > length then return 0 end
   A = bit.bor(bit.lshift(P[14], 8), P[14+1])
   if not (A==65278) then goto L6 end
   if 18 > length then return 0 end
   A = P[17]
   if not (A==47) then goto L6 end
   do return 65535 end
   ::L6::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (length >= 18) then do return false end end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      local v2 = bit.rshift(bit.bswap(v1), 16)
      if not (v2 <= 1500) then do return false end end
      do
         local v3 = ffi.cast("uint16_t*", P+14)[0]
         if not (v3 == 65278) then do return false end end
         do
            local v4 = P[17]
            do return v4 == 47 end
         end
      end
   end
end
```

