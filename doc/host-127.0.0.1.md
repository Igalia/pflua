# host 127.0.0.1


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 6
002: A = P[26:4]
003: if (A == 2130706433) goto 12 else goto 4
004: A = P[30:4]
005: if (A == 2130706433) goto 12 else goto 13
006: if (A == 2054) goto 8 else goto 7
007: if (A == 32821) goto 8 else goto 13
008: A = P[28:4]
009: if (A == 2130706433) goto 12 else goto 10
010: A = P[38:4]
011: if (A == 2130706433) goto 12 else goto 13
012: return 65535
013: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L5 end
   if 30 > length then return 0 end
   A = bit.bor(bit.lshift(P[26], 24),bit.lshift(P[26+1], 16), bit.lshift(P[26+2], 8), P[26+3])
   if (A==2130706433) then goto L11 end
   if 34 > length then return 0 end
   A = bit.bor(bit.lshift(P[30], 24),bit.lshift(P[30+1], 16), bit.lshift(P[30+2], 8), P[30+3])
   if (A==2130706433) then goto L11 end
   goto L12
   ::L5::
   if (A==2054) then goto L7 end
   if not (A==32821) then goto L12 end
   ::L7::
   if 32 > length then return 0 end
   A = bit.bor(bit.lshift(P[28], 24),bit.lshift(P[28+1], 16), bit.lshift(P[28+2], 8), P[28+3])
   if (A==2130706433) then goto L11 end
   if 42 > length then return 0 end
   A = bit.bor(bit.lshift(P[38], 24),bit.lshift(P[38+1], 16), bit.lshift(P[38+2], 8), P[38+3])
   if not (A==2130706433) then goto L12 end
   ::L11::
   do return 65535 end
   ::L12::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (14 <= length) then return false end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 8) then goto L3 end
      do
         if not (30 <= length) then return false end
         do
            local v2 = ffi.cast("uint32_t*", P+26)[0]
            local v3 = bit.bswap(v2)
            local v4 = v3%4294967296
            if v4 == 16777343 then goto L2 end
         end
      end
::L3::
      do
         if not (v1 == 1544) then goto L6 end
         do
            if not (32 <= length) then return false end
            do
               local v5 = ffi.cast("uint32_t*", P+28)[0]
               local v6 = bit.bswap(v5)
               local v7 = v6%4294967296
               if v7 == 16777343 then goto L2 end
            end
         end
::L6::
         do
            if not (32 <= length) then return false end
            do
               if not (v1 == 13696) then return false end
               do
                  local v8 = ffi.cast("uint32_t*", P+28)[0]
                  local v9 = bit.bswap(v8)
                  local v10 = v9%4294967296
                  if not (v10 == 16777343) then return false end
               end
            end
         end
      end
::L2::
      do
         if not (v1 == 8) then goto L11 end
         do
            if not (34 <= length) then return false end
            do
               local v11 = ffi.cast("uint32_t*", P+30)[0]
               local v12 = bit.bswap(v11)
               local v13 = v12%4294967296
               if v13 == 16777343 then return true end
            end
         end
::L11::
         do
            if not (v1 == 1544) then goto L14 end
            do
               if not (42 <= length) then return false end
               do
                  local v14 = ffi.cast("uint32_t*", P+38)[0]
                  local v15 = bit.bswap(v14)
                  local v16 = v15%4294967296
                  if v16 == 16777343 then return true end
               end
            end
::L14::
            do
               if not (42 <= length) then return false end
               do
                  if not (v1 == 13696) then return false end
                  do
                     local v17 = ffi.cast("uint32_t*", P+38)[0]
                     local v18 = bit.bswap(v17)
                     local v19 = v18%4294967296
                     do return v19 == 16777343 end
                  end
               end
            end
         end
      end
   end
end
```

