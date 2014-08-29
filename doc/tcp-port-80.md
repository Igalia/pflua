# tcp port 80


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 6) goto 4 else goto 19
004: A = P[54:2]
005: if (A == 80) goto 18 else goto 6
006: A = P[56:2]
007: if (A == 80) goto 18 else goto 19
008: if (A == 2048) goto 9 else goto 19
009: A = P[23:1]
010: if (A == 6) goto 11 else goto 19
011: A = P[20:2]
012: if (A & 8191 != 0) goto 19 else goto 13
013: X = (P[14:1] & 0xF) << 2
014: A = P[X+14:2]
015: if (A == 80) goto 18 else goto 16
016: A = P[X+16:2]
017: if (A == 80) goto 18 else goto 19
018: return 65535
019: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   local X = 0
   local T = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L7 end
   if 21 > length then return 0 end
   A = P[20]
   if not (A==6) then goto L18 end
   if 56 > length then return 0 end
   A = bit.bor(bit.lshift(P[54], 8), P[54+1])
   if (A==80) then goto L17 end
   if 58 > length then return 0 end
   A = bit.bor(bit.lshift(P[56], 8), P[56+1])
   if (A==80) then goto L17 end
   goto L18
   ::L7::
   if not (A==2048) then goto L18 end
   if 24 > length then return 0 end
   A = P[23]
   if not (A==6) then goto L18 end
   if 22 > length then return 0 end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L18 end
   if 14 >= length then return 0 end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+14))
   if T < 0 or T + 2 > length then return 0 end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if (A==80) then goto L17 end
   T = bit.tobit((X+16))
   if T < 0 or T + 2 > length then return 0 end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if not (A==80) then goto L18 end
   ::L17::
   do return 65535 end
   ::L18::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (length >= 24) then return false end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 8) then goto L3 end
      do
         local v2 = P[23]
         if not (v2 == 6) then return false end
         do
            local v3 = ffi.cast("uint16_t*", P+20)[0]
            local v4 = bit.band(v3,65311)
            if not (v4 == 0) then return false end
            do
               local v5 = P[14]
               local v6 = bit.band(v5,15)
               local v7 = bit.lshift(v6,2)
               local v8 = v7+16
               if not (v8 <= length) then return false end
               do
                  local v9 = v7+14
                  local v10 = ffi.cast("uint16_t*", P+v9)[0]
                  if v10 == 20480 then return true end
                  do
                     local v11 = v7+18
                     if not (v11 <= length) then return false end
                     do
                        local v12 = ffi.cast("uint16_t*", P+v8)[0]
                        do return v12 == 20480 end
                     end
                  end
               end
            end
         end
      end
::L3::
      do
         if not (length >= 56) then return false end
         do
            if not (v1 == 56710) then return false end
            do
               local v13 = P[20]
               if v13 == 6 then goto L11 end
               do
                  if not (v13 == 44) then return false end
                  do
                     local v14 = P[54]
                     if not (v14 == 6) then return false end
                  end
               end
::L11::
               do
                  local v15 = ffi.cast("uint16_t*", P+54)[0]
                  if v15 == 20480 then return true end
                  do
                     if not (length >= 58) then return false end
                     do
                        local v16 = ffi.cast("uint16_t*", P+56)[0]
                        do return v16 == 20480 end
                     end
                  end
               end
            end
         end
      end
   end
end
```

