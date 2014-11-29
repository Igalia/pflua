# dst portrange 80-90


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 132) goto 6 else goto 4
004: if (A == 6) goto 6 else goto 5
005: if (A == 17) goto 6 else goto 20
006: A = P[56:2]
007: if (A >= 80) goto 18 else goto 20
008: if (A == 2048) goto 9 else goto 20
009: A = P[23:1]
010: if (A == 132) goto 13 else goto 11
011: if (A == 6) goto 13 else goto 12
012: if (A == 17) goto 13 else goto 20
013: A = P[20:2]
014: if (A & 8191 != 0) goto 20 else goto 15
015: X = (P[14:1] & 0xF) << 2
016: A = P[X+16:2]
017: if (A >= 80) goto 18 else goto 20
018: if (A > 90) goto 20 else goto 19
019: return 65535
020: return 0
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
   if (A==132) then goto L5 end
   if (A==6) then goto L5 end
   if not (A==17) then goto L19 end
   ::L5::
   if 58 > length then return 0 end
   A = bit.bor(bit.lshift(P[56], 8), P[56+1])
   if (runtime_u32(A)>=80) then goto L17 end
   goto L19
   ::L7::
   if not (A==2048) then goto L19 end
   if 24 > length then return 0 end
   A = P[23]
   if (A==132) then goto L12 end
   if (A==6) then goto L12 end
   if not (A==17) then goto L19 end
   ::L12::
   if 22 > length then return 0 end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if not (bit.band(A, 8191)==0) then goto L19 end
   if 14 >= length then return 0 end
   X = bit.lshift(bit.band(P[14], 15), 2)
   T = bit.tobit((X+16))
   if T < 0 or T + 2 > length then return 0 end
   A = bit.bor(bit.lshift(P[T], 8), P[T+1])
   if not (runtime_u32(A)>=80) then goto L19 end
   ::L17::
   if (runtime_u32(A)>90) then goto L19 end
   do return 65535 end
   ::L19::
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
      if not (v1 == 8) then goto L3 end
      do
         local v2 = P[23]
         if v2 == 6 then goto L4 end
         do
            if v2 == 17 then goto L4 end
            do
               if not (v2 == 132) then do return false end end
            end
         end
::L4::
         do
            local v3 = ffi.cast("uint16_t*", P+20)[0]
            local v4 = bit.band(v3,65311)
            if not (v4 == 0) then do return false end end
            do
               local v5 = P[14]
               local v6 = bit.band(v5,15)
               local v7 = bit.lshift(v6,2)
               local v8 = v7 + 18
               if not (v8 <= length) then do return false end end
               do
                  local v9 = v7 + 16
                  local v10 = ffi.cast("uint16_t*", P+v9)[0]
                  local v11 = bit.rshift(bit.bswap(v10), 16)
                  if not (v11 >= 80) then do return false end end
                  do
                     do return v11 <= 90 end
                  end
               end
            end
         end
      end
::L3::
      do
         if not (length >= 58) then do return false end end
         do
            if not (v1 == 56710) then do return false end end
            do
               local v12 = P[20]
               if v12 == 6 then goto L12 end
               do
                  if not (v12 == 44) then goto L13 end
                  do
                     local v13 = P[54]
                     if v13 == 6 then goto L12 end
                  end
               end
::L13::
               do
                  if v12 == 17 then goto L12 end
                  do
                     if not (v12 == 44) then goto L16 end
                     do
                        local v14 = P[54]
                        if v14 == 17 then goto L12 end
                     end
                  end
::L16::
                  do
                     if v12 == 132 then goto L12 end
                     do
                        if not (v12 == 44) then do return false end end
                        do
                           local v15 = P[54]
                           if not (v15 == 132) then do return false end end
                        end
                     end
                  end
               end
::L12::
               do
                  local v16 = ffi.cast("uint16_t*", P+56)[0]
                  local v17 = bit.rshift(bit.bswap(v16), 16)
                  if not (v17 >= 80) then do return false end end
                  do
                     do return v17 <= 90 end
                  end
               end
            end
         end
      end
   end
end
```

