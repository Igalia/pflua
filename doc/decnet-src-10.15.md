# decnet src 10.15


## BPF

```
000: A = P[12:2]
001: if (A == 24579) goto 2 else goto 23
002: A = P[16:1]
003: A &= 7
004: if (A == 2) goto 5 else goto 7
005: A = P[19:2]
006: if (A == 3880) goto 22 else goto 7
007: A = P[16:2]
008: A &= 65287
009: if (A == 33026) goto 10 else goto 12
010: A = P[20:2]
011: if (A == 3880) goto 22 else goto 12
012: A = P[16:1]
013: A &= 7
014: if (A == 6) goto 15 else goto 17
015: A = P[31:2]
016: if (A == 3880) goto 22 else goto 17
017: A = P[16:2]
018: A &= 65287
019: if (A == 33030) goto 20 else goto 23
020: A = P[32:2]
021: if (A == 3880) goto 22 else goto 23
022: return 65535
023: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==24579) then goto L22 end
   if 17 > length then return 0 end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==2) then goto L6 end
   if 21 > length then return 0 end
   A = bit.bor(bit.lshift(P[19], 8), P[19+1])
   if (A==3880) then goto L21 end
   ::L6::
   if 18 > length then return 0 end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33026) then goto L11 end
   if 22 > length then return 0 end
   A = bit.bor(bit.lshift(P[20], 8), P[20+1])
   if (A==3880) then goto L21 end
   ::L11::
   if 17 > length then return 0 end
   A = P[16]
   A = bit.band(A, 7)
   if not (A==6) then goto L16 end
   if 33 > length then return 0 end
   A = bit.bor(bit.lshift(P[31], 8), P[31+1])
   if (A==3880) then goto L21 end
   ::L16::
   if 18 > length then return 0 end
   A = bit.bor(bit.lshift(P[16], 8), P[16+1])
   A = bit.band(A, 65287)
   if not (A==33030) then goto L22 end
   if 34 > length then return 0 end
   A = bit.bor(bit.lshift(P[32], 8), P[32+1])
   if not (A==3880) then goto L22 end
   ::L21::
   do return 65535 end
   ::L22::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if not (length >= 21) then do return false end end
   do
      local v1 = P[16]
      local v2 = bit.band(v1,7)
      if not (v2 == 2) then goto L3 end
      do
         local v3 = ffi.cast("uint16_t*", P+19)[0]
         do return v3 == 3850 end
      end
::L3::
      do
         if not (length >= 22) then do return false end end
         do
            local v4 = ffi.cast("uint16_t*", P+16)[0]
            local v5 = bit.band(v4,2047)
            if not (v5 == 641) then goto L6 end
            do
               local v6 = ffi.cast("uint16_t*", P+20)[0]
               do return v6 == 3850 end
            end
::L6::
            do
               if not (length >= 33) then do return false end end
               do
                  if not (v2 == 6) then goto L9 end
                  do
                     local v7 = ffi.cast("uint16_t*", P+31)[0]
                     do return v7 == 3850 end
                  end
::L9::
                  do
                     if not (length >= 34) then do return false end end
                     do
                        if not (v5 == 1665) then do return false end end
                        do
                           local v8 = ffi.cast("uint16_t*", P+32)[0]
                           do return v8 == 3850 end
                        end
                     end
                  end
               end
            end
         end
      end
   end
end
```

