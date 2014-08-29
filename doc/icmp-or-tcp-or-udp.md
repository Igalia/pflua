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
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L4 end
   if 24 > length then return 0 end
   A = P[23]
   if (A==1) then goto L11 end
   if (A==6) then goto L11 end
   goto L10
   ::L4::
   if not (A==34525) then goto L12 end
   if 21 > length then return 0 end
   A = P[20]
   if (A==6) then goto L11 end
   if not (A==44) then goto L10 end
   if 55 > length then return 0 end
   A = P[54]
   if (A==6) then goto L11 end
   ::L10::
   if not (A==17) then goto L12 end
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
   if not (length >= 21) then return false end
   do
      local v1 = ffi.cast("uint16_t*", P+12)[0]
      if not (v1 == 8) then goto L3 end
      do
         if not (length >= 24) then return false end
         do
            local v2 = P[23]
            if v2 == 1 then return true end
            do
               if v2 == 6 then return true end
               do
                  do return v2 == 17 end
               end
            end
         end
      end
::L3::
      do
         if not (v1 == 56710) then return false end
         do
            local v3 = P[20]
            if v3 == 6 then return true end
            do
               if not (length >= 55) then return false end
               do
                  if not (v3 == 44) then return false end
                  do
                     local v4 = P[54]
                     do return v4 == 6 end
                  end
               end
            end
         end
      end
   end
end
```

