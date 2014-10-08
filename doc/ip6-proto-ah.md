# ip6 proto \ah


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 8
002: A = P[20:1]
003: if (A == 51) goto 7 else goto 4
004: if (A == 44) goto 5 else goto 8
005: A = P[54:1]
006: if (A == 51) goto 7 else goto 8
007: return 65535
008: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L7 end
   if 21 > length then return 0 end
   A = P[20]
   if (A==51) then goto L6 end
   if not (A==44) then goto L7 end
   if 55 > length then return 0 end
   A = P[54]
   if not (A==51) then goto L7 end
   ::L6::
   do return 65535 end
   ::L7::
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
         local v2 = P[20]
         if v2 == 51 then do return true end end
         do
            if not (length >= 55) then do return false end end
            do
               if not (v2 == 44) then do return false end end
               do
                  local v3 = P[54]
                  do return v3 == 51 end
               end
            end
         end
      end
   end
end
```

