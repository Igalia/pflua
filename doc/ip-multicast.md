# ip multicast


## BPF

```
000: A = P[12:2]
001: if (A == 2048) goto 2 else goto 5
002: A = P[30:1]
003: if (A >= 224) goto 4 else goto 5
004: return 65535
005: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==2048) then goto L4 end
   if 31 > length then return 0 end
   A = P[30]
   if not (runtime_u32(A)>=224) then goto L4 end
   do return 65535 end
   ::L4::
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
      if not (v1 == 8) then do return false end end
      do
         local v2 = P[30]
         do return v2 == 224 end
      end
   end
end
```

