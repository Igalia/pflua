# ip6 multicast


## BPF

```
000: A = P[12:2]
001: if (A == 34525) goto 2 else goto 5
002: A = P[38:1]
003: if (A == 255) goto 4 else goto 5
004: return 65535
005: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 14 > length then return 0 end
   A = bit.bor(bit.lshift(P[12], 8), P[12+1])
   if not (A==34525) then goto L4 end
   if 39 > length then return 0 end
   A = P[38]
   if not (A==255) then goto L4 end
   do return 65535 end
   ::L4::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if length < 54 then return false end
   if cast("uint16_t*", P+12)[0] ~= 56710 then return false end
   return P[38] == 255
end

```

