# ether multicast


## BPF

```
000: A = P[0:1]
001: if (A & 1 != 0) goto 2 else goto 3
002: return 65535
003: return 0
```


## BPF cross-compiled to Lua

```
return function (P, length)
   local A = 0
   if 1 > length then return 0 end
   A = P[0]
   if (bit.band(A, 1)==0) then goto L2 end
   do return 65535 end
   ::L2::
   do return 0 end
   error("end of bpf")
end
```


## Direct pflang compilation

```
return function(P,length)
   if length < 1 then return false end
   return band(P[0],1) ~= 0
end

```

