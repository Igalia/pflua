# pflua

`pflua` is a library to filter packets using LuaJIT.  It supports
filters written in the [pcap-filter
language](https://www.wireshark.org/docs/man-pages/pcap-filter.html#DESCRIPTION).

## Getting started

```shell
$ git clone --recursive git@github.com:Igalia/pflua.git
$ cd pflua; make             # Builds embedded LuaJIT
$ make check                 # Run builtin basic tests
```
## Status

It's early days, but pcap filters are supported via compilation to the
[Berkeley packet filter
VM](https://www.freebsd.org/cgi/man.cgi?query=bpf#FILTER_MACHINE) using
libpcap, and cross-compilation from there to Lua.  See the `selfcheck`
function in
[pf.lua](https://github.com/Igalia/pflua/blob/master/src/pf.lua) for
more details.

## TODO

* Add many more test traces and tests

* Analyze BPF performance

  - Benchmark against kernel bpf and user-space pcap

  - Figure out what generated code looks like

  - Figure out good uint32 story -- currently there is an impedance
    mismatch between bit operations which return int32 values and
    aritmetic that wants modular uint32 operations (including
    multiplication)

* Compile pcap filters directly to Lua, without going through libpcap

  - Will need corresponding perf analysis

## Example

Currently compiling the following filter:

```
tcp port 80
```

yields the following Lua code:

```lua
function (P)
   local A = 0
   local X = 0
   local T = 0
   if 14 > P.length then return 0 end
   A = P:u16(12)
   if not (A==34525) then goto L7 end
   if 21 > P.length then return 0 end
   A = P:u8(20)
   if not (A==6) then goto L18 end
   if 56 > P.length then return 0 end
   A = P:u16(54)
   if (A==80) then goto L17 end
   if 58 > P.length then return 0 end
   A = P:u16(56)
   if (A==80) then goto L17 end
   goto L18
   ::L7::
   if not (A==2048) then goto L18 end
   if 24 > P.length then return 0 end
   A = P:u8(23)
   if not (A==6) then goto L18 end
   if 22 > P.length then return 0 end
   A = P:u16(20)
   if not (bit.band(A, 8191)==0) then goto L18 end
   if 14 >= P.length then return 0 end
   X = bit.lshift(bit.band(P:u8(14), 15), 2)
   T = bit.tobit((X+14))
   if T < 0 or T + 2 > P.length then return 0 end
   A = P:u16(T)
   if (A==80) then goto L17 end
   T = bit.tobit((X+16))
   if T < 0 or T + 2 > P.length then return 0 end
   A = P:u16(T)
   if not (A==80) then goto L18 end
   ::L17::
   do return 65535 end
   ::L18::
   do return 0 end
   error("end of bpf")
end
```

The mismatch between bit and arithmetic operations is clear here;
compiling directly from pcap filter language will fix that.
