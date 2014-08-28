# pflua

`pflua` is a network packet filtering library using LuaJIT.  It supports
filters written in
[pflang](https://github.com/Igalia/pflua/blob/master/doc/pflang.md), the
filter language of the popular
[tcpdump](https://www.wireshark.org/docs/man-pages/pcap-filter.html#DESCRIPTION)
tool.  It's also fast: to our knowledge, it's actually the fastest
pflang implementation, by a wide margin.  Read on for more details.

## Getting started

```shell
$ git clone --recursive https://github.com/Igalia/pflua.git
$ cd pflua; make             # Builds embedded LuaJIT
$ make check                 # Run builtin basic tests
```

## Using pflua

Pflua is a library; you need an application to drive it.

The most simple way to use pflua is filtering packets from a file
captured by `tcpdump`.  For example:

```
$ cd tools
$ ../deps/luajit/usr/local/bin/luajit pflua-filter \
    ../src/ts/pcaps/ws/v4.pcap /tmp/foo.pcap "ip"
Filtered 43/43 packets from ../src/ts/pcaps/ws/v4.pcap to /tmp/foo.pcap.
```

See the source of
[pflua-filter](https://github.com/Igalia/pflua/blob/master/tools/pflua-filter)
for more information.

Pflua was made to be integrated into the [Snabb
Switch](https://github.com/SnabbCo/snabbswitch/wiki) user-space
networking toolkit, also written in Lua.  A common deployment
environment for Snabb is within the host virtual machine of a
virtualized server, with Snabb having CPU affinity and complete control
over a high-performance 10Gbit NIC, which it then routes to guest VMs.
The administrator of such an environment might want to apply filters on
the kinds of traffic passing into and out of the guests.  To this end,
we plan on integrating pflua into Snabb so as to provide a pleasant,
expressive, high-performance filtering facility.

Given its high performance, it is also reasonable to deploy pflua on
gateway routers and load-balancers, within virtualized networking
appliances.

## Implementation

Pflua can compile pflang filters in two ways.

The default compilation pipeline is pure Lua.  First, a [custom
parser](https://github.com/Igalia/pflua/blob/master/src/pf/parse.lua)
produces a high-level AST of a pflang filter expression.  This AST is
[_lowered_](https://github.com/Igalia/pflua/blob/master/src/pf/expand.lua)
to a primitive AST, with a limited set of operators and ways in which
they can be combined.  This representation is then exhaustively
[optimized](https://github.com/Igalia/pflua/blob/master/src/pf/optimize.lua),
folding constants and tests, inferring ranges of expressions and packet
offset values, hoisting assertions that post-dominate success
continuations, etc.  Finally, we
[residualize](https://github.com/Igalia/pflua/blob/master/src/pf/codegen.lua)
Lua source code, performing common subexpression elimination as we go.

The resulting Lua function is a predicate of two parameters: the packet
as a `uint8_t*` pointer, and its length.  If the predicate is called
enough times, LuaJIT will kick in and optimize traces that run through
the function.  Pleasantly, this results in machine code whose structure
reflects the actual packets that the filter sees, as branches that are
never taken are not residualized at all.

The other compilation pipeline starts with bytecode for the [Berkeley
packet filter
VM](https://www.freebsd.org/cgi/man.cgi?query=bpf#FILTER_MACHINE).
Pflua can load up the `libpcap` library and use it to compile a pflang
expression to BPF.  In any case, whether you start from raw BPF or from
a pflang expression, the BPF is compiled directly to Lua source code,
which LuaJIT can gnaw on as it pleases.

We like the independence and optimization capabilities afforded by the
native pflang pipeline.  However, though pflua does a good job in
implementing pflang, it is inevitable that there may be bugs or
differences of implementation relative to what `libpcap` does.  For that
reason, the `libpcap`-to-bytecode pipeline can be a useful alternative
in some cases.

## Performance

To our knowledge, pflua is the fastest implementation of pflang that
exists, by a wide margin (August 2014).  See
https://github.com/Igalia/pflua-bench for our benchmarking experiments.

## API documentation

None yet.  See
[pf.lua](https://github.com/Igalia/pflua/blob/master/src/pf.lua) for the
high-level `compile_filter` interface.

## Bugs

Please check our (issue tracker)[https://github.com/Igalia/pflua/issues]
for known bugs, and please file a bug if you find one.  Cheers :)

## Authors

Pflua was written by Andy Wingo, Diego Pino, and Javier Muñoz at
(Igalia, S.L.)[https://www.igalia.com/].  Development of pflua was
supported by Luke Gorrie at (Snabb Gmbh)[http://snabb.co/], purveyors of
fine networking solutions.  Thanks, Snabb!

Feedback is very welcome!  If you are interested in pflua in a Snabb
context, probably the best thing is to post a message to the
(snabb-devel)[https://groups.google.com/forum/#!forum/snabb-devel]
group.  Or, if you like, you can contact Andy directly at
`wingo@igalia.com`.  If you have a problem that pflua can help solve,
let us know!

## Example

For the following filter:

```
tcp port 80
```

The BPF that `libpcap` produces looks something like this:

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

Note that 

If we compile this to Lua using the BPF pipeline, we get:

```lua
function (P, length)
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

With the default compilation pipeline, this yields:

```lua
return function(P,length)
   if not (24 <= length) then return false end
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
         if not (56 <= length) then return false end
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
                     if not (58 <= length) then return false end
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

The nesting in this last example is a bit excessive.  Some nesting is
needed because of the way Lua local variable scope interacts with
`goto`, but not all of the `do` blocks here need be present.  The native
Lua code is longer in lines but actually simpler in structure.

The assembly produced for this filter depends on the packets that the
filter sees.  We'll post more information as we have it.

These examples were produced using the
(tools/pflang-compile)[https://github.com/Igalia/pflua/blob/master/tools/pflang-compile]
tool.
