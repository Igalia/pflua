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
