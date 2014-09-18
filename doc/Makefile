PATH := ../deps/luajit/usr/local/bin:$(PATH)

EXAMPLES = \
	tcp-port-80.md \
	icmp-or-tcp-or-udp.md \
	portrange-0-6000.md \
	host-127.0.0.1.md \
	net-127.0.0.0-8.md \
	host-ipv6-localhost.md \
	net-ipv6-0-mask-16.md \
	net-ipv6-ee.cc.9954.0-mask-111.md \
	src-net-ffff.ffff.eeee.eeee.1.0.0.0-82.md \
	src-net-ffff.ffff.eeee.eeee.0.0.0.0-72.md

PFLUA = \
	../src/pf.lua \
	../src/pf/bpf.lua \
	../src/pf/parse.lua \
	../src/pf/expand.lua \
	../src/pf/optimize.lua \
	../src/pf/codegen.lua

all: $(EXAMPLES)

maintainer-clean:
	rm -f $(EXAMPLES)

tcp-port-80.md: $(PFLUA)
	../tools/dump-markdown "tcp port 80" > $@.tmp && mv $@.tmp $@

icmp-or-tcp-or-udp.md: $(PFLUA)
	../tools/dump-markdown "icmp or tcp or udp" > $@.tmp && mv $@.tmp $@

portrange-0-6000.md: $(PFLUA)
	../tools/dump-markdown "portrange 0-6000" > $@.tmp && mv $@.tmp $@

host-127.0.0.1.md: $(PFLUA)
	../tools/dump-markdown "host 127.0.0.1" > $@.tmp && mv $@.tmp $@

net-127.0.0.0-8.md: $(PFLUA)
	../tools/dump-markdown "net 127.0.0.0/8" > $@.tmp && mv $@.tmp $@

host-ipv6-localhost.md: $(PFLUA)
	../tools/dump-markdown "host ::1" > $@.tmp && mv $@.tmp $@

net-ipv6-0-mask-16.md: $(PFLUA)
	../tools/dump-markdown "net ::0/16" > $@.tmp && mv $@.tmp $@

net-ipv6-ee.cc.9954.0-mask-111.md: $(PFLUA)
	../tools/dump-markdown "net ee:cc::9954:0/111" > $@.tmp && mv $@.tmp $@

src-net-ffff.ffff.eeee.eeee.1.0.0.0-82.md: $(PFLUA)
	../tools/dump-markdown "src net ffff:ffff:eeee:eeee:1:0:0:0/82" > $@.tmp && mv $@.tmp $@

src-net-ffff.ffff.eeee.eeee.0.0.0.0-72.md: $(PFLUA)
	../tools/dump-markdown "src net ffff:ffff:eeee:eeee:0:0:0:0/72" > $@.tmp && mv $@.tmp $@
