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
	src-net-ffff.ffff.eeee.eeee.0.0.0.0-72.md \
	src-port-80.md \
	dst-portrange-80-90.md \
	ether-multicast.md \
	ether-broadcast.md \
	ether-proto-decnet.md \
	ether-proto-1500.md \
	ether-proto-1501.md \
	ether-proto-255.md \
	dst-portrange-80-90.md \
	src-host-192.68.1.1-and-less-100.md \
	dst-host-192.68.1.1-and-greater-100.md \
	ip-multicast.md \
	ip-proto-ah.md \
	ip6-multicast.md \
	ip6-proto-ah.md

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

src-port-80.md:
	../tools/dump-markdown "src port 80" > $@.tmp && mv $@.tmp $@

dst-portrange-80-90.md:
	../tools/dump-markdown "dst portrange 80-90" > $@.tmp && mv $@.tmp $@

ether-multicast.md:
	../tools/dump-markdown "ether multicast" > $@.tmp && mv $@.tmp $@

ether-broadcast.md:
	../tools/dump-markdown "ether broadcast" > $@.tmp && mv $@.tmp $@

ether-proto-decnet.md:
	../tools/dump-markdown "ether proto \decnet" > $@.tmp && mv $@.tmp $@

# The frame should be treated as an Ethernet frame.
ether-proto-1501.md:
	../tools/dump-markdown "ether proto 1501" > $@.tmp && mv $@.tmp $@

# The frame should be treated as an 802.3 frame.
ether-proto-1500.md:
	../tools/dump-markdown "ether proto 1500" > $@.tmp && mv $@.tmp $@

# The frame should be treated as an 802.3 frame and check SAP (Service Access
# Point) at byte 14.
ether-proto-255.md:
	../tools/dump-markdown "ether proto 255" > $@.tmp && mv $@.tmp $@

src-host-192.68.1.1-and-less-100.md: $(PFLUA)
	../tools/dump-markdown "src host 192.68.1.1 and less 100" > $@.tmp && mv $@.tmp $@

dst-host-192.68.1.1-and-greater-100.md: $(PFLUA)
	../tools/dump-markdown "dst host 192.68.1.1 and greater 100" > $@.tmp && mv $@.tmp $@

ip-multicast.md:
	../tools/dump-markdown "ip multicast" > $@.tmp && mv $@.tmp $@

ip-proto-ah.md:
	../tools/dump-markdown "ip proto \ah" > $@.tmp && mv $@.tmp $@

ip6-multicast.md:
	../tools/dump-markdown "ip6 multicast" > $@.tmp && mv $@.tmp $@

ip6-proto-ah.md:
	../tools/dump-markdown "ip6 proto \ah" > $@.tmp && mv $@.tmp $@
