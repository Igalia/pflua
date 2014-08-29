PATH := ../deps/luajit/usr/local/bin:$(PATH)

EXAMPLES = \
	tcp-port-80.md \
	icmp-or-tcp-or-udp.md \
	portrange-0-6000.md \
	host-127.0.0.1.md

all: $(EXAMPLES)

maintainer-clean:
	rm -f $(EXAMPLES)

tcp-port-80.md:
	../tools/dump-markdown "tcp port 80" > $@.tmp && mv $@.tmp $@

icmp-or-tcp-or-udp.md:
	../tools/dump-markdown "icmp or tcp or udp" > $@.tmp && mv $@.tmp $@

portrange-0-6000.md:
	../tools/dump-markdown "portrange 0-6000" > $@.tmp && mv $@.tmp $@

host-127.0.0.1.md:
	../tools/dump-markdown "host 127.0.0.1" > $@.tmp && mv $@.tmp $@
