PATH := ../deps/luajit/usr/local/bin:$(PATH)

all:

clean:
	rm -f tmp.pcap

check:
	./pflua-filter ../tests/data/v4.pcap ./tmp.pcap "ip"
	cmp ../tests/data/v4.pcap tmp.pcap
	rm tmp.pcap
