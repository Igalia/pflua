PATH := ../deps/luajit/usr/local/bin:$(PATH)

all:

clean:
	rm -f tmp.pcap

check:
	./pflua-filter ../src/ts/pcaps/ws/v4.pcap ./tmp.pcap "ip"
	cmp ../src/ts/pcaps/ws/v4.pcap tmp.pcap
	rm tmp.pcap
