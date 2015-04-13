TOP_SRCDIR:=..
include $(TOP_SRCDIR)/common.mk

PATH := $(ABS_TOP_SRCDIR)/deps/luajit/usr/local/bin:$(PATH)

all:

clean:
	rm -f tmp.pcap

check:
	./pflua-filter ../tests/data/v4.pcap ./tmp.pcap "ip"
	cmp ../tests/data/v4.pcap tmp.pcap
	rm tmp.pcap
