PATH := ../deps/luajit/usr/local/bin:$(PATH)

all:
clean:

check:
	luajit -l pf -e 'pf.selftest()'
	luajit -l pcap -e 'pcap.selftest()'
