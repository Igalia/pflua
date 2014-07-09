PATH := .:../deps/luajit/usr/local/bin:$(PATH)

all:

clean:

check:
	luajit -l pf.buffer -e 'pf.buffer.selftest()'
	luajit -l pf.types -e 'pf.types.selftest()'
	luajit -l pf.libpcap -e 'pf.libpcap.selftest()'
	luajit -l pf.bpf -e 'pf.bpf.selftest()'
	luajit -l pf.lang -e 'pf.lang.selftest()'
	luajit -l pf -e 'pf.selftest()'

test:
	luajit -l pf_test -e 'pf_test.run()'

test_jit_off:
	luajit -joff -l pf_test -e 'pf_test.run()'

trace:
	luajit -jdump -l pf_test -e 'pf_test.run()'
