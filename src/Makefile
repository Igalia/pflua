PATH := ../deps/luajit/usr/local/bin:$(PATH)

all:
clean:

check:
	luajit -l pf -e 'pf.selftest()'

test:
	luajit -l pf_test -e 'pf_test.run()'
