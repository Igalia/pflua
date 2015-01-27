PATH := .:../deps/luajit/usr/local/bin:$(PATH)

check:
	luajit -l bpf_pflua_ts -e 'bpf_pflua_ts.run()'

check_jit_off:
	luajit -joff -l bpf_pflua_ts -e 'bpf_pflua_ts.run()'

trace:
	luajit -jdump -l bpf_pflua_ts -e 'bpf_pflua_ts.run()'
