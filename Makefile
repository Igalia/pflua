TOP_SRCDIR:=.
include common.mk
LUAJIT_O := $(ABS_TOP_SRCDIR)/deps/luajit/src/libluajit.a
DYNASM_SO := $(ABS_TOP_SRCDIR)/deps/dynasm/libdasm_x86.so

LUAJIT_CFLAGS := -DLUAJIT_USE_PERFTOOLS -DLUAJIT_USE_GDBJIT

all: $(LUAJIT_O) $(DYNASM_SO)
	$(MAKE) -C src preprocess
	$(MAKE) -C doc

$(LUAJIT_O): check_luajit deps/luajit/Makefile
	echo 'Building LuaJIT\n'
	(cd deps/luajit && \
	 $(MAKE) PREFIX=`pwd`/usr/local \
	         CFLAGS="$(LUAJIT_CFLAGS)" && \
	 $(MAKE) DESTDIR=`pwd` install)
	(cd deps/luajit/usr/local/bin; ln -fs luajit-2.0.3 luajit)

$(DYNASM_SO): check_dynasm
	(cd deps/dynasm && \
	 gcc csrc/dynasm/dasm_x86.c -O -fPIC -DDASM_CHECKS -shared -s -o libdasm_x86.so)

check_luajit:
	@if [ ! -f deps/luajit/Makefile ]; then \
	    echo "Can't find deps/luajit/. You might need to: git submodule update --init"; exit 1; \
	fi

check_dynasm:
	@if [ ! -f deps/dynasm/dynasm.lua ]; then \
	    echo "Can't find deps/dynasm/. You might need to: git submodule update --init"; exit 1; \
	fi

check:
	$(MAKE) -C src check
	$(MAKE) -C tools check
	$(MAKE) -C doc
	$(MAKE) -C tests check

clean:
	$(MAKE) -C deps/luajit clean
	$(MAKE) -C src clean
	$(MAKE) -C tools clean

.SERIAL: all
