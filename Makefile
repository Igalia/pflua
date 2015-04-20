TOP_SRCDIR:=.
include common.mk
LUAJIT_O := $(ABS_TOP_SRCDIR)/deps/luajit/src/libluajit.a

LUAJIT_CFLAGS := -DLUAJIT_USE_PERFTOOLS -DLUAJIT_USE_GDBJIT

all: $(LUAJIT_O) env
	$(MAKE) -C doc

$(LUAJIT_O): check_luajit deps/luajit/Makefile
	echo 'Building LuaJIT\n'
	(cd deps/luajit && \
	 $(MAKE) PREFIX=`pwd`/usr/local \
	         CFLAGS="$(LUAJIT_CFLAGS)" && \
	 $(MAKE) DESTDIR=`pwd` install)
	(cd deps/luajit/usr/local/bin; ln -fs luajit-2.0.3 luajit)

check_luajit:
	@if [ ! -f deps/luajit/Makefile ]; then \
	    echo "Can't find deps/luajit/. You might need to: git submodule update --init"; exit 1; \
	fi

env:
	@echo "#!/bin/bash\nLUA_PATH=$(LUA_PATH) exec \"\$$@\"" > env
	chmod +x env

check:
	$(MAKE) -C src check
	$(MAKE) -C tools check
	$(MAKE) -C doc
	$(MAKE) -C tests check

clean:
	$(MAKE) -C deps/luajit clean
	$(MAKE) -C src clean
	$(MAKE) -C tools clean
	rm -rf env

.SERIAL: all
