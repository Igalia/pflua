PATH := ../deps/luajit/usr/local/bin:$(PATH)

EXAMPLES = tcp-port-80.md

all: $(EXAMPLES)

maintainer-clean:
	rm -f $(EXAMPLES)

tcp-port-80.md:
	../tools/dump-markdown "tcp port 80" > $@.tmp
	mv $@.tmp $@
