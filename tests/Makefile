PATH := ../deps/luajit/usr/local/bin:$(PATH)

all:
	@true

check:
	./test-matches data
	#$(MAKE) -C pfquickcheck # Fix NaN bug and luajit setup for travis-ci
