PATH := ../deps/luajit/usr/local/bin:$(PATH)
TEST_SAVEFILE_URL='https://github.com/Igalia/pflua-test/blob/master/savefiles/wingolog.org.pcap?raw=true'
TEST_SAVEFILE=data/wingolog.pcap
PFLUA_QUICKCHECK=../tools/pflua-quickcheck

all:
	@true

check: quickcheck
	./test-matches data

$(TEST_SAVEFILE):
	wget --output-document $@ $(TEST_SAVEFILE_URL)

quickcheck: $(TEST_SAVEFILE)
	$(PFLUA_QUICKCHECK) properties/repeatable_randomization
	$(PFLUA_QUICKCHECK) properties/pflua_math_eq_libpcap_math
	$(PFLUA_QUICKCHECK) properties/pflua_pipelines_match $(TEST_SAVEFILE)
	$(PFLUA_QUICKCHECK) properties/opt_eq_unopt $(TEST_SAVEFILE)
	$(PFLUA_QUICKCHECK) properties/opt_eq_unopt $(TEST_SAVEFILE) test-filters

.SERIAL: all
