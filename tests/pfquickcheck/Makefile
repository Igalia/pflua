check: quickcheck

TEST_SAVEFILE_URL='https://github.com/Igalia/pflua-test/blob/master/savefiles/wingolog.org.pcap?raw=true'
TEST_SAVEFILE=../data/wingolog.pcap

$(TEST_SAVEFILE):
	wget --output-document $@ $(TEST_SAVEFILE_URL)

quickcheck: $(TEST_SAVEFILE)
	./pflua-quickcheck properties/opt_eq_unopt $(TEST_SAVEFILE) test-filters
	./pflua-quickcheck properties/opt_eq_unopt $(TEST_SAVEFILE)
	./pflua-quickcheck --iterations=50 properties/pflua_math_eq_libpcap_math

.SERIAL: all
