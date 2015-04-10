TOP_SRCDIR:=..
include $(TOP_SRCDIR)/common.mk

TEST_SAVEFILE_URL='https://github.com/Igalia/pflua-test/blob/master/savefiles/wingolog.org.pcap?raw=true'
TEST_SAVEFILE=data/wingolog.pcap
PFLUA_QUICKCHECK=$(ABS_TOP_SRCDIR)/tools/pflua-quickcheck

all:
	@true

check: quickcheck regression
	./test-matches data
	# Make sure PF_VERBOSE isn't causing crashes
	PF_VERBOSE=1 $(ABS_TOP_SRCDIR)/tools/pflua-compile "ip" >/dev/null 2>&1

$(TEST_SAVEFILE):
	wget --output-document $@ $(TEST_SAVEFILE_URL)

quickcheck: $(TEST_SAVEFILE)
	$(PFLUA_QUICKCHECK) properties/repeatable_randomization
	$(PFLUA_QUICKCHECK) properties/pflua_math_eq_libpcap_math
	$(PFLUA_QUICKCHECK) properties/opt_eq_unopt $(TEST_SAVEFILE)
	$(PFLUA_QUICKCHECK) properties/opt_eq_unopt $(TEST_SAVEFILE) test-filters

pipeline_diverge: $(TEST_SAVEFILE)
	cd regression && ./multi_octet.sh
	cd regression && ./portrange_bigger_first.sh

math_regression:
	cd regression && ./integer_multiplication.sh

regression: pipeline_diverge math_regression
	echo "All regression tests passed"

.SERIAL: all
