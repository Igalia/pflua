TOP_SRCDIR:=..
include $(TOP_SRCDIR)/common.mk

# Tests where the pure-lua pipeline and/or bpf-lua pipeline diverged from libpcap.
PFLANG_REGRESSION_PL_TESTS := $(wildcard pflang-reg/pl*)

TEST_SAVEFILE_URL='https://github.com/Igalia/pflua-test/blob/master/savefiles/wingolog.org.pcap?raw=true'
TEST_SAVEFILE=data/wingolog.pcap
PFLUA_QUICKCHECK=$(ABS_TOP_SRCDIR)/tools/pflua-quickcheck

all:
	@true

check: pflang_regression_tests quickcheck
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

pflang_regression_tests: $(TEST_SAVEFILE) $(PFLANG_REGRESSION_PL_TESTS)

.PHONY: $(PFLANG_REGRESSION_PL_TESTS)
$(PFLANG_REGRESSION_PL_TESTS):
	$(ABS_TOP_SRCDIR)/tools/pipe-lua-libpcap-match $(shell cat $@)

.SERIAL: all
