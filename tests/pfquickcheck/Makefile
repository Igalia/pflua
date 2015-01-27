check: quickcheck

quickcheck: get_savefile
	./pflua-quickcheck properties/opt_eq_unopt savefiles/wingolog.org.pcap test-filters
	./pflua-quickcheck properties/opt_eq_unopt savefiles/wingolog.org.pcap
	make tcpdumpchecks

tcpdumpchecks:
	if ./test_tcpdump.sh; then \
	  ./pflua-quickcheck --iterations=50 properties/pflua_math_eq_libpcap_math; \
	else \
	  echo "Skipped running properties that need tcpdump"; \
	fi

get_savefile:
	./get_savefile.sh

.SERIAL: all
