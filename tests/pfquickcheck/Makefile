quickcheck: get_savefile
	./pflua-quickcheck prop_opt_eq_unopt savefiles/wingolog.org.pcap test-filters
	./pflua-quickcheck prop_opt_eq_unopt savefiles/wingolog.org.pcap
	make tcpdumpchecks

tcpdumpchecks:
	./test_tcpdump.sh || (echo "Skipped running properties that need tcpdump" && \
                              exit 0)
	./pflua-quickcheck --iterations=50 prop_pfluamath_eq_libpcap_math

get_savefile:
	./get_savefile.sh

.SERIAL: all
