#
# This is a simple test plan
#
# Set 'enabled' to 'false' in order to skip test cases
#
# Use "make test | grep 'tc id'" to identify test cases failing quickly
#
# i.e:
#  $ make test | grep 'tc id'
#  tc id 1 FAIL (48 != 47)
#  tc id 2 PASS
#  tc id 3 SKIP
#  ...
#

id:1
description:empty filter test
filter:
pcap_file:v4.pcap
expected_result:43
enabled:true

id:2
description:ip test
filter:ip
pcap_file:v4.pcap
expected_result:43
enabled:true

id:3
description:tcp test
filter:tcp
pcap_file:v4.pcap
expected_result:41
enabled:true

id:4
description:tcp port test
filter:tcp port 80
pcap_file:v4.pcap
expected_result:41
enabled:true

id:5
description:tcp dst port test
filter:tcp dst port 23
pcap_file:telnet-cooked.pcap
expected_result:48
enabled:true

id:6
description:udp dst port test
filter:udp dst port 2087
pcap_file:tftp_wrq.pcap
expected_result:49
enabled:true

id:7
description:host check test
filter:host 192.168.0.13
pcap_file:tftp_wrq.pcap
expected_result:100
enabled:false

id:8
description:net mask test success
filter:net 192.168.0.0 mask 255.255.255.0
pcap_file:telnet-cooked.pcap
expected_result:92
enabled:false

id:9
description:net mask test failure
filter:net 192.168.50.0 mask 255.255.255.0
pcap_file:telnet-cooked.pcap
expected_result:0
enabled:false
