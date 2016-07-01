#!/usr/local/bin/python2.7

import os
from addr import *
from scapy.all import *

pid=os.getpid() & 0xffff

# send syn packet, receive syn+ack
syn=TCP(sport=pid, dport='chargen', seq=1, flags='S', window=(2**16)-1)
synack=sr1(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/syn, iface=LOCAL_IF)

# send ack packet, receive chargen data
ack=TCP(sport=synack.dport, dport=synack.sport, seq=2, flags='A',
    ack=synack.seq+1, window=(2**16)-1)
data=sr1(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/ack, iface=LOCAL_IF)

# fill our receive buffer
time.sleep(1)

# send icmp fragmentation needed packet with mtu 1300
icmp=ICMP(type="dest-unreach", code="fragmentation-needed",
    nexthopmtu=1300)/data
send(IP(src=LOCAL_ADDR, dst=REMOTE_ADDR)/icmp, iface=LOCAL_IF)

# path mtu discovery will resend first data with length 1300
data=sr1(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/ack, iface=LOCAL_IF)

# cleanup the other's socket with a reset packet
rst=TCP(sport=synack.dport, dport=synack.sport, seq=2, flags='AR',
    ack=synack.seq+1)
send(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/rst, iface=LOCAL_IF)

len = data.len
print "len=%d" % len
if len != 1300:
	print "TCP data packet len is %d, expected 1300" % len
	exit(1)
exit(0)
