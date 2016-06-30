#!/usr/local/bin/python2.7

import os
from addr import *
from scapy.all import *

pid=os.getpid() & 0xffff

syn=TCP(sport=pid, dport='chargen', seq=1, flags='S', window=(2**16)-1)
synack=sr1(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/syn, iface=LOCAL_IF)

ack=TCP(sport=synack.dport, dport=synack.sport, seq=2, flags='A',
    ack=synack.seq+1, window=(2**16)-1)

while 1:
	data=sr1(IP(src=FAKE_NET_ADDR, dst=REMOTE_ADDR)/ack, iface=LOCAL_IF)
	data.show()
	ack=TCP(sport=data.dport, dport=data.sport, seq=2, flags='A',
	    ack=data.seq+len(data.load), window=(2**16)-1)
