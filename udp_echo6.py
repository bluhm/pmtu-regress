#!/usr/local/bin/python2.7

import os
import string
import random
from addr import *
from scapy.all import *

e=Ether(src=LOCAL_MAC, dst=REMOTE_MAC)
ip6=IPv6(src=FAKE_NET_ADDR6, dst=REMOTE_ADDR6)
port=os.getpid() & 0xffff

print "Send UDP packet with 1400 octets payload, receive echo."
data=''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase +
    string.digits) for _ in range(1400))
udp=UDP(sport=port, dport='echo')/data
echo=srp1(e/ip6/udp, iface=LOCAL_IF)

print "Fill our fragment cache."
time.sleep(1)

print "Send ICMP6 packet too big packet with MTU 1300."
icmp6=ICMPv6PacketTooBig(mtu=1300)/echo.payload
sendp(e/IPv6(src=LOCAL_ADDR6, dst=REMOTE_ADDR6)/icmp6, iface=LOCAL_IF)

print "Clear route cache at echo socket by sending to different address."
sendp(e/IPv6(src="fdd7:e83e:66bc:188::", dst=REMOTE_ADDR6)/udp, iface=LOCAL_IF)

class UDPfrag6(UDP):
    def hashret(self):
	return "X"
    def answers(self, other):
	return 1

print "Path MTU discovery will send UDP fragment with length 1300."
udpfrag6=IPv6ExtHdrFragment()/UDP(sport=port, dport='echo')/data
p=e/ip6/udpfrag6
p.show2()
frag=srp1(e/ip6/udpfrag6, nofilter=1, iface=LOCAL_IF)

len = frag.plen + len(IPv6())
print "len=%d" % len
if len != 1300:
	print "ERROR: UDP fragment len is %d, expected 1300." % len
	exit(1)
exit(0)
