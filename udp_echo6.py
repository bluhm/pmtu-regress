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
echo=srp1(e/ip6/udp, iface=LOCAL_IF, timeout=5)

print "Send ICMP6 packet too big packet with MTU 1300."
icmp6=ICMPv6PacketTooBig(mtu=1300)/echo.payload
sendp(e/IPv6(src=LOCAL_ADDR6, dst=REMOTE_ADDR6)/icmp6, iface=LOCAL_IF)

print "Clear route cache at echo socket by sending to different address."
sendp(e/IPv6(src="fdd7:e83e:66bc:188::", dst=REMOTE_ADDR6)/udp, iface=LOCAL_IF)

print "Path MTU discovery will send UDP fragment with length 1300."
# srp1 cannot be used, fragment answer will not match on outgoing udp packet
if os.fork() == 0:
        time.sleep(1)
        sendp(e/ip6/udp, iface=LOCAL_IF)
        os._exit(0)

ans=sniff(iface=LOCAL_IF, timeout=3, filter=
    "ip6 and src "+ip6.dst+" and dst "+ip6.src+" and proto ipv6-frag")

for a in ans:
	fh=a.payload.payload
	if fh.offset != 0 or fh.nh != (ip6/udp).nh:
		continue
	uh=fh.payload
	if uh.sport != udp.dport or uh.dport != udp.sport:
		continue
	frag=a
	break
else:
	print "ERROR: no matching IPv6 fragment UDP answer found"
	exit(1)

len = frag.plen + len(IPv6())
print "len=%d" % len
# fragments contain multiple of 8 octets, so expected len is 1296
if len != 1296:
	print "ERROR: UDP fragment len is %d, expected 1296." % len
	exit(1)
exit(0)
