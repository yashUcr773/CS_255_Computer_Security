from scapy.all import *
def print_pkt(pkt):
    pkt.show()

# For icmp
# pkt = sniff(iface = 'br-ce2219c0e00d', filter='icmp', prn=print_pkt)

# For tcp
# pkt = sniff(iface = 'br-ce2219c0e00d', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)

# For subnet
pkt = sniff(iface = 'br-ce2219c0e00d', filter='src net 172.17.0.0/24', prn=print_pkt)