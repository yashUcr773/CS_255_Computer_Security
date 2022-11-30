from scapy.all import *
host = sys.argv[1]
print ('looking for', host)

ttl = 1

while 1:
    a = IP()
    a.dst = host
    a.ttl = ttl

    b = ICMP()
    p = a/b

    rply = sr1(p,verbose = 0)

    if rply is None:
        break
    elif rply['ICMP'].type == 0:
        print(rply['IP'].src, ' is ', ttl, ' hops away')
        break
    else:
        print (ttl, ' jumps for ', rply['IP'].src) 
        ttl += 1