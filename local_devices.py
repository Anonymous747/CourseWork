import os
import subprocess
import commands
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import arping

#in future it'll read outut from terminal
def address():
    connected = subprocess.check_output('arp -a')
    f = open('result.txt', 'w')
    array = connected.splitlines()
    for adress in array:
        f.writelines(str(adress))
        print(adress)
    f.close()


#it's one of main methods for researching active IP(we can exchange packages for them)
def findRespondingIp():
    arping('192.168.43.1/24')


#give the possibility to listen packege from range of IP's
def listenIpInRange():
    ans,unans = sr(IP(dst=['192.168.100.8','192.168.100.1'], timeout=10)/ICMP())
    ans.show()
    print('------')
    unans.show()

#it's the part of method for three-step handshake connection
def listenerOfPackage():
    ip = IP(src="192.168.43.77", dst="192.168.43.38")
    SYN = TCP(sport=1024, dport=80, flags="S", seq=12345)
    packet = ip / SYN
    SYNACK = sr1(packet)
    my_ack = SYNACK.seq + 1
    ACK = TCP(sport=1024, dport=80, flags="A", seq=12346, ack=my_ack)
    send(ip / ACK)
    print(SYNACK)
# class LocalDevices:

#the method which check all ports in the specified range and displays open ports
def portScanner():
    packet = IP(dst="192.168.43.77")/TCP(dport=(1,100),flags="S")
    res,unans = sr(packet,timeout=1)

    for a in res:
        if a[1][1].flags==18:
            print(a[1].sport)
