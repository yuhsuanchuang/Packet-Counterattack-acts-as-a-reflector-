## Import Scapy module
from scapy.all import *

import argparse
from optparse import OptionParser
import time



parser = OptionParser()
parser.add_option("--interface", dest="interface",
                  help="enter interface")
parser.add_option("--victim-ip", dest="victimip",
                  help="enter victim-ip")
parser.add_option("--victim-ethernet", dest="victimethernet",
                  help="enter victim-ethernet")
parser.add_option("--reflector-ip", dest="reflectorip",
                  help="enter reflector-ip")
parser.add_option("--reflector-ethernet", dest="reflectorethernet",
                  help="enter reflector-ethernet")

(options, args) = parser.parse_args()
# print "interface = ", options.interface
# print "victimip = ", options.victimip
# print "victimethernet = ", options.victimethernet 

# ## Create a Packet Count var
# packetCount = 0

## Define our Custom Action function
# def listenARP(packet):
#     packet.show()
#     #packet.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
#     if ARP in packet:
#       print "ARP psrc = %s ==> pdst = %s" % (packet[ARP].psrc, packet[ARP].pdst)
#       if packet[ARP].pdst == options.victimip:
#         print "attack!!!!!!\n"
#         global attackIP, attackMAC
#         attackIP = packet[ARP].psrc
#         attackMAC = packet[ARP].hwsrc
#         return "psrc = %s ==> pdst = %s" % (packet[ARP].psrc, packet[ARP].pdst)

#     #sniff(iface=options.interface,prn=listenARP, count=1)
#     return 0

# def sendback(packet):
#   #packet.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))

#   if IP in packet or TCP in packet or UDP in packet:
#     print "packet src = %s => dst = %s" % (packet[IP].src,packet[IP].dstIP)
#     if packet[IP].src == attackIP and packet[IP].dst == options.victimip:
#       print "GET!!\n"
#       sendp(Ether()/IP(dst=attackIP)/ICMP()/("packet[Raw]"),iface="eth0")
      
#       return "src = %s => dst = %s" % (options.reflectorip,attackIP)
#   sniff(iface=options.interface,prn=sendback, count=1)
#   return 0

# ## Setup sniff, filtering for IP traffic
# #sniff(prn=lambda x: x.show())
#sniff(filter="arp",iface=options.interface,prn=listenARP, count=2)
# print attackIP, ",", attackMAC
# sniff(iface=options.interface,prn=sendback, count=1)
# #Ether(src = options.reflectorethernet,dst = attackMAC)/
# #/IP(src=options.reflectorip,dst=attackIP)

# def reflect():
  #packet.show()

def listen(packet):
#while True:
  #packet=sniff(iface=options.interface,filter="arp",count=1)
  
  if ARP in packet:
    if packet[ARP].pdst == options.victimip:
      print "------------------------victim get ARP------------------------\n"
      #packet.show()
      print packet.summary()
      global attackIP, attackMAC
      attackIP = packet[ARP].psrc
      attackMAC = packet[ARP].hwsrc
      send(ARP(op="is-at", psrc=options.victimip, pdst=attackIP, hwsrc=options.victimethernet, hwdst=attackMAC))

    elif packet[ARP].pdst == options.reflectorip:
      print "------------------------reflector get ARP------------------------\n"
      print packet.summary()
      #global attackIP, attackMAC
      attackIP = packet[ARP].psrc
      attackMAC = packet[ARP].hwsrc
      send(ARP(op="is-at", psrc=options.reflectorip, pdst=attackIP, hwsrc=options.reflectorethernet, hwdst=attackMAC))

  elif IP in packet:

    if ICMP in packet and (packet[IP].dst == options.victimip or packet[IP].dst == options.reflectorip):
      #packet.show()
      global srcip
      if packet[IP].dst == options.victimip:
        print "------------------------victim get ICMP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)       
        srcip = options.reflectorip
      elif packet[IP].dst == options.reflectorip:
        print "------------------------reflector get ICMP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)
        srcip = options.victimip

      send(IP(src=srcip,dst=attackIP)
        /ICMP(seq=packet[ICMP].seq,type=packet[ICMP].type,id=packet[ICMP].id)/packet[Raw].load)
      
    elif TCP in packet and (packet[IP].dst == options.victimip or packet[IP].dst == options.reflectorip):
      #packet.show()
      if packet[IP].dst == options.victimip:
        print "------------------------victim get TCP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)       
        srcip = options.reflectorip
      elif packet[IP].dst == options.reflectorip:
        print "------------------------reflector get TCP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)
        srcip = options.victimip

      if Raw in packet:
        send(IP(src=srcip,dst=attackIP)
          /TCP(sport=packet[TCP].sport
            ,dport=packet[TCP].dport
            ,seq=packet[TCP].seq
            ,options=packet[TCP].options
            ,flags=packet[TCP].flags
            ,ack=packet[TCP].ack) 
          /packet[Raw].load)
      else:
        send(IP(src=srcip,dst=attackIP)
          /TCP(sport=packet[TCP].sport
            ,dport=packet[TCP].dport
            ,seq=packet[TCP].seq
            ,options=packet[TCP].options
            ,flags=packet[TCP].flags
            ,ack=packet[TCP].ack))

    elif UDP in packet and (packet[IP].dst == options.victimip or packet[IP].dst == options.reflectorip):
      #packet.show()
      if packet[IP].dst == options.victimip:
        print "------------------------victim get UDP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)       
        srcip = options.reflectorip
      elif packet[IP].dst == options.reflectorip:
        print "------------------------reflector get UDP------------------------\n"
        print "src = %s ==> dst = %s" % (packet[IP].src, packet[IP].dst)
        srcip = options.victimip

      if Raw in packet:
        send(IP(src=srcip,dst=attackIP)
          /UDP(sport=packet[UDP].sport
            ,dport=packet[UDP].dport) 
          /packet[Raw].load)
      else:
        send(IP(src=srcip,dst=attackIP)
          /UDP(sport=packet[UDP].sport
            ,dport=packet[UDP].dport))

sniff(iface=options.interface,prn=listen)
