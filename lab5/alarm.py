#!/usr/bin/python

from scapy.all import *
import pcapy
import argparse

iNum = 1
user_no_password = ""
num = 0
def packetcallback(packet):
  global num
  #if (num > 9) and (num < 12): packet.show()
  #num = num + 1
  global user_no_password
  try: 
     payload = ""
     if packet[Raw] != None:
        load = str(packet[Raw])
        load_lower = load.lower()
        start = load.find("Authorization: Basic")
        if start != -1:
            end = load.find('\r', start)
            encoded = load[start+21:end]
            payload = ' (' + encoded.decode('base64') + ')'
            printAlarm ("username and password sent in-the-clear", packet[IP].src,packet[TCP].dport,payload)
        if start == -1:
            start = load.find("LOGIN ")
            if start != -1:
                end = load.find('\r',start)
                if end != -1:
                    payload = ' (' + load[start+6:end] + ')'
                    printAlarm ("username and password sent in-the-clear", packet[IP].src,packet[TCP].dport,payload)
        
        start = load.find("USER ")
        if start != -1:
            end = load.find('\r',start)
            if end != -1: user_no_password = load[start+5:end]
        if user_no_password != "":
            start = load.find("PASS ")
            if start != -1:
                end = load.find('\r', start)
                if end != -1:
                    password = load[start+5:end] 
                    payload = ' (' + user_no_password + ':' + password + ')'
                    printAlarm("username and password sent in-the-clear", packet[IP].src,packet[TCP].dport,payload)
                    user_no_password = ""
        found_nikto = load.find("nikto")
        found_Nikto = load.find("Nikto")
        if (found_nikto + found_Nikto) != -2:
            printAlarm("Nikto scan", packet[IP].src, packet[TCP].dport,"") 
        found_shellshock = load.find("() { :;};")
        if found_shellshock != -1:
            printAlarm("Shellshock scan", packet[IP].src, packet[TCP].dport, "")
     if packet[TCP].flags == 1:
         printAlarm("FIN scan", packet[IP].src,"",payload) 
     if packet[TCP].flags == 0:
         printAlarm("NULL scan", packet[IP].src,"",payload)
     if packet[TCP].flags == 41:
         printAlarm("XMAS scan", packet[IP].src,"",payload)
  except:
    pass

def printAlarm(incident, ip, protocol, payload):
    global iNum
    print 'ALERT #{}: {} is detected from {} ({}) ({})'.format(iNum,incident,ip,protocol,payload)
    iNum = iNum+1

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print "Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile}
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print "Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile}
else:
  print "Sniffing on %(interface)s... " % {"interface" : args.interface}
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print "Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface}
  except:
    print "Sorry, can't read network traffic. Are you root?"
