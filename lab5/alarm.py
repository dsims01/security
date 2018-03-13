#!/usr/bin/python

from scapy.all import *
import pcapy
import argparse

iNum = 1
user_no_password = ""
username_checks = ["log","login","wpname","ahd_username","unickname","nickname","user","user_name","alias",
                   "pseudo","email","username","_username","userid","form_loginname","loginname","login_id",
                   "loginid","session_key","sessionkey","pop_login","uid","id","user_id","screenname",
                   "uname","ulogin","acctname","account","member","mailaddress","membername","login_username",
                   "login_email","loginusername","loginemail","uin","sign-in"]
password_checks = ["ahd_password","pass","password","_password","passwd","session_password","sessionpassword",
                   "login_password","loginpassword","form_pw","pw","userpassword","pwd","upassword",
                   "login_password","passwort","passwrd","wppassword","upasswd"]
def packetcallback(packet):
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
            printAlarm ("username and password sent in-the-clear", packet[IP].src,"",payload)
        else:
            for option in username_checks:
                start = load_lower.find(option)
                if start != -1:
                    end = load.find('\r',start)
                    user_no_password = load[start+5:end]
                    break            
            if user_no_password != "":
                for option in password_checks:
                    start = load_lower.find(option)
                    if start != -1:
                        end = load.find('\r', start)
                        password = load[start+5:end] 
                        payload = ' (' + user_no_password + ':' + password + ')'
                        printAlarm("username and password sent in-the-clear", packet[IP].src,"",payload)
                        break
        found_nikto = load.find("nikto")
        if found_nikto != -1:
            printAlarm("Nikto scan", packet[IP].src, "HTTP","") 

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
    print 'ALERT #{}: {} is detected from {}{}{}'.format(iNum,incident,ip,protocol,payload)
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
