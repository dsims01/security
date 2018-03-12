# File for log analysis
import re

ips = []


with open('access.log','r') as f:
#     with open('test1.txt','w') as g: 
         for x in f:
         	line = x.rstrip()
         	found_ip = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',line)
         	if found_ip:
         		print found_ip[0]
         		ips.append(found_ip[0])
         	
#             x = x.rstrip()
#             if not x: continue
#             print >> g, int(x, 16)