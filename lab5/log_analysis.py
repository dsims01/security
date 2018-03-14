# File for log analysis
import re
import json
from urllib2 import urlopen


countries = json.load(open("country-names.json"))
found_countries = []

with open('access.log','r') as f:
         for x in f:
         	line = x.rstrip()
         	found_ip = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',line)
                valid1 = re.findall('phpmyadmin',line.lower())
                valid2 = re.findall('php-my-admin',line.lower())
         	if found_ip and (valid1 or valid2):
                        url = 'http://ipinfo.io/' + found_ip[0] + '/country'
                        response = urlopen(url)
                        if response:
                            country = countries[response.read().rstrip()]
                            country_in_list = False
                            for y in found_countries:
                                if y['country'] == country:
                                    y['count'] = y['count'] + 1
                                    country_in_list = True
                            if not country_in_list:
                                found_countries.append({'country': country, 'count': 1})
found_countries = sorted(found_countries, key = lambda item: item['count'], reverse=True)
for x in found_countries:
    print 'Country: {0} \n-- Number of IPs: {1}'.format(x['country'],x['count'])

