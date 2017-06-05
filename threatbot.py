#!/usr/bin/env python
# Name:    ThreatBot.py
# Purpose: Slack bot that generates report for IP from threat intel sources
# By:      Joshua Galloway
# Date:    05.30.17
# Modified 06.05.17
#---------------------------------------------------------------------------

import re
import os
import sys
import time
import requests
import json
import shodan
import socket
import urllib
from slackbot.bot import Bot, respond_to, listen_to, default_reply


SHODAN_API_KEY = '<your shodan API key here>'

shodan_api = shodan.Shodan(SHODAN_API_KEY)

VT_API_KEY = '<your VT API key here>'


def validip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def validsha256(string):
    result = None
    try:
        result = re.match(r'^[a-f0-9]{64}$', string)
    except:
        pass
    return result is not None


def main():
    bot = Bot()
    bot.run()


@respond_to('report (.*)', re.IGNORECASE)
def report(message, addr=None):
    if validip(addr):
        # Lookup the host on Shodan
        try:
            host = shodan_api.host(addr)
            message.reply('Shodan reports that {0} belongs to {1} and is running {2}. It is vulnerable to {3}.'.format(addr, host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('vulns', 'n/a')))
            # Show service banners
            for item in host['data']:
                message.reply('\nPort: %s\nBanner: %s\n' % (item['port'], item['data']))

        except shodan.APIError, e:
            message.reply('Shodan Error: %s' % e)
            if e == 'No information available for that IP.':
                Shodan.scan(addr)
                message.reply('Shodan is scanning ' + addr + ', check back later.')

        # Fetch and display geolocation information
        geoip = urllib.urlopen('http://api.hackertarget.com/geoip/?q='
                    + addr).read().rstrip()
        message.reply('\nGeolocation IP Information:\n'+ geoip)


        # Check against blacklists on VirusTotal
        headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip, My Python requests library example client or username"
                }

        params = {'apikey': VT_API_KEY, 'resource':addr, 'scan':'1'}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                params=params, headers=headers)
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            message.reply('{0} is on {1}/{2} blacklists.'.format(addr, positives, total))
        else:
            # Submit IP for scanning if no report exists yet
            message.reply('{0} has been submitted for scanning, check back later.'.format(addr))
    else:
        message.reply('{0} is not a valid ip address'.format(addr))

#Look up a sha256 hash on VirusTotal

@respond_to('lookup (.*)', re.IGNORECASE)
def lookup(message, string=None):
    if validsha256(string):
        params = {'apikey': VT_API_KEY, 'resource':string}
        headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip, My Python requests library example client"
                }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                params=params, headers=headers)
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            message.reply('This file has {0}/{1} hits on VirusTotal.'.format(positives, total))
        elif json_response['response_code'] == -2:
            message.reply('This file is queued for scanning.')
        else:
            message.reply('This file is not found in VirusTotal\'s database.')

    else:
        message.reply('Please enter a valid sha256 hash. Usage: @threatbot lookup <sha256>')


@default_reply
def default(message):
    message.reply("Usage: @threatbot report <ip address>")

if __name__ == "__main__":
    main()



