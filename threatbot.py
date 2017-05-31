#!/usr/bin/env python
# Name:    ThreatBot.py
# Purpose: Slack bot that generates report from threat intel sources
# By:      Joshua Galloway
# Date:    05.30.17
# Modified 05.30.17
#---------------------------------------------------------------------

import re
import os
import time
import shodan
import socket
from slackbot.bot import Bot, respond_to, listen_to, default_reply

SHODAN_API_KEY = 'jmh9k6YzgHAx4q0X3xLa1266XZrrRn6h'

shodan_api = shodan.Shodan(SHODAN_API_KEY)

# get threatbot's id as environmental variables

BOT_ID = os.environ.get("BOT_ID")

def validip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def main():
    bot = Bot()
    bot.run()

@respond_to('hi', re.IGNORECASE)
def hi(message):
    message.reply('I can understand hi or HI!')
    # react with thumb up emoji
    message.react('+1')

@respond_to('report (.*)')
def report(message, addr=None):
    if validip(addr):
        # Lookup the host
        try:
            host = shodan_api.host(addr)
            message.reply('{0} belongs to {1} and is running {2}. It is vulnerable to {3}.'.format(addr, host.get('org', 'n/a'), host.get('os', 'n/a'), host.get('vulns', 'n/a')))
        except:
            message.reply('Error! Shodan may not have info for that ip address')
    else:
        message.reply('{0} is not a valid ip address'.format(addr))

@default_reply
def default(message):
    message.reply("Usage: @threatbot report <ip address>")

if __name__ == "__main__":
    main()



