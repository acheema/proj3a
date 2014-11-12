#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

import socket
import struct

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        #print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                #config['rule']
	f = open(config['rule'])
	lines = [line.strip() for line in f]
	counter = 0
	for l in lines:
		if l == '' or l[counter][0]=='%':
			del lines[counter]
		counter = counter + 1
	print lines
	f.close()

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
	self.send = True
	length = ord(pkt[0:1]) & 0x0f
	protocol = ord(pkt[9:10])
	if length != 5:
		self.send == False
	"""if protocol not in {1,6,17}:
		print "The protocol is recognized and is: %d" %protocol
		self.send == True
	print "Current the send variable is: " + str(self.send)"""
	if pkt_dir == PKT_DIR_INCOMING and self.send:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and self.send:
            self.iface_ext.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
