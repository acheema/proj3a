#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

import socket
import struct
import sys
# -*- coding: utf-8 -*-

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
	self.protocolDict = {}
	self.protocolDict[1] = 'icmp'
	self.protocolDict[6] = 'tcp'
	self.protocolDict[17] = 'udp'

	f = open(config['rule'])
	self.lines = [line.strip() for line in f]
	counter = 0
	for l in self.lines:
		if l == '' or l[counter][0]=='%':
			del self.lines[counter]
		counter = counter + 1
	print self.lines
	f.close()

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
	self.send = True
	length = ord(pkt[0:1]) & 0x0f
	if length != 5:
		self.send == False
	if ord(pkt[9:10]) in {1,6,17}:
		self.send = self.handle_protocol(pkt_dir, pkt)
	#print "Current the send variable is: " + str(self.send)
	if pkt_dir == PKT_DIR_INCOMING and self.send:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and self.send:
            self.iface_ext.send_ip_packet(pkt)

    def handle_protocol(self, pkt_dir, pkt):
	rulelist = []
	
	src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
	src_port, = struct.unpack("!H", pkt[20:22])
	dst_port, = struct.unpack("!H", pkt[22:24])
	protocol = ord(pkt[9:10])
	#print "src port is %d, dst port is %d" % (src_port, dst_port)
	#print "Protocol number is %d" % protocol
	for l in self.lines:
		if l.split(' ')[1] == self.protocolDict[protocol]:
			rulelist.append(l)
	#No rules found, send packet.
	if len(rulelist) == 0:
		return True
	if pkt_dir == PKT_DIR_INCOMING:
		externalip = src_ip
		externalport = src_port
        elif pkt_dir == PKT_DIR_OUTGOING:
		externalip = dst_ip
		externalport = dst_port
	print "current external IP is %s and external port is %d" % (externalip, externalport)
	lastmatch = None
	for r in rulelist:
		extip = r.split(' ')[2]
		exprt = r.split(' ')[3]
		if  extip == 'any' or extip == externalip and exprt == 'any' or exprt == str(externalport):
			if r == rulelist[-1]:
				lastmatch = r
				break
			else:
				continue

		else:
			lastmatch = r
	print lastmatch
	if lastmatch.split(' ')[0] == 'drop':
		print "DROPPING PACKET"
		return False
	print 'SENDING PACKET'
	return True

# TODO: You may want to add more classes/functions as well.