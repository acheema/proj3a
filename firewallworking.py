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
    	self.rules = []

        # Load rules files
        with open(config['rule'], 'r') as f:
    		lines = [l.strip() for l in f.readlines()]
    		lines = [l for l in lines if len(l) > 0]
    		lines = [l for l in lines if l[0] != "%"]
    		self.rules = lines
    	print self.rules


        geoipdb = open('geoipdb.txt')
        self.geoIP = [h.strip() for h in geoipdb.readlines()]
        self.geoIP = [h for h in self.geoIP if len(h) > 0]



    	f.close()
        geoipdb.close()
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        self.send = True
        length = ord(pkt[0:1]) & 0x0f
        if ord(pkt[9:10]) in {1,6,17}:
            self.send = self.handle_protocol(pkt_dir, pkt)
        if length < 5:
            self.send = False
        #print "Current the send variable is: " + str(self.send)
        if pkt_dir == PKT_DIR_INCOMING and self.send:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and self.send:
            self.iface_ext.send_ip_packet(pkt)

    def handle_protocol(self, pkt_dir, pkt):
    	headlength = ord(pkt[0:1]) & 0x0f
    	src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
    	src_port = struct.unpack("!H", pkt[20:22])[0]
    	dst_port = struct.unpack("!H", pkt[22:24])[0]
    	protocol = ord(pkt[9:10])
	qtypecopy = None
	qclasscopy = None
	dnsnamecopy = None
    	if self.protocolDict[protocol] == 'udp' and dst_port == 53:
		print 'found a dns packet'
    		dnsHead = (headlength*4)+8
    		qdcount = struct.unpack('!H', pkt[dnsHead+4:dnsHead+6])[0]
    		if qdcount != 1:
    			return False
    		dnsquestionstart = dnsHead+12
    		dnsqname, dnsqnamelen = self.handle_qname(pkt, dnsquestionstart)
		dnsnamecopy = dnsqname
    		dnsQtypestart = dnsquestionstart + dnsqnamelen
    		qtype = struct.unpack('!H', pkt[dnsQtypestart:dnsQtypestart+2])[0]
		qtypecopy = qtype
    		qclass = struct.unpack('!H', pkt[dnsQtypestart+2:dnsQtypestart+4])[0]
		qclasscopy = qclass
    		if qtype != 1 and qtype != 28:
    			return True
    		if qclass != 1:
    			return True
    		#If we reach this point, that means we have found a DNS packet that
    		#falls under our jurisdiction and we must match against the rules
    	if pkt_dir == PKT_DIR_INCOMING:
            externalip = src_ip
            externalport = src_port
        elif pkt_dir == PKT_DIR_OUTGOING:
            externalip = dst_ip
            externalport = dst_port
    	print "current external IP is %s and external port is %d" % (externalip, externalport)
    	for r in self.rules:
		print r
    		rule = [t.lower() for t in r.split()]
		print rule
    		if len(rule) == 4:
    			ruleverdict = rule[0]
    			ruleprotocol = rule[1]
    			extip = rule[2]
    			exprt = rule[3]
			print 'ruleprotocol is: %s' % ruleprotocol
			print 'protocol is: %s' % self.protocolDict[protocol]
    			if self.protocolDict[protocol] != ruleprotocol:
    				continue
    			else:
				print 'finding a matched rule'
    				if self.handle_ip(extip, externalip):
    					if self.handle_port(exprt, externalport):
    						if ruleverdict == 'pass':
							return True
    						else:
							print 'dropping packet'
							return False
    		elif len(rule) == 3 and self.protocolDict[protocol] == 'udp' and externalport == 53:
    			ruleverdict = rule[0]
    			dns = rule[1]
    			ruledomain = rule[2]
			dnsverdict = self.handle_dns(ruleverdict, ruledomain, dnsnamecopy)
			if dnsverdict:
				return True
			else:
				return False
	print 'GOT TO THE END OF HANDLE PROTOCOL, NO MATCH FOUND'
	return True

    def handle_dns(self, verdict, domain, pktdomain):
	matches = None
	if domain == pktdomain:
		matches = True
	elif '*' in domain:
		if '*' == domain[0] and domain[1:len(pktdomain)] in pktdomain:
			matches = True
		else:
			matches = False
	
	if matches == True and verdict == 'pass':
		return True
	elif matches == True and verdict == 'drop':
		return False
	return True

    def handle_ip(self, ruleip, pktip):
        ruleip = str(ruleip)
        pktip = str(pktip)

        if ruleip == 'any' or ruleip == "0.0.0.0/0":
            return True


        # 2 byte country code
        elif len(ruleip) == 2:
            pktCC = self.handle_country(pktip)
            if pktCC != None and ruleip.lower() == pktCC.lower():
                return True
            else:
                return False


        # single IP address
        elif ruleip == pktip:
            return True

        else:
            #IP prefix
            if "/" in ruleip:
                ip_prefix_split = ruleip.split('/')
                ip_addr = ip_prefix_split[0]
                network_bits = int(ip_prefix_split[1])
                host_bits = 32 - network_bits

                #Convert ip addresses to 4B ints using struct.unpack before comparing them.
                min_ip = struct.unpack('!L', socket.inet_aton(ip_addr))[0]
                max_ip = int( (2**host_bits - 1) + min_ip)
                pktip = struct.unpack('!L', socket.inet_aton(pktip))[0]
                if pktip <= max_ip and pktip >= min_ip:
                    return True
            return False


    #Implements binary search for country code.
    #Return the country code for the pkt. 
    def handle_country(self, pktip, mid=0, left=0, right=0):

        #Need to convert IP addresses before being able to compare them. 
        pktip = struct.unpack('!L', socket.inet_aton(pktip))
        l = ''


        #check some corner cases
        if len(self.geoIP) == 0:
            return None

        if len(self.geoIP) == 1:
            l = self.geoIP[0].split()
            startIP = struct.unpack('!L', socket.inet_aton(l[0]))[0]
            endIP = struct.unpack('!L', socket.inet_aton(l[1]))[0]
            cc = l[2].lower()
            if (pktip >= startIP) and (pktip <= endIP):
                return cc
            else:
                return None

        #Main loop
        right = len(self.geoIP) - 1
        while left <= right:
            mid = (right - left)  // 2
		#Some shits going on here, not working
            l = self.geoIP[mid].split()
            startIP = struct.unpack('!L', socket.inet_aton(l[0]))[0]
            endIP = struct.unpack('!L', socket.inet_aton(l[1]))[0]
            cc = l[2].lower()

            if (pktip >= startIP) and (pktip <= endIP):
                return cc
            elif (pktip < startIP):
                right = mid - 1

            elif (pktip > endIP):
                left = mid + 1

        return None





    def handle_port(self, ruleport, pktport):
        ruleport = str(ruleport)
        pktport = str(pktport)
        if ruleport == 'any':
            return True

        #single value
        elif ruleport == pktport:
            return True
        #range
        else:
            if '-' in ruleport:
                portRange = ruleport.split('-')
                minPort = int(portRange[0])
                maxPort = int(portRange[1])
                pktPort = int(pktPort)
                if pktPort >= minPort and pktPort <= maxPort:
                    return True
            return False


    def handle_qname(self, pkt, questionstart):
    	name = ""
    	i = 0
    	namelen = 0
    	for b in pkt[questionstart:len(pkt)]:
    		currbyte = struct.unpack('!B',b)[0]
    		if currbyte == 0:
    			break
    		elif i != 0:
    			name += chr(currbyte)
    			i = i -1
    		else:
    			i = currbyte
    			namelen = namelen + currbyte + 1				
    			if len(name) > 0:
    				name = name + "."
    	return name, namelen + 1

    # TODO: You may want to add more classes/functions as well.