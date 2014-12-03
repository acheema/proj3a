#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from collections import defaultdict

import struct
import socket
import random
import re

DEBUG = False
DEBUG_HTTP = False

PASS = 0
DROP = 1
DENY = 2
NONE = 3



class http(object):
	def __init__(self):
		self.destroy()

	def destroy(self):
		self.inbuff = ""
		self.outbuff = ""
		self.inhead = []
		self.outhead = []
		self.inheader = False
		self.outheader = False
		self.prevdata = False
		self.previous = PKT_DIR_INCOMING
	def handle_ack(self, pkt_info, pkt_dir, domain_name):
		if pkt_dir == PKT_DIR_OUTGOING:
			if len(pkt_info['data']) > 0:
				if self.outheader == False:
					self.outbuff += pkt_info['data']
				if header_end_exists(pkt_info['data']) and self.outheader == False:
					self.outheader = True
		else:
			if len(pkt_info['data']) > 0:		
				if self.inheader == False:
					self.inbuff += pkt_info['data']
				if header_end_exists(pkt_info['data']) and self.inheader == False:
					self.inheader = True
		if header_end_exists(self.inbuff) and header_end_exists(self.outbuff):
			self.inhead = [self.inbuff]
			self.outhead = [self.outbuff]
			lines = [http_line(self.inhead[i], self.outhead[i]) for i in xrange(len(self.inhead))]
			for l in lines:
                                if search_regex(domain_name, l.split()[0]) != None:
                                        logfile = open('http.log', 'a')
                                        logfile.write(l + '\n')
                                        logfile.flush()
                                        logfile.close()
                        self.destroy()
		self.previous = pkt_dir
		self.prevdata = len(pkt_info['data']) > 0

class Firewall:
	TCP = 6
	UDP = 17
	ICMP = 1

	def __init__(self, config, iface_int, iface_ext):
		self.iface_int = iface_int
		self.iface_ext = iface_ext
		self.rules = []
		with open(config['rule'], 'r') as f:
			lines = [l.strip() for l in f.readlines()]
			lines = [l for l in lines if len(l) > 0]
			lines = [l for l in lines if l[0] != "%"]

			self.rules = lines
		self.expected_seqno = defaultdict(lambda: -1)
		self.http_connections = defaultdict(lambda: http())

	def handle_packet(self, pkt_dir, pkt):

		verdict, pktdict = self.handle_rules(pkt_dir, pkt)
		protocol = pktdict['protocol']
		if verdict == PASS:
			if pkt_dir == PKT_DIR_OUTGOING:
				self.iface_ext.send_ip_packet(pkt)
			else:
				self.iface_int.send_ip_packet(pkt)
		elif verdict == DENY:
			if protocol == "tcp":
				packet = self.tcp_packet(pktdict, pkt)
				if pkt_dir == PKT_DIR_OUTGOING:
					self.iface_int.send_ip_packet(packet)
				else:
					self.iface_ext.send_ip_packet(packet)
			elif protocol == "dns":
				packet = self.dns_packet(pktdict, pkt)
				self.iface_int.send_ip_packet(packet)

	def tcp_packet(self, pktdict, packet):
		iphlen = pktdict['ihl'] * 4
		packet = packet[0:8] + struct.pack('!B', 64) + packet[9:]
		packet = packet[0:12] + socket.inet_aton(pktdict['dst_ip']) + packet[16:]
		packet = packet[0:16] + socket.inet_aton(pktdict['src_ip']) + packet[20:]
		packet = packet[0:iphlen] + struct.pack('!H', pktdict['tcp_dst']) + packet[iphlen+2:]
		packet = packet[0:iphlen + 2] + struct.pack('!H', pktdict['tcp_src']) + packet[iphlen + 4:]
		newack = struct.pack('!L', struct.unpack('!L', packet[iphlen + 4:iphlen + 8])[0] + 1)
		packet = packet[0:iphlen + 4] + struct.pack('!L', 0) + packet[iphlen + 8:]
		packet = packet[0:iphlen + 8] + newack + packet[iphlen + 12:]
		packet = packet[0:iphlen + 13] + struct.pack('!B', 0x10+ 0x04) + packet[iphlen + 14:]
		if pktdict['pktlength'] != len(packet):
			packet = packet[0:2] + struct.pack('!H', len(packet)) + packet[4:]
		ip_checksum = struct.pack('!H', self.compute_ip_checksum(packet))
		packet = packet[0:10] + ip_checksum + packet[12:]
		tcp_checksum = struct.pack('!H', self.compute_transport_checksum(packet))
		packet = packet[0:iphlen + 16] + tcp_checksum + packet[iphlen + 18:]
		return packet

	def dns_packet(self, pktdict, packet):
		iphlen = pktdict['ihl'] * 4
		dns_header = iphlen + 8
		packet = packet[0:8] + struct.pack('!B', 64) + packet[9:]
		packet = packet[0:12] + socket.inet_aton(pktdict['dst_ip']) + packet[16:]
		packet = packet[0:16] + socket.inet_aton(pktdict['src_ip']) + packet[20:]
		packet = packet[0:iphlen] + struct.pack('!H', pktdict['udp_dst']) + packet[iphlen+2:]
		packet = packet[0:iphlen + 2] + struct.pack('!H', pktdict['udp_src']) + packet[iphlen + 4:]
		options = struct.unpack('!H', packet[dns_header + 2:dns_header + 4])[0]
		qr = 0b1 << 15
		options = options | qr
		packet = packet[0:dns_header + 2] + struct.pack('!H', options) + packet[dns_header + 4:]
		packet = packet[0:dns_header + 6] + struct.pack('!H', 1) + packet[dns_header + 8:]
		qloc = dns_header + 12 + pktdict['qname_len']
		packet = packet[0:qloc] + struct.pack('!H', 1) + packet[qloc + 2:]
		packet = packet[0:qloc + 2] + struct.pack('!H', 1) + packet[qloc + 4:]
		packet = packet[0:qloc + 4]
		packet += packet[dns_header + 12:]
		packet += struct.pack('!L', 1)
		packet += struct.pack('!H', 4)
		packet += socket.inet_aton('54.173.224.150')
		packet = packet[0:iphlen + 4] + struct.pack('!H', len(packet) - iphlen) + packet[iphlen + 6:]
		packet = packet[0:2] + struct.pack('!H', len(packet)) + packet[4:]
		ip_checksum = struct.pack('!H', self.compute_ip_checksum(packet))
		packet = packet[0:10] + ip_checksum + packet[12:]
		tcp_checksum = struct.pack('!H', self.compute_transport_checksum(packet))
		packet = packet[0:iphlen + 6] + tcp_checksum + packet[iphlen + 8:]
		return packet


	def compute_ip_checksum(self, packet):
		nleft = header_len = (struct.unpack('!B', packet[0:1])[0] & 0x0F) * 4
		checksum = 0
		while nleft > 1:
			if nleft != 12: 
				checksum += struct.unpack('!H', packet[nleft - 2:nleft])[0]
			nleft -= 2
		checksum = (checksum >> 16) + (checksum & 0xFFFF)
		checksum += (checksum >> 16)
		checksum = (~checksum) & 0xFFFF
		return checksum


	def compute_transport_checksum(self, packet):
		total_len = struct.unpack('!H', packet[2:4])[0]
		header_len = (struct.unpack('!B', packet[0:1])[0] & 0x0F) * 4
		if total_len % 2 != 0:
			new_len = total_len + 1
			packet += struct.pack('!B', 0)
		else:
			new_len = total_len

		checksum = 0
		if (struct.unpack('!B', packet[9:10])[0] == 6): #TCP
			prot = "tcp"
			orig_chksum = struct.unpack('!H', packet[header_len + 16:header_len + 18])[0] #TCP
			for i in range(header_len, new_len, 2):
				if i != (header_len + 16):
					checksum += struct.unpack("!H", packet[i: i+ 2])[0]
		elif (struct.unpack('!B', packet[9:10])[0] == 17): #UDP
			prot = "udp"
			orig_chksum = struct.unpack('!H', packet[header_len + 6:header_len + 8])[0] #UDP
			for i in range(header_len, new_len, 2):
				if i != (header_len + 6):
					checksum += struct.unpack("!H", packet[i: i+ 2])[0]

		checksum += struct.unpack("!H", packet[12:14])[0]
		checksum += struct.unpack("!H", packet[14:16])[0]
		checksum += struct.unpack("!H", packet[16:18])[0]
		checksum += struct.unpack("!H", packet[18:20])[0]

		checksum += struct.unpack('!B', packet[9:10])[0]
		checksum += total_len - header_len

		checksum = (checksum >> 16) + (checksum & 0xFFFF)
		checksum += (checksum >> 16)
		checksum = ~checksum & 0xFFFF
		return checksum

	def handle_rules(self, pkt_dir, pkt):
		pass_pkt = PASS

		#Pull all the relavant information out of the packet
		pkt_info = self.read_pkt(pkt)
		#debug(pkt_info)
		if pkt_info == None:
			debug("Dropping, packet is None")
			return DROP, pkt_info

		pkt_protocol = pkt_info['protocol']

		#Pass all packets that aren't using ICMP, TCP, or UDP
		if pkt_info['protocol'] == "other":
			debug("passing")
			return PASS, pkt_info

		#Pass all DNS packets that fall outside the scope of the project
		if pkt_protocol == "dns" and pkt_info['valid_dns'] == True:
			if pkt_info['dns_qtype'] != 1 and pkt_info['dns_qtype'] != 28:
				return PASS, pkt_info
			if pkt_info['dns_qclass'] != 1:
				return PASS, pkt_info

		#Handle all of the rules
		for rule in self.rules:
			rule_tuple = tuple([t.lower() for t in rule.split()])
			
			#Handle Transport Layer Rules
			if len(rule_tuple) == 4:
				# Protocol/IP/Port rules
				verdict, protocol, ext_ip_address, ext_port = rule_tuple
				if verdict == "deny":
					debug(rule)

				#If the protocol of the rule doesn't match current protocol, go to the next rule
				if (protocol == "http") and (pkt_info['HTTP'] == True):
					http_rules = self.process_http_rules(verdict, protocol, ext_ip_address, ext_port)
					if http_rules != NONE:
						pass_pkt = http_rules
				elif protocol != pkt_protocol:
					continue
				else:
					# Process all Transport layer rules
					transport_rules = self.process_transport_rules(verdict, protocol, ext_ip_address, ext_port, pkt_info, pkt_dir) 
					if transport_rules != NONE:
						debug("Pass pkt: " + str(transport_rules))
						pass_pkt = transport_rules

			# handle logging
			elif len(rule_tuple) == 3 and rule_tuple[0] == "log":
				log, http, domain_name = rule_tuple

				# write to log if tcp_src == 80 or tcp_dst == 80
				if pkt_protocol == "tcp" and (pkt_info['tcp_src'] == 80 or pkt_info['tcp_dst'] == 80):
					return self.handle_log(rule_tuple, pkt_dir, pkt_info, domain_name), pkt_info

			#Handle DNS Rules
			elif len(rule_tuple) == 3 and pkt_protocol == "dns":
				#Only consider well formed DNS requests
				if pkt_info['valid_dns'] == True:
					verdict, dns, domain_name = rule_tuple
					#debug("DNS verdict is: " + str(verdict))
					dns_rules = self.process_dns_rules(verdict, domain_name, pkt_info['dns_qname'])
					#debug("DNS rules: " + str(dns_rules))
					if dns_rules != NONE:
						#debug("Pass pkt: " + str(dns_rules))
						pass_pkt = dns_rules
				else:
					debug("Invalid DNS")
					return DROP, pkt_info
		return pass_pkt, pkt_info

	def process_transport_rules(self, verdict, protocol, ext_ip_address, ext_port,
								pkt_info, pkt_dir):
		#Find the external port IP of the packet
		if pkt_dir == PKT_DIR_OUTGOING:
			pkt_ext_ip_address = pkt_info['dst_ip']
			if protocol == "icmp":
				pkt_ext_port = pkt_info[protocol + "_type"]
			else:
				pkt_ext_port = pkt_info[protocol + '_dst']
		else:
			pkt_ext_ip_address = pkt_info['src_ip']
			if protocol == "icmp":
				pkt_ext_port = pkt_info[protocol + "_type"]
			else:
				pkt_ext_port = pkt_info[protocol + '_src']

		if self.handle_ip(ext_ip_address, pkt_ext_ip_address):
			if self.handle_port(ext_port, pkt_ext_port):
				if verdict == "pass":
					return PASS
				elif verdict == "drop":
					return DROP
				else:
					return DENY

		return NONE


	def handle_port(self, ruleport, pktport):
		if ruleport == "any":
			return True

		elif ruleport == str(pktport):
			return True

		elif '-' in ruleport:
			portRange = ruleport.split('-')
			minPort = int(portRange[0])
			maxPort = int(portRange[1])
			if int(pktport) >= minPort and int(pktport) <= maxPort:
				return True
			else:
				return False
		else:
			return False

	def handle_ip(self, ruleip, pktip):
		if ruleip == "any":
			return True

		elif ruleip == pktip:
			return True

		elif "/" in ruleip:
			ip_prefix_split = ruleip.split('/')
			ip_addr = ip_prefix_split[0]
			network_bits = int(ip_prefix_split[1])
			host_bits = 32 - network_bits
			min_ip = struct.unpack('!L', socket.inet_aton(ip_addr))[0]
			max_ip = int((2**host_bits - 1) + min_ip)
			pktipComp = struct.unpack('!L', socket.inet_aton(pktip))[0]
			if pktipComp <= max_ip and pktipComp >= min_ip:
				return True
			else:
				return False
		else:
			return False

	def process_dns_rules(self, verdict, domain_name, pkt_domain_name):
		if search_regex(domain_name, pkt_domain_name) != None:
			if verdict == "pass":
				return PASS
			elif verdict == "drop":
				return DROP
			else:
				return DENY
		else:
			return NONE

	def read_pkt(self, pkt):
		packet = {}
		packet['valid'] = False

		if len(pkt) < 8:
			return None

		firstbyte = struct.unpack('!B', pkt[0:1])[0]
		packet['version'] = firstbyte >> 4
		packet['ihl'] = firstbyte & 0b00001111
		packet['tos'] = struct.unpack('!B', pkt[1:2])[0]
		packet['pktlength'] = struct.unpack('!H', pkt[2:4])[0]
		packet['ttl'] = struct.unpack('!B', pkt[8:9])[0]
		packet['ip_checksum'] = struct.unpack('!H', pkt[10:12])[0]
		if packet['ihl'] >= 5 and packet['pktlength'] == len(pkt):
			packet['valid'] = True
			packet['src_ip'] = socket.inet_ntoa(pkt[12:16])
			packet['dst_ip'] = socket.inet_ntoa(pkt[16:20])
			protocol_byte = struct.unpack('!B', pkt[9:10])[0]
			packet['protocol'] = self.match_protocol(protocol_byte, packet, pkt)
			packet['ip_id'] = struct.unpack('!H', pkt[4:6])[0]

		return packet

	def match_protocol(self, protocol, pkt_specs, pkt):
		#Find the end of the IP Header in bytes
		protocol_header = pkt_specs['ihl'] * 4

		#ICMP Protocol
		if protocol == 1:
			pkt_specs['icmp_type'] = struct.unpack('!B', pkt[protocol_header:protocol_header + 1])[0] 
			return "icmp"

		#TCP Protocol
		if protocol == 6:
			if DEBUG == True:
				self.compute_transport_checksum(pkt)
			pkt_specs['tcp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
			pkt_specs['tcp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]
			if (pkt_specs['tcp_dst'] == 80) or (pkt_specs['tcp_src'] == 80):
				pkt_specs['HTTP'] = True
			flags = struct.unpack('!B', pkt[protocol_header + 13:protocol_header + 14])[0]
			offset_reserve = struct.unpack('!B', pkt[protocol_header + 12:protocol_header + 13])[0]
			# offset is number of 32-bit words in header
			offset = (offset_reserve >> 4) * 4  # multply by 4 to convert to bytes

			pkt_specs['fin'] = 0x1 & flags == 0x1
			pkt_specs['syn'] = 0x2 & flags == 0x2
			pkt_specs['ack'] = 0x10 & flags == 0x10
			pkt_specs['data'] = pkt[protocol_header + offset:pkt_specs['pktlength']]
			pkt_specs['tcp_seqno'] = struct.unpack('!L', pkt[protocol_header + 4:protocol_header + 8])[0]
			pkt_specs['tcp_ackno'] = struct.unpack('!L', pkt[protocol_header + 8:protocol_header + 12])[0]

			return "tcp"

		#UDP Protocol
		if protocol == 17:
			pkt_specs['udp_src'] = struct.unpack('!H', pkt[protocol_header:protocol_header + 2])[0]
			pkt_specs['udp_dst'] = struct.unpack('!H', pkt[protocol_header + 2:protocol_header + 4])[0]

			if pkt_specs['udp_dst'] == 53:
				try: 
					dns_header = protocol_header + 8
					QDCOUNT = struct.unpack('!H', pkt[dns_header + 4:dns_header + 6])[0]

					if QDCOUNT != 1:
						debug("Setting valid dns to false")
						pkt_specs['valid_dns'] = False
					else:	
						pkt_specs['valid_dns'] = True
						dns_questions = dns_header + 12
						pkt_specs['dns_qname'], pkt_specs['qname_len'] = self.handle_qname(pkt, dns_questions)
						DNS_qtype_location = dns_questions + pkt_specs['qname_len']
						pkt_specs['dns_qtype'] = struct.unpack('!H', pkt[DNS_qtype_location:DNS_qtype_location + 2])[0]
						pkt_specs['dns_qclass'] = struct.unpack('!H', pkt[DNS_qtype_location + 2:DNS_qtype_location + 4])[0]
				except Exception as e:
					pkt_specs['valid_dns'] = False
				return "dns"

			return "udp"

		return "other"


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

	def increment_expected_seqno(self, stream_id, i):
		self.expected_seqno[stream_id] = (self.expected_seqno[stream_id] + i) % (0xFFFFFFFF + 1)

	def handle_log(self, rule_tuple, pkt_dir, pkt_info, domain_name):
		debug_http("*** handle_log")
		debug_http("rule_tuple: " + str(rule_tuple))
		if pkt_dir == PKT_DIR_INCOMING:
			debug_http("pkt_dir: " + str("INCOMING"))
		else:
			debug_http("pkt_dir: " + str("OUTGOING"))
		l = []
		if pkt_info['syn']:
			l.append("SYN")
		if pkt_info['fin']:
			l.append("FIN")
		if pkt_info['ack']:
			l.append("ACK")
		debug_http(','.join(l))
		debug_http('seqno: ' + str(pkt_info['tcp_seqno']) + '   ackno: ' + str(pkt_info['tcp_ackno']))
		debug_http('src: ' + str(pkt_info['src_ip']) + ":" + str(pkt_info['tcp_src']) + '   dst: ' + str(pkt_info['dst_ip']) + ":" + str(pkt_info['tcp_dst']))
		debug_http('data: ' + repr(pkt_info['data']))

		#debug_http("pkt_info: " + str(pkt_info))

		# determine stream_id
		if pkt_dir == PKT_DIR_OUTGOING:
			stream_id = (pkt_info['src_ip'], pkt_info['tcp_src'])
		else:
			stream_id = (pkt_info['dst_ip'], pkt_info['tcp_dst'])

		debug_http('expected_seqno: ' + str(self.expected_seqno[stream_id]))
		pass_pkt = PASS

		if pkt_dir == PKT_DIR_OUTGOING:
			conn_id = (pkt_info['src_ip'], pkt_info['tcp_src'])
		else:
			conn_id = (pkt_info['dst_ip'], pkt_info['tcp_dst'])
		debug_http("conn_id: " + str(conn_id))
		http_conn = self.http_connections[conn_id]
		if pkt_dir == PKT_DIR_OUTGOING:
			if pkt_info['syn'] == True and pkt_info['ack'] == False and pkt_info['fin'] == False:
				self.expected_seqno[stream_id] = pkt_info['tcp_seqno']
				self.increment_expected_seqno(stream_id, 1)
			elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
				self.increment_expected_seqno(stream_id, len(pkt_info['data']))
				http_conn.handle_ack(pkt_info, pkt_dir, domain_name)
			elif pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == True:
				self.increment_expected_seqno(stream_id, 1)
			else:
				pass
		else:
			if self.expected_seqno[stream_id] >= 0:
				if self.expected_seqno[stream_id] < pkt_info['tcp_ackno']:
					# packet out of order
					return DROP
				elif self.expected_seqno[stream_id] > pkt_info['tcp_ackno']:
					# packet retransmission
					return PASS 
			if pkt_info['syn'] == False and pkt_info['ack'] == True and pkt_info['fin'] == False:
				http_conn.handle_ack(pkt_info, pkt_dir, domain_name)
		return pass_pkt

def header_end_exists(data):
	return re.search("\r\n\r\n", data) != None
    
# This returns the line we write to file.
def http_line(incoming_stream, outgoing_stream):
	outLines = [line.split() for line in outgoing_stream.split('\n')]
	hname = re.search(r"Host: (.*)", outgoing_stream, re.IGNORECASE).group(1).strip()
	inLines = [line.split() for line in incoming_stream.split('\n')]
	if 'Content-Length' in incoming_stream:
		clen = int(re.search(r"Content-Length: (\d+)", incoming_stream, re.IGNORECASE).group(1))
	else:
		clen = -1
	#We will return the host name, method, path, version, status, and content length properly formatted
	return "{} {} {} {} {} {}".format(hname, outLines[0][0].strip(), outLines[0][1].strip(), outLines[0][2].strip(), inLines[0][1].strip(), clen)

def search_regex(domain_name, pkt_domain_name):
	pkt_domain_name = pkt_domain_name.lstrip("www.")
	if domain_name == pkt_domain_name:
		return True
	elif '*' in domain_name:
		if '*' != domain_name[0]:
			return None
		else:
			if domain_name[1:len(domain_name)] in pkt_domain_name:
				return True
	else:
		return None
