import datetime
import ipaddress
import hashlib
import struct
p4 = bfrt.pint

logfile = "/home/sde/pint_digestProc.log"

maxDeciderHash = 1<<16
maxGlobalHash = 1<<16 #1<<16: 65536
maxValueHash = 1<<32 #1<<32: 4294967296

#Contains the mappings between ingress ports and switch ID
switchIDPortMap = {
64: 0,
134: 0,
135: 1,
184: 1,
168: 2,
36: 2,
52: 3,
152: 3,
136: 4,
65: 4
}

portsEgressingNetwork = [
64,
65,
56,
57
]

#Specify static forwarding rules for each virtual switch
forwardingRules = {
0: [("10.0.0.101", 64),("10.0.0.102", 134)],
1: [("10.0.0.101", 135),("10.0.0.102", 184)],
2: [("10.0.0.101", 168),("10.0.0.102", 36)],
3: [("10.0.0.101", 52),("10.0.0.102", 152)],
4: [("10.0.0.101", 136),("10.0.0.102", 65)],
}


def log(text):
	global logfile, datetime
	line = "%s \t DigProc: %s" %(str(datetime.datetime.now()), str(text))
	print(line)
	
	f = open(logfile, "a")
	f.write(line + "\n")
	f.close()

def calcGlobalHash(hopNum, pktID):
	global hashlib, struct, maxGlobalHash
	indata = struct.pack("BH", hopNum, pktID)
	hashval = int(hashlib.md5(indata).hexdigest(),16) % maxGlobalHash
	return hashval

def calcValueHash(value, pktID):
	global hashlib, struct, maxValueHash
	indata = struct.pack("IH", value, pktID)
	hashval = int(hashlib.md5(indata).hexdigest(),16) % maxValueHash
	return hashval

class Digest:
	digest = None
	hop_number = None
	pkt_id = None
	ip_src = None
	ip_dst = None
	
	def __init__(self, dig):
		global log
		log("Creating a new digest... Raw:%s" %str(dig))
		
		self.digest = dig["digest"]
		self.hop_number = dig["hop_number"]
		self.pkt_id = dig["pkt_id"]
		self.ip_src = ipaddress.IPv4Address(dig["ip_src"])
		self.ip_dst = ipaddress.IPv4Address(dig["ip_dst"])
		
		log("New digest created: %s" %str(self))
	
	def __str__(self):
		return "Dig:%s, hop:%i, pkt_id:%i, ip_src:%s, ip_dst:%s" %(hex(self.digest), self.hop_number, self.pkt_id, self.ip_src, self.ip_dst)
	
	

def digest_callback(dev_id, pipe_id, direction, parser_id, session, msg):
	global p4, log, Digest
	#smac = p4.Ingress.smac
	log("Received message from data plane!")
	for dig in msg:
		Digest(dig)
		print("")
	
	return 0

def bindDigestCallback():
	global digest_callback, log, p4
	
	try:
		p4.learn.SwitchIngressDeparser.pint_cpu_digest.callback_deregister()
	except:
		pass
	finally:
		log("Deregistering old callback function (if any)")

	#Register as callback for digests (bind to DMA?)
	log("Registering callback...")
	p4.learn.SwitchIngressDeparser.pint_cpu_digest.callback_register(digest_callback)

	log("Bound callback to digest")

def populateGlobalHashTable():
	global p4, log, calcGlobalHash
	log("Populating global hash lookup table...")
	
	for pktID in range(0,1000):
		for hopNum in range(0,10):
			hashVal = calcGlobalHash(hopNum, pktID)
			p4.SwitchIngress.pint.hashlookup_global.add_with_doLookupHash_global(hop_number=hopNum, identification=pktID, hashvalue=hashVal)

def populateValueHashTable():
	global p4, log, calcValueHash
	log("Populating value hash lookup table...")
	
	for pktID in range(0,1000):
		for value in range(0,64):
			hashVal = calcValueHash(value, pktID)
			p4.SwitchIngress.pint.hashlookup_value.add_with_doLookupHash_value(raw_value=value, identification=pktID, hashvalue=hashVal)


def insertForwardingRules():
	global p4, log, ipaddress, forwardingRules
	log("Inserting forwarding rules...")
	
	for switchID in forwardingRules:
		for dstAddr,egrPort in forwardingRules[switchID]:
			dstIP = ipaddress.ip_address(dstAddr)
			log("s%i %s->%i" %(switchID, dstIP, egrPort))
			p4.SwitchIngress.tbl_forward.add_with_forward(switch_id=switchID, dstaddr=dstIP, port=egrPort)
	

def insertSwitchIDRules():
	global p4, log, switchIDPortMap
	log("Inserting Switch ID P4 rules...")
	
	
	for inPort in switchIDPortMap:
		switchID = switchIDPortMap[inPort]
		p4.SwitchIngress.tbl_set_switch_id.add_with_set_switch_id(ingress_port=inPort, switch_id=switchID)

def insertSinkDetectingRules():
	global p4, log, portsEgressingNetwork
	log("Inserting sink detecting P4 rules...")
	
	
	for egrPort in portsEgressingNetwork:
		p4.SwitchIngress.tbl_checkIsSink.add_with_set_is_sink(ucast_egress_port=egrPort)
	
def populateTables():
	global p4, log, insertSwitchIDRules, insertForwardingRules, populateGlobalHashTable, populateValueHashTable, insertSinkDetectingRules
	
	log("Populating the P4 tables...")
	
	insertSwitchIDRules()
	populateGlobalHashTable()
	populateValueHashTable()
	insertForwardingRules()
	insertSinkDetectingRules()

log("Starting")

populateTables()
bindDigestCallback()

log("Bootstrap complete")
