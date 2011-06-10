#!/usr/bin/python

import optparse
import sys

sys.path.insert(0, 'pyasn1-0.0.13b/')
sys.path.insert(0, 'pysnmp-4.1.16a/')
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen, cmdrsp, context

class hiT:
	def __init__(self, host, port, username, password, snmp_context):
		self.snmp_context = snmp_context

		self.snmp_engine = engine.SnmpEngine()
		# HiT7300 uses the user password for encryption (privacy protocol) pass phrase (PSK?)
		config.addV3User(
				self.snmp_engine,
				username,
				config.usmHMACMD5AuthProtocol, password,
				config.usmAesCfb128Protocol, password)

		# pysnmp bug?
		# setting context doesn't affect the getCommandGenerator, so we don't set it
		# FIXME: report upstream and have cmdgen use context of snmpEngine!?
		#config.addContext(self.snmp_engine, 'tnms')
		#snmp_context = context.SnmpContext(self.snmp_engine)

		config.addTargetParams(self.snmp_engine, 'myParams', username, 'authPriv')
		#config.addTargetParams(self.snmp_engine, 'myParams', username, 'authPriv')

		config.addTargetAddr(
			self.snmp_engine, 'myTarget', config.snmpUDPDomain,
			(host, int(port)), 'myParams'
			)

		config.addSocketTransport(
			self.snmp_engine,
			udp.domainName,
			udp.UdpSocketTransport().openClientMode()
			)

		self.cbCtx = {}



	def snmp_get(self, oid):
		""" Send a SNMPv3 GET request and return result as a list of lists
		"""
		oa = map(int, oid.split('.'))
		#oid = (1,3,6,1,2,1,1,1,0)
		cmdgen.GetCommandGenerator().sendReq(
				self.snmp_engine, 'myTarget', ((oa, None),), self.cbFun, self.cbCtx, None, self.snmp_context
				)
		self.snmp_engine.transportDispatcher.runDispatcher()
		if self.cbCtx['errorIndication']:
			print self.cbCtx['errorIndication']
		elif self.cbCtx['errorStatus']:
			print self.cbCtx['errorStatus'].prettyPrint()
		else:
			res = []
			for oid, val in self.cbCtx['varBinds']:
				res.append( [ oid.prettyPrint(), val.prettyPrint().strip("'") ] )
#				print '%s = %s' % (oid.prettyPrint(), val.prettyPrint())
			return res

	def setup_session(self):
		""" Setup a NSN SNMP session

			NSN uses some funky "session" concept which appear to be 
		"""
		pass



	def cbFun(self, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
		cbCtx['errorIndication'] = errorIndication
		cbCtx['errorStatus'] = errorStatus
		cbCtx['errorIndex'] = errorIndex
		cbCtx['varBinds'] = varBinds





def main():
	parser = optparse.OptionParser()

	parser.add_option("--host", dest = "host", help = "target host, ie IP / FQDN of hiT 7300 box")
	parser.add_option("--port", dest = "port", default = "161", help = "target port, ie SNMP port of hiT 7300 box [default:161]")
	parser.add_option("--username", dest = "username", default = "Administrator", help = "username [default:Administrator]")
	parser.add_option("--password", dest = "password", help = "username [default:Administrator]")
	parser.add_option("--context", dest = "context", default = "tnms", help = "context [default:tnms]")

	options, args = parser.parse_args()

	if len(args) > 0:
		print >> sys.stderr, "Unknown arguments:", str(args)
		sys.exit(1)

	if options.host is None:
		print >> sys.stderr, "You must specify a target host"
		sys.exit(1)

	if options.username is None:
		print >> sys.stderr, "You must specify a username"
		sys.exit(1)

	if options.password is None:
		print >> sys.stderr, "You must specify a password"
		sys.exit(1)

	if options.context is None:
		print >> sys.stderr, "You must specify a context"
		sys.exit(1)

	h = hiT(options.host, options.port, options.username, options.password, options.context)
	print h.snmp_get('1.3.6.1.2.1.1.1.0')
	print h.snmp_get('1.3.6.1.2.1.1.1.0')

if __name__ == '__main__':
	sys.exit(main())
