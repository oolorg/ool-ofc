import json

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset, ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as port_no_lib
from ryu.lib.packet import packet, ethernet
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.topology.switches import get_switch, get_link
from operator import attrgetter

from api.service import SwitchController
from common import conf, log, define
from client.ofpm import OfpmClient
from stats.stats import OfpStats

GONFIG = conf.read_conf()
LOG = log.getLogger(__name__)

OFP_VERSION_13 = ofproto_v1_3.OFP_VERSION
OFP_VERSION_10 = ofproto_v1_0.OFP_VERSION
CURRENT_OFP_VERSION = OFP_VERSION_13

class OfPatchOfc(app_manager.RyuApp):
	OFP_VERSIONS = [CURRENT_OFP_VERSION]
	_CONTEXTS = { 'dpset':dpset.DPSet, 'wsgi':WSGIApplication, }

	def __init__(self, *args, **kwargs):
		LOG.debug("START")
		LOG.debug(" CURRENT_OFP_VERSION = " + str(CURRENT_OFP_VERSION) + ", Note! ofproto_v1_x.OFP_VERSION")

		super(OfPatchOfc, self).__init__(*args, **kwargs)
		self.switches = {}
		wsgi = kwargs['wsgi']
		wsgi.register(SwitchController, {define.OFP_OFC_INSTANCE_NAME : self})

		self.ofpmClient = OfpmClient()

		self.ofpStats = OfpStats()

		LOG.debug("END")

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def _switch_features_handler(self, ev):
		LOG.debug("START")

		datapath = ev.msg.datapath
		self.switches[datapath.id] = datapath
		LOG.info('Switch is joined : ' + str(hex(datapath.id)))

		# set table-miss flow entry. Default:All Drop
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = []
		self.add_flow(datapath, define.FLOW_PRIORITY_DROP, define.FLOW_IDLE_TIMEOUT_NO_LIMIT, define.FLOW_HARD_TIMEOUT_NO_LIMIT, match, actions);

		self.ofpmClient.init_flow(datapath.id)

#		dpid = hex(datapath.id)
#		LOG.info('dpid = ' + str(dpid))
#		if str(dpid) == "0x5e3e089e01e99558":
#			LOG.info('dpid == 0x5e3e089e01e99558')
#			for i in range(51,60):
#				self.ofpmClient.set_flow(datapath.id, 1, "00:00:00:00:00:"+str(i), "ff:ff:ff:ff:ff:ff")

		LOG.debug("END")

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		LOG.debug("START")

		datapath = ev.msg.datapath
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		dpid = datapath.id
		inPort = msg.match['in_port']
		srcMac = eth.src
		dstMac = eth.dst
		LOG.info('packet in dpid=%s, inPort=%s, srcMac=%s, dstMac=%s', dpid, inPort, srcMac, dstMac)

		# Suppress redundant packet in.
		datapath = self.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch(in_port=inPort, eth_src=srcMac, eth_dst=dstMac)
		actions = []
		try:
			self.add_flow(datapath, define.FLOW_PRIORITY_PACKET_IN_DISABLE, define.FLOW_IDLE_TIMEOUT_PACKET_IN_DISABLE, define.FLOW_HARD_TIMEOUT_NO_LIMIT, match, actions)
		except Exception as e:
			LOG.error(e)

		# Notify packet in to ofpm.
		self.ofpmClient.set_flow(dpid, inPort, srcMac, dstMac)

		#LOG.info('delete Drop flow START : dpid=%s, inPort=%s, srcMac=%s', dpid, inPort, srcMac)
		#match = parser.OFPMatch(in_port=inPort, eth_src=srcMac)
		#actions = []
		#try:
		#	self.del_flow(datapath, define.FLOW_PRIORITY_PACKET_IN_DISABLE, match, actions)
		#except Exception as e:
		#	LOG.error(e)
		#LOG.info('delete Drop flow START : dpid=%s, inPort=%s, srcMac=%s', dpid, inPort, srcMac)

		LOG.debug("END")

	@set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
	def desc_stats_reply_handler(self, ev):
		self.ofpStats.desc_stats_reply(ev)

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		self.ofpStats.port_stats_reply(ev)

	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		self.ofpStats.port_desc_stats_reply(ev)

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
		self.ofpStats.flow_stats_reply(ev)

	def add_flow(self, datapath, priority, idle_timeout, hard_timeout, match, actions):
		LOG.debug("START")

		LOG.debug("datapath.id = " + str(hex(datapath.id)) + ", priority = " + str(priority) + ", idle_timeout = " + str(idle_timeout) + ", hard_timeout = " + str(hard_timeout))
		LOG.debug("match = " + str(match))
		LOG.debug("actions = " + str(actions))

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		if CURRENT_OFP_VERSION == OFP_VERSION_10:
			mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=priority, flags=ofproto.OFPFF_SEND_define.FLOW_REM, actions=actions)
		else:
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_ADD,idle_timeout, hard_timeout, priority, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		datapath.send_msg(mod)
		LOG.debug("END")

	def del_flow(self, datapath, priority, match, actions):
		LOG.debug("START")

		LOG.debug("datapath.id = " + str(hex(datapath.id)))
		LOG.debug("priority = " + str(priority))
		LOG.debug("match = " + str(match))
		LOG.debug("actions = " + str(actions))

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		if CURRENT_OFP_VERSION == OFP_VERSION_10:
			mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0, priority=priority, flags=ofproto.OFPFF_SEND_define.FLOW_REM, actions=actions)
		else:
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE,0, 0, priority, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		datapath.send_msg(mod)
		LOG.debug("END")

