import json
from common import log, define
from client.ofpm import OfpmClient

LOG = log.getLogger(__name__)

class OfpStats:

	def __init__(self, *args, **kwargs):
		self.ofpmClient = OfpmClient()

	def desc_stats_reply(self, ev):
		dpid = hex(ev.msg.datapath.id)
		LOG.info('\nEventOFPDescStatsReply')
		bodyData = json.loads(json.dumps(ev.msg.to_jsondict()))
		bodyData.update({'dpid':dpid})
		LOG.info(json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2))
		descStats = json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2)
		self.ofpmClient.set_desc_stats(dpid, descStats)
	
	def port_stats_reply(self, ev):
		body = ev.msg.body
		dpid = hex(ev.msg.datapath.id)
		LOG.info('\nEventOFPPortStatsReply')
		bodyData = json.loads(json.dumps(ev.msg.to_jsondict()))
		bodyData.update({'dpid':dpid})
		LOG.info(json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2))
		portStats = json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2)
		self.ofpmClient.set_port_stats(dpid, portStats)
	
	def port_desc_stats_reply(self, ev):
		dpid = hex(ev.msg.datapath.id)
		LOG.info('\nEventOFPPortDescStatsReply')
		bodyData = json.loads(json.dumps(ev.msg.to_jsondict()))
		bodyData.update({'dpid':dpid})
		LOG.info(json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2))
		portDescStats = json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2)
		self.ofpmClient.set_port_desc_stats(dpid, portDescStats)
	
	def flow_stats_reply(self, ev):
		dpid = hex(ev.msg.datapath.id)
		LOG.info('\nEventOFPFlowStatsReply')
		bodyData = json.loads(json.dumps(ev.msg.to_jsondict()))
		bodyData.update({'dpid':dpid})
		LOG.info(json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2))
		flowStats = json.dumps(bodyData, ensure_ascii=True, sort_keys=True, indent=2)
		self.ofpmClient.set_flow_stats(dpid, flowStats)
