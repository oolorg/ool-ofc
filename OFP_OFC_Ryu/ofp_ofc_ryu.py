import logging
import logging.handlers
import json
import struct
import threading
import time
import cgi
import httplib2
import pprint
import unirest

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as port_no_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_0
from ryu.topology.switches import get_switch, get_link
from webob import Response

# define log data
LOG_FILENAME = '/var/log/ool-ofc/log.out'
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "%(asctime)s %(name)s %(levelname)s : %(message)s"
# create formatter
formatter = logging.Formatter(LOG_FORMAT)
ofc_logger = logging.getLogger('ofp_ofc_ryu')
ofc_logger.setLevel(LOG_LEVEL)
# create file handler
handler_file = logging.handlers.RotatingFileHandler(
            LOG_FILENAME,
            maxBytes=10*1024*1024,
            backupCount=2)
handler_file.setFormatter(formatter)
ofc_logger.addHandler(handler_file)

# Definition
ofp_ofc_ryu_instance_name = 'ofp_ofc_ryu_instance_name'

url = '/ofc/ryu/ctrl'
unirest.timeout(60)

FLOW_PRIORITY_DROP					= 200
FLOW_PRIORITY_PACKET_IN				= 400
FLOW_PRIORITY_PACKET_IN_DISABLE		= 600
FLOW_PRIORITY_FLOW					= 800

FLOW_IDLE_TIMEOUT_NORMAL				= 65535		# About 18hour.
FLOW_IDLE_TIMEOUT_PACKET_IN_DISABLE		= 60 * 10	# 10minutes
FLOW_IDLE_TIMEOUT_NO_LIMIT				= 0
FLOW_HARD_TIMEOUT_NO_LIMIT				= 0

HTTP_STATUS_SUCCESS			= 200
HTTP_STATUS_CREATED_SUCCESS	= 201
HTTP_STATUS_BAD_REQUEST		= 400
HTTP_STATUS_INTL_SRV_ERR	= 500

SUCCESS_MSG				= "Success"
ERR_MSG_BAD_REQUEST		= "Bad Request"
ERR_MSF_INT_SRV_ERR		= "Internal server error"

OFP_VERSION_13 = ofproto_v1_3.OFP_VERSION
OFP_VERSION_10 = ofproto_v1_0.OFP_VERSION

CURRENT_OFP_VERSION = OFP_VERSION_13

class OfPatchOfc(app_manager.RyuApp):
	OFP_VERSIONS = [CURRENT_OFP_VERSION]
	_CONTEXTS = { 'dpset':dpset.DPSet, 'wsgi':WSGIApplication, }

	def __init__(self, *args, **kwargs):
		funcName = "__init__()"
		ofc_logger.debug(funcName + " : START")
		ofc_logger.debug(funcName + " CURRENT_OFP_VERSION = " + str(CURRENT_OFP_VERSION) + ", Note! ofproto_v1_x.OFP_VERSION")

		super(OfPatchOfc, self).__init__(*args, **kwargs)
		self.switches = {}
		wsgi = kwargs['wsgi']
		wsgi.register(SwitchController, {ofp_ofc_ryu_instance_name : self})

		# Read Config file.
		f = open('config.txt')
		self.configData = json.load(f)
		self.ofpmSetFlowUrl = self.configData['ofpmSetFlowUrl']
		self.ofpmInitFlowUrl = self.configData['ofpmInitFlowUrl']
		f.close()
		self.ofpmClient = ofpm_client(self.ofpmSetFlowUrl, self.configData['ofpmInitFlowUrl'])
		ofc_logger.debug(funcName + " : END")


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def _switch_features_handler(self, ev):
		funcName = "_switch_features_handler()"
		ofc_logger.debug(funcName + " : START")

		datapath = ev.msg.datapath
		self.switches[datapath.id] = datapath
		ofc_logger.info(funcName + ' : Switch is joined : ' + str(hex(datapath.id)))

		# set table-miss flow entry. Default:All Drop
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		#match = parser.OFPMatch(in_port=ofproto.OFPP_ANY)
		actions = []
		self.add_flow(datapath, FLOW_PRIORITY_DROP, FLOW_IDLE_TIMEOUT_NO_LIMIT, FLOW_HARD_TIMEOUT_NO_LIMIT, match, actions);
		ofc_logger.info(funcName + ' : ofpmClient.init_flow() START')
		self.ofpmClient.init_flow(datapath.id)
		ofc_logger.info(funcName + ' : ofpmClient.init_flow() END')
		ofc_logger.debug(funcName + " : END")

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		funcName = "_packet_in_handler()"
		ofc_logger.debug(funcName + " : START")

		datapath = ev.msg.datapath
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		dpid = datapath.id
		inPort = msg.match['in_port']
		srcMac = eth.src
		dstMac = eth.dst
		ofc_logger.info(funcName + ' : packet in dpid=%s, inPort=%s, srcMac=%s, dstMac=%s', dpid, inPort, srcMac, dstMac)

		# Suppress redundant PacketIN
		datapath = self.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch(in_port=inPort, eth_src=srcMac, eth_dst=dstMac)
		actions = []
		try:
			self.add_flow(datapath, FLOW_PRIORITY_PACKET_IN_DISABLE, FLOW_IDLE_TIMEOUT_PACKET_IN_DISABLE, FLOW_HARD_TIMEOUT_NO_LIMIT, match, actions)
		except Exception as e:
			ofc_logger.error(e)


		ofc_logger.info(funcName + ' : ofpmClient.set_flow() START')
		self.ofpmClient.set_flow(dpid, inPort, srcMac, dstMac)
		ofc_logger.info(funcName + ' : ofpmClient.set_flow() END')

		#ofc_logger.info(funcName + ' : delete Drop flow START : dpid=%s, inPort=%s, srcMac=%s', dpid, inPort, srcMac)
		#match = parser.OFPMatch(in_port=inPort, eth_src=srcMac)
		#actions = []
		#try:
		#	self.del_flow(datapath, FLOW_PRIORITY_PACKET_IN_DISABLE, match, actions)
		#except Exception as e:
		#	ofc_logger.error(e)
		#ofc_logger.info(funcName + ' : delete Drop flow START : dpid=%s, inPort=%s, srcMac=%s', dpid, inPort, srcMac)

		ofc_logger.debug(funcName + " : END")

	def add_flow(self, datapath, priority, idle_timeout, hard_timeout, match, actions):
		funcName = "add_flow()"
		ofc_logger.debug(funcName + " : START")

		ofc_logger.debug(funcName + " : datapath.id = " + str(hex(datapath.id)) + ", priority = " + str(priority) + ", idle_timeout = " + str(idle_timeout) + ", hard_timeout = " + str(hard_timeout))
		ofc_logger.debug(funcName + " : match = " + str(match))
		ofc_logger.debug(funcName + " : actions = " + str(actions))

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		if CURRENT_OFP_VERSION == OFP_VERSION_10:
			mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=priority, flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
		else:
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_ADD,idle_timeout, hard_timeout, priority, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		datapath.send_msg(mod)
		ofc_logger.debug(funcName + " : END")

	def del_flow(self, datapath, priority, match, actions):
		funcName = "del_flow()"
		ofc_logger.debug(funcName + " : START")

		ofc_logger.debug(funcName + " : datapath.id = " + str(hex(datapath.id)))
		ofc_logger.debug(funcName + " : priority = " + str(priority))
		ofc_logger.debug(funcName + " : match = " + str(match))
		ofc_logger.debug(funcName + " : actions = " + str(actions))

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		if CURRENT_OFP_VERSION == OFP_VERSION_10:
			mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0, priority=priority, flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
		else:
			inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
			mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE,0, 0, priority, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		datapath.send_msg(mod)
		ofc_logger.debug(funcName + " : END")

# switch controll crass
class SwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(SwitchController, self).__init__(req, link, data, **config)
		self.switch_ctrl_spp = data[ofp_ofc_ryu_instance_name]

	@route('switch_ctrl', '/ofc/ryu/ctrl/test1', methods=['POST'])
	def testIf1(self, req, **kwargs):
		reqBody = req.body

		self.http_client = httplib2.Http()
		header = {'Content-type':'application/json'}
		body = "{}"
		resp, content = self.http_client.request("http://172.16.1.177:18080/ofpm/logical_topology/", "POST", headers=header, body=body)
		print "resp = " + str(resp)
		print "content = " + str(content)

		return self.set_response_data()

	@route('switch_ctrl', '/ofc/ryu/ctrl/test', methods=['POST'])
	def testIf(self, req, **kwargs):
		reqBody = req.body

		print "reqBody = " + str(reqBody)

		return self.set_response_data(201, "OFC OK!")

	@route('switch_ctrl', url, methods=['POST'])
	def post_flow(self, req, **kwargs):
		funcName = "post_flow()"
		ofc_logger.debug(funcName + " : START")
		ofc_logger.debug(funcName + " : ***** POST ***** : url = " + url)
		ofc_logger.debug(funcName + " : body = " + req.body)

		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			ofc_logger.debug(funcName + ' : QUERY_STRING = ' + str(queryStr))
		if reqBody:
			ofc_logger.debug(funcName + ' : body = ' + req.body)

		result = self.parse_requestBody(reqBody)
		if(result['status'] != HTTP_STATUS_SUCCESS):
			ofc_logger.error(funcName + " : END : status = " + str(result['status']) + ", message = " + result['message'])
			return self.set_response_data(result['status'], result['message'])

		try:
			switch_ctrl.add_flow(result['datapath'], result['priority'], result['idle_timeout'], result['hard_timeout'], result['match'], result['actions'])
			ret = self.set_response_data(HTTP_STATUS_CREATED_SUCCESS)
		except Exception as e:
			ofc_logger.error(e)
			ret = self.set_response_data(HTTP_STATUS_INTL_SRV_ERR, ERR_MSF_INT_SRV_ERR)

		ofc_logger.debug(funcName + " : END")
		return ret

	@route('switch_ctrl', url, methods=['DELETE'])
	def delete_flow(self, req, **kwargs):
		funcName = "delete_flow()"
		ofc_logger.debug(funcName + " : START")
		ofc_logger.debug(funcName + " : ***** DELETE ***** : url = " + url)

		ret = None
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			ofc_logger.debug(funcName + ' : QUERY_STRING = ' + str(queryStr))
		if req.body:
			ofc_logger.debug(funcName + ' : body = ' + str(req.body))

		queryRes = self.parse_queryStr(queryStr)
		if(queryRes['status'] != HTTP_STATUS_SUCCESS):
			ofc_logger.error(funcName + " : END : status = " + queryRes['status'] + ", message = " + queryRes['message'])
			return self.set_response_data(queryRes['status'], queryRes['message'])

		reqRes = self.parse_requestBody(queryRes['query'])
		if(reqRes['status'] != HTTP_STATUS_SUCCESS):
			ofc_logger.error(funcName + " : END : status = " + queryRes['status'] + ", message = " + queryRes['message'])
			return self.set_response_data(reqRes['status'], reqRes['message'])

		datapath = reqRes['datapath']
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		try:
			switch_ctrl.del_flow(reqRes['datapath'], reqRes['priority'], reqRes['match'], reqRes['actions'])
			ret = self.set_response_data(HTTP_STATUS_SUCCESS)
		except Exception as e:
			ofc_logger.error(e)
			ret = self.set_response_data(HTTP_STATUS_INTL_SRV_ERR, ERR_MSF_INT_SRV_ERR)

		ofc_logger.debug(funcName + " : END")
		return ret

	@route('ctrl', '/ctrl', methods=['OPTIONS'])
	def options_ctrl(self, req, **kwargs):
		queryStr = req.environ.get('QUERY_STRING')
		ofc_logger.debug('OPTIONS : QUERY_STRING:' + str(queryStr) + ', body = ' + str(req.body))
		ret = self.set_response_data()
		ret = set_response_headers_for_all(ret)
		ret = set_response_headers_for_options(ret)
		return ret

	def parse_requestBody(self, reqBody):
		funcName = "parse_requestBody()"
		ofc_logger.debug(funcName + " : START")

		ret = {'status':'','message':'','datapath':'','priority':FLOW_PRIORITY_FLOW,'idle_timeout':FLOW_IDLE_TIMEOUT_NORMAL,'hard_timeout':FLOW_HARD_TIMEOUT_NO_LIMIT,'match':'','actions':''}
		switch_ctrl = self.switch_ctrl_spp

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				ret['status'] = HTTP_STATUS_BAD_REQUEST
				ret['message'] = ERR_MSG_BAD_REQUEST
				ofc_logger.error(funcName + " : END : dipd is None : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
				return ret
			ofc_logger.debug(funcName + " : dpid = " + str(dpid))
		else:
			ret['status'] = HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			ofc_logger.error(funcName + " : END : Not found dpid in reqBody : ret[\'status\'] = " + str(ret['status']) + ", ret[\'message\'] = " + ret['message'])
			return ret

		datapath = switch_ctrl.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		ret['datapath'] = datapath

		matchArgs = {}
		if 'match' in reqBody:
			matchData = reqBody['match']
			if matchData:
				if 'inPort' in matchData:
					inPort = matchData['inPort']
					matchArgs.update({'in_port':inPort})
					ofc_logger.debug(funcName + " : inPort = " + str(inPort))

				if 'srcMac' in matchData:
					srcMac = matchData['srcMac']
					matchArgs.update({'eth_src':srcMac})
					ofc_logger.debug(funcName + " : srcMac = " + srcMac)

				if 'dstMac' in matchData:
					dstMac = matchData['dstMac']
					matchArgs.update({'eth_dst':dstMac})
					ofc_logger.debug(funcName + " : dstMac = " + dstMac)
		else:
			ret['status'] = HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			ofc_logger.error(funcName + " : END : Not found match in reqBody : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
			return ret

		match = parser.OFPMatch(**matchArgs)
		ret['match'] = match

		actions = []
		if 'action' in reqBody:
			action = reqBody['action']
			if action:
				if 'modSrcMac' in action:
					modSrcMac = action['modSrcMac']
					actions.append(parser.OFPActionSetField(eth_src=modSrcMac))
					ofc_logger.debug(funcName + " : modSrcMac = " + modSrcMac)

				if 'modDstMac' in action:
					modDstMac = action['modDstMac']
					actions.append(parser.OFPActionSetField(eth_dst=modDstMac))
					ofc_logger.debug(funcName + " : modDstMac = " + modDstMac)

				if 'outPort' in action:
					outPort = action['outPort']
					actions.append(parser.OFPActionOutput(outPort,0))
					ofc_logger.debug(funcName + " : outPort = " + str(outPort))

				if 'packetIn' in action:
					packeIn = action['packetIn']
					ofc_logger.debug(funcName + " : packeIn = " + packeIn)
					if 'true' == packeIn:
						ret['priority'] = FLOW_PRIORITY_PACKET_IN
						actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
						ret['idle_timeout'] = FLOW_IDLE_TIMEOUT_NO_LIMIT

				if 'drop' in action:
					drop = action['drop']
					ofc_logger.debug(funcName + " : drop = " + drop)
					if 'true' == drop:
						ret['priority'] = FLOW_PRIORITY_DROP
						actions = []
						ret['idle_timeout'] = FLOW_IDLE_TIMEOUT_NO_LIMIT
		else:
			ret['status'] = HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			ofc_logger.error(funcName + " : END : Not found action in reqBody : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
			return ret

		ret['actions'] = actions
		ret['status'] = HTTP_STATUS_SUCCESS
		ret['message'] = SUCCESS_MSG
		ofc_logger.debug(funcName + " : END : status = " + str(ret['status']) + ", message = " + ret['message'])
		return ret

	def parse_queryStr(self, queryStr):
		funcName = "parse_queryStr()"
		ofc_logger.debug(funcName + " : START")

		ret = {'status':'','message':'','query':''}

		query = cgi.parse_qsl(queryStr)
		queryParam = {}
		match = {}
		action = {}
		for param in query:
			ofc_logger.debug(funcName + " : param[0] = " + param[0] + ", param[1] = " + param[1])
			if param[0] == 'dpid':
				queryParam.update({'dpid':param[1]})
			if param[0] == 'inPort':
				match.update({'inPort':int(param[1])})
			if param[0] == 'srcMac':
				match.update({'srcMac':param[1]})
			if param[0] == 'dstMac':
				match.update({'dstMac':param[1]})
			if param[0] == 'outPort':
				action.update({'outPort':int(param[1])})
			if param[0] == 'modSrcMac':
				action.update({'modSrcMac':param[1]})
			if param[0] == 'packeIn':
				action.update({'packeIn':param[1]})
			if param[0] == 'drop':
				action.update({'drop':param[1]})

		queryParam.update({'match':match})
		queryParam.update({'action':action})
		ret['query'] = queryParam
		ret['status'] = HTTP_STATUS_SUCCESS
		ret['message'] = SUCCESS_MSG
		ofc_logger.debug(funcName + " : END : status = " + str(ret['status']) + ", message = " + ret['message'])
		return ret

	def set_response_data(self, status=HTTP_STATUS_CREATED_SUCCESS, message = SUCCESS_MSG):
		funcName = "set_response_data()"
		response_data = {'status':status, 'message':message}
		res = Response(status = status,content_type = 'application/json', body = json.dumps(response_data))
		ofc_logger.debug(funcName + " : status = " + str(status) + ", message = \"" + message + "\"")
		return res

	def set_response_headers_for_all(res):
		res.headers.update({'Access-Control-Allow-Header':'*'})
		return res

	def set_response_headers_for_options(res):
		res.headers.update({'Access-Control-Allow-Origin':'*'})
		res.headers.update({'Allow':'GET,POST,PUT,DELETE,OPTIONS'})
		res.headers.update({'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'})
		return res

class ofpm_client:

	def __init__(self, setFlowUrl, initFlowUrl):
		self.setFlowUrl = setFlowUrl
		self.initFlowUrl = initFlowUrl
		self.http_client = httplib2.Http()

	def set_flow(self, dpid, inPort, srcMac, dstMac):
		funcName = "set_flow()"
		dpidStr = (hex(dpid))
		header = {'Content-type':'application/json'}
		body = {'dpid':dpidStr[2:], 'inPort':inPort, 'srcMac':srcMac, 'dstMac':dstMac}
		ofc_logger.debug(funcName + " : body = " + str(body))
		ofc_logger.info("Request setFlow body = " + str(body))
		res = unirest.post(self.setFlowUrl, headers=header, params=str(body), callback=self.__http_response__)
		return 

	def init_flow(self, dpid):
		funcName = "init_flow()"
		dpidStr = (hex(dpid))
		header = {'Content-type':'application/json'}
		body = {'datapathId':dpidStr[2:]}
		ofc_logger.debug(funcName + " : body = " + str(body))
		ofc_logger.info("Request initFlow body = " + str(body))
		res = unirest.post(self.initFlowUrl, headers=header, params=str(body), callback=self.__http_response__)
		return

	def __http_request__(self, url, method, header, body=None):
		funcName = "__http_request__()"
		ofc_logger.debug(funcName + " : START")
		ofc_logger.debug(funcName + " : url = " + url + ", method = " + method + ", header = " + str(header) + ", body = " + str(body))

		resp, content = self.http_client.request(url, method, headers=header, body=body)
		ofc_logger.info(funcName + ' : Request Result = %s', str(content))
		ofc_logger.debug(funcName + " : END")
		return resp, content

	def __http_response__(self, res):
		funcName = "__http_response__()"
		ofc_logger.debug(funcName + " : START")
		ofc_logger.info("Response status = " + str(res.code) + ", body = " + str(res.body))
		ofc_logger.debug(funcName + " : END")
