import logging
import logging.handlers
import json
import struct
import threading
import time
import cgi

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.lib import dpid as dpid_lib
from ryu.lib import port_no as port_no_lib
from ryu.ofproto import ofproto_v1_3
from ryu.topology.switches import get_switch, get_link
from webob import Response

# define log data
LOG_FILENAME = 'log.out'
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "%(asctime)s %(name)s %(levelname)s : %(message)s"
# create formatter
formatter = logging.Formatter(LOG_FORMAT)
#logging.basicConfig(level=logging.ERROR, format=LOG_FORMAT)
# create logger
ofc_logger = logging.getLogger('ofp_ofc_ryu')
ofc_logger.setLevel(LOG_LEVEL)
# create file handler
handler_file = logging.handlers.RotatingFileHandler(
            LOG_FILENAME,
            maxBytes=512*1024,
            backupCount=2)
handler_file.setFormatter(formatter)
ofc_logger.addHandler(handler_file)
# create console handler
#handler_stream = logging.StreamHandler()
#handler_stream.setFormatter(formatter)
#ofc_logger.addHandler(handler_stream)

ofp_ofc_ryu_instance_name = 'ofp_ofc_ryu_instance_name'

url = '/ofc/ryu/ctrl'

class SimpleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = { 'dpset':dpset.DPSet, 'wsgi':WSGIApplication, }

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch, self).__init__(*args, **kwargs)
		self.switches = {}
		wsgi = kwargs['wsgi']
		wsgi.register(SwitchController, {ofp_ofc_ryu_instance_name : self}) 

		# 'IP address - datapath id' map data
		f = open('config.txt')
		self.ip_id_map = json.load(f)
		f.close()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def _switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		self.switches[datapath.id] = datapath
		ofc_logger.info('Switch is joined:' + str(datapath.id))

	def add_flow(self, dp, in_port, out_port):
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		match = parser.OFPMatch()
		match.set_in_port(in_port)

		actions = [parser.OFPActionOutput(out_port, 0)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

		mod = parser.OFPFlowMod(dp, 0, 0, 0, ofproto.OFPFC_ADD,
							0, 0, 0, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		dp.send_msg(mod)

	def del_flow(self, dp, in_port, out_port):
		ofproto = dp.ofproto
		parser = dp.ofproto_parser

		match = parser.OFPMatch()
		match.set_in_port(in_port)

		actions = [parser.OFPActionOutput(out_port, 0)]
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(dp, 0, 0, 0, ofproto.OFPFC_DELETE_STRICT,
					0, 0, 0, 0xffffffff, ofproto.OFPP_ANY, 0xffffffff, 0, match, inst)

		dp.send_msg(mod)

# switch controll crass
class SwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(SwitchController, self).__init__(req, link, data, **config)
		self.switch_ctrl_spp = data[ofp_ofc_ryu_instance_name]

	@route('switch_ctrl', url, methods=['POST'])
	def post_flow(self, req, **kwargs):
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp
		ip_id_map = switch_ctrl.ip_id_map

		queryStr = req.environ.get('QUERY_STRING')
		ofc_logger.debug('POST : QUERY_STRING:' + str(queryStr) + ', body = ' + str(req.body))

		for list in ip_id_map['list']:
			if list['ofsIp'] == reqBody['ip']:
				dpid = switch_ctrl.switches[list['ofsDatapathId']]
		if dpid == None:
			return self.set_response_data(400, 'Do not find datapath id: ip = ' + reqBody['ip'])

		try:
			switch_ctrl.add_flow(dpid, reqBody['port'][0], reqBody['port'][1])
			switch_ctrl.add_flow(dpid, reqBody['port'][1], reqBody['port'][0])
			ret = self.set_response_data()
		except Exception as e:
			ofc_logger.error(e)
			ret = self.set_response_data(500, 'Internal server error')

		return ret

	@route('switch_ctrl', url, methods=['DELETE'])
	def delete_flow(self, req, **kwargs):
		ret = None
		dpid = None
		switch_ctrl = self.switch_ctrl_spp
		ip_id_map = switch_ctrl.ip_id_map

		queryStr = req.environ.get('QUERY_STRING')
		ofc_logger.debug('DELETE : QUERY_STRING:' + str(queryStr) + ', body = ' + str(req.body))
		query = cgi.parse_qsl(queryStr)
		queryParam = {}
		for param in query:
			if param[0] == 'ip':
				queryParam.update({'ip':param[1]})
			if param[0] == 'port':
				queryParam.update({'port':param[1].split(",")})

		ofc_logger.debug('ip = ' + queryParam['ip'] + ', port[0] = ' + queryParam['port'][0] + ', port[1] = ' + queryParam['port'][1])

		for list in ip_id_map['list']:
			if list['ofsIp'] == queryParam['ip']:
				dpid = switch_ctrl.switches[list['ofsDatapathId']]
		if dpid == None:
			return self.set_response_data(400, 'Do not find datapath id: ip = ' + queryParam['ip'])

		try:
			switch_ctrl.del_flow(dpid, int(queryParam['port'][0]), int(queryParam['port'][1]))
			switch_ctrl.del_flow(dpid, int(queryParam['port'][1]), int(queryParam['port'][0]))
			ret = self.set_response_data(200)
		except Exception as e:
			ofc_logger.error(e)
			ret = self.set_response_data(500, 'Internal server error')

		return ret

	@route('ctrl', '/ctrl', methods=['OPTIONS'])
	def options_ctrl(self, req, **kwargs):
		queryStr = req.environ.get('QUERY_STRING')
		ofc_logger.debug('OPTIONS : QUERY_STRING:' + str(queryStr) + ', body = ' + str(req.body))
		ret = self.set_response_data()
		ret = set_response_headers_for_all(ret)
		ret = set_response_headers_for_options(ret)
		return ret

	def set_response_data(self, status=201, message = ''):
		response_data = {'status':status, 'message':message}
		res = Response(content_type = 'application/json', body = json.dumps(response_data))
		if status == 200 or status == 201:
			ofc_logger.debug("status = " + str(status) + ", message = \"" + message + "\"")
		else:
			ofc_logger.error("status = " + str(status) + ", message = \"" + message + "\"")

		return res

	def set_response_headers_for_all(res):
		res.headers.update({'Access-Control-Allow-Header':'*'})

	def set_response_headers_for_options(res):
		res.headers.update({'Access-Control-Allow-Origin':'*'})
		res.headers.update({'Allow':'GET,POST,PUT,DELETE,OPTIONS'})
		res.headers.update({'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'})
		return res

