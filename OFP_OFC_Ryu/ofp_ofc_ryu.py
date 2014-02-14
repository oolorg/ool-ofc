import logging
import json

import struct
import threading
import time

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

LOG = logging.getLogger('ryu.app.ofp_ofc_ryu')
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
		print('Switch is joined:' + str(datapath.id))

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

	@route('switch_ctrl', url, methods=['PUT'])
	def put_flow(self, req, **kwargs):
		print('\nPUT: ' + req.body)
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp
		ip_id_map = switch_ctrl.ip_id_map

		for list in ip_id_map['list']:
			if list['ofsIp'] == reqBody['ip']:
				dpid = switch_ctrl.switches[list['ofsDatapathId']]
		if dpid == None:
			return self.set_response_data(400, 'Do not find datapath id: ' + reqBody['ip'])

		try:
			switch_ctrl.add_flow(dpid, reqBody['inPort'], reqBody['outPort'])
			switch_ctrl.add_flow(dpid, reqBody['outPort'], reqBody['inPort'])
			ret = self.set_response_data()
		except Exception as e:
			print e
			ret = self.set_response_data(500, 'Internal server error')

		return ret

	@route('switch_ctrl', url, methods=['DELETE'])
	def delete_flow(self, req, **kwargs):
		print('\nDELETE: ' + req.body)
		ret = None
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp
		ip_id_map = switch_ctrl.ip_id_map

		for list in ip_id_map['list']:
			if list['ofsIp'] == reqBody['ip']:
				dpid = switch_ctrl.switches[list['ofsDatapathId']]
		if dpid == None:
			return self.set_response_data(400, 'Do not find datapath id: ' + reqBody['ip'])

		try:
			switch_ctrl.del_flow(dpid, reqBody['inPort'], reqBody['outPort'])
			switch_ctrl.del_flow(dpid, reqBody['outPort'], reqBody['inPort'])
			ret = self.set_response_data()
		except Exception as e:
			print e
			ret = self.set_response_data(500, 'Internal server error')

		return ret

	@route('ctrl', '/ctrl', methods=['OPTIONS'])
	def options_ctrl(self, req, **kwargs):
		ret = self.set_response_data()
		ret = set_response_headers_for_all(ret)
		ret = set_response_headers_for_options(ret)
		return ret

	def set_response_data(self, state=201, message = ''):
		response_data = {'Status':state, 'Message':message}
		res = Response(content_type = 'application/json', body = json.dumps(response_data))
		print(json.dumps(response_data))
		return res

	def set_response_headers_for_all(res):
		res.headers.update({'Access-Control-Allow-Header':'*'})

	def set_response_headers_for_options(res):
		res.headers.update({'Access-Control-Allow-Origin':'*'})
		res.headers.update({'Allow':'GET,POST,PUT,DELETE,OPTIONS'})
		res.headers.update({'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'})
		return res

