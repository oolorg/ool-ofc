import json
import cgi
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

from common import conf, log, define

LOG = log.getLogger(__name__)
CONF = conf.read_conf()

# switch controll crass
class SwitchController(ControllerBase):

	def __init__(self, req, link, data, **config):
		super(SwitchController, self).__init__(req, link, data, **config)
		self.switch_ctrl_spp = data[define.OFP_OFC_INSTANCE_NAME]

	@route('switch_ctrl', CONF.service_url, methods=['POST'])
	def post_flow(self, req, **kwargs):
		LOG.debug("START ***** POST ***** : url = " + CONF.service_url)
		LOG.debug("body = " + req.body)

		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			LOG.debug('QUERY_STRING = ' + str(queryStr))
		if reqBody:
			LOG.debug('body = ' + req.body)

		result = self.parse_requestBody(reqBody)
		if(result['status'] != define.HTTP_STATUS_SUCCESS):
			LOG.error("END : status = " + str(result['status']) + ", message = " + result['message'])
			return self.set_response_data(result['status'], result['message'])

		try:
			switch_ctrl.add_flow(result['datapath'], result['priority'], result['idle_timeout'], result['hard_timeout'], result['match'], result['actions'])
			ret = self.set_response_data(define.HTTP_STATUS_CREATED_SUCCESS)
		except Exception as e:
			LOG.error(e)
			ret = self.set_response_data(define.HTTP_STATUS_INTL_SRV_ERR, ERR_MSF_INT_SRV_ERR)

		LOG.debug("END")
		return ret

	@route('switch_ctrl', CONF.service_url, methods=['DELETE'])
	def delete_flow(self, req, **kwargs):
		LOG.debug("START ***** DELETE ***** : url = " + CONF.service_url)

		ret = None
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			LOG.debug('QUERY_STRING = ' + str(queryStr))
		if req.body:
			LOG.debug('body = ' + str(req.body))

		queryRes = self.parse_queryStr(queryStr)
		if(queryRes['status'] != define.HTTP_STATUS_SUCCESS):
			LOG.error("END : status = " + queryRes['status'] + ", message = " + queryRes['message'])
			return self.set_response_data(queryRes['status'], queryRes['message'])

		reqRes = self.parse_requestBody(queryRes['query'])
		if(reqRes['status'] != define.HTTP_STATUS_SUCCESS):
			LOG.error("END : status = " + queryRes['status'] + ", message = " + queryRes['message'])
			return self.set_response_data(reqRes['status'], reqRes['message'])

		datapath = reqRes['datapath']
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		try:
			switch_ctrl.del_flow(reqRes['datapath'], reqRes['priority'], reqRes['match'], reqRes['actions'])
			ret = self.set_response_data(define.HTTP_STATUS_SUCCESS)
		except Exception as e:
			LOG.error(e)
			ret = self.set_response_data(define.HTTP_STATUS_INTL_SRV_ERR, ERR_MSF_INT_SRV_ERR)

		LOG.debug("END")
		return ret

	@route('switch_ctrl', CONF.desc_stats_request_url, methods=['POST'])
	def desc_stats_request(self, req, **kwargs):
		LOG.debug("START ***** POST ***** : url = " + CONF.desc_stats_request_url)

		ret = None
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			LOG.debug('QUERY_STRING = ' + str(queryStr))
		if req.body:
			LOG.debug('body = ' + str(req.body))

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
				return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)
			LOG.debug("dpid = " + str(dpid))
		else:
			LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
			return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)

		datapath = switch_ctrl.switches[dpid]
		parser = datapath.ofproto_parser

		req = parser.OFPDescStatsRequest(datapath, 0)
		datapath.send_msg(req)

		ret = self.set_response_data(define.HTTP_STATUS_CREATED_SUCCESS)

		LOG.debug("END")
		return ret

	@route('switch_ctrl', CONF.port_stats_request_url, methods=['POST'])
	def port_stats_request(self, req, **kwargs):
		LOG.debug("START ***** POST ***** : url = " + CONF.port_stats_request_url)

		ret = None
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			LOG.debug('QUERY_STRING = ' + str(queryStr))
		if req.body:
			LOG.debug('body = ' + str(req.body))

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
				return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)
			LOG.debug("dpid = " + str(dpid))
		else:
			LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
			return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)

		datapath = switch_ctrl.switches[dpid]
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		port = ofproto.OFPP_ANY
		if 'port' in reqBody:
			port = reqBody['port']

		req = parser.OFPPortStatsRequest(datapath, 0, port)
		datapath.send_msg(req)

		ret = self.set_response_data(define.HTTP_STATUS_CREATED_SUCCESS)

		LOG.debug("END")
		return ret

	@route('switch_ctrl', CONF.port_desc_stats_request_url, methods=['POST'])
	def port_desc_stats_request(self, req, **kwargs):
		LOG.debug("START ***** POST ***** : url = " + CONF.port_desc_stats_request_url)

		ret = None
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		if req.body:
			LOG.debug('body = ' + str(req.body))

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
				return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)
			LOG.debug("dpid = " + str(dpid))
		else:
			LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
			return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)

		datapath = switch_ctrl.switches[dpid]
		parser = datapath.ofproto_parser

		req = parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)

		ret = self.set_response_data(define.HTTP_STATUS_CREATED_SUCCESS)

		LOG.debug("END")
		return ret

	@route('switch_ctrl', CONF.flow_stats_request_url, methods=['POST'])
	def flow_stats_request(self, req, **kwargs):
		LOG.debug("START ***** POST ***** : url = " + CONF.flow_stats_request_url)

		ret = None
		reqBody = eval(req.body)
		dpid = None
		switch_ctrl = self.switch_ctrl_spp

		queryStr = req.environ.get('QUERY_STRING')
		if queryStr:
			LOG.debug('QUERY_STRING = ' + str(queryStr))
		if req.body:
			LOG.debug('body = ' + str(req.body))

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
				return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)
			LOG.debug("dpid = " + str(dpid))
		else:
			LOG.error("END : status = " + define.HTTP_STATUS_BAD_REQUEST + ", message = " + ERR_MSG_BAD_REQUEST)
			return self.set_response_data(define.HTTP_STATUS_BAD_REQUEST, ERR_MSG_BAD_REQUEST)

		datapath = switch_ctrl.switches[dpid]
		parser = datapath.ofproto_parser

		req = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(req)

		ret = self.set_response_data(define.HTTP_STATUS_CREATED_SUCCESS)

		LOG.debug("END")
		return ret

	@route('ctrl', '/ctrl', methods=['OPTIONS'])
	def options_ctrl(self, req, **kwargs):
		queryStr = req.environ.get('QUERY_STRING')
		LOG.debug('OPTIONS : QUERY_STRING:' + str(queryStr) + ', body = ' + str(req.body))
		ret = self.set_response_data()
		ret = set_response_headers_for_all(ret)
		ret = set_response_headers_for_options(ret)
		return ret

	def parse_requestBody(self, reqBody):
		LOG.debug("START")

		ret = {'status':'','message':'','datapath':'','priority':define.FLOW_PRIORITY_FLOW,'idle_timeout':define.FLOW_IDLE_TIMEOUT_NO_LIMIT,'hard_timeout':define.FLOW_HARD_TIMEOUT_NO_LIMIT,'match':'','actions':''}
		switch_ctrl = self.switch_ctrl_spp

		idleTimeOutFlag = define.FLOW_IDLE_TIMEOUT_NO_LIMIT;

		if 'dpid' in reqBody:
			dpid = int(reqBody['dpid'], 16)
			if dpid is None:
				ret['status'] = define.HTTP_STATUS_BAD_REQUEST
				ret['message'] = ERR_MSG_BAD_REQUEST
				LOG.error("END : dipd is None : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
				return ret
			LOG.debug("dpid = " + str(dpid))
		else:
			ret['status'] = define.HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			LOG.error("END : Not found dpid in reqBody : ret[\'status\'] = " + str(ret['status']) + ", ret[\'message\'] = " + ret['message'])
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
					LOG.debug("inPort = " + str(inPort))

				if 'srcMac' in matchData:
					srcMac = matchData['srcMac']
					matchArgs.update({'eth_src':srcMac})
					idleTimeOutFlag = define.FLOW_IDLE_TIMEOUT_NORMAL;
					LOG.debug("srcMac = " + srcMac)

				if 'dstMac' in matchData:
					dstMac = matchData['dstMac']
					matchArgs.update({'eth_dst':dstMac})
					idleTimeOutFlag = define.FLOW_IDLE_TIMEOUT_NORMAL;
					LOG.debug("dstMac = " + dstMac)
		else:
			ret['status'] = define.HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			LOG.error("END : Not found match in reqBody : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
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
					idleTimeOutFlag = define.FLOW_IDLE_TIMEOUT_NORMAL;
					LOG.debug("modSrcMac = " + modSrcMac)

				if 'modDstMac' in action:
					modDstMac = action['modDstMac']
					actions.append(parser.OFPActionSetField(eth_dst=modDstMac))
					idleTimeOutFlag = define.FLOW_IDLE_TIMEOUT_NORMAL;
					LOG.debug("modDstMac = " + modDstMac)

				if 'outPort' in action:
					outPort = action['outPort']
					actions.append(parser.OFPActionOutput(outPort,0))
					LOG.debug("outPort = " + str(outPort))

				if 'packetIn' in action:
					packeIn = action['packetIn']
					LOG.debug("packeIn = " + packeIn)
					if 'true' == packeIn:
						ret['priority'] = define.FLOW_PRIORITY_PACKET_IN
						actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]

				if 'drop' in action:
					drop = action['drop']
					LOG.debug("drop = " + drop)
					if 'true' == drop:
						ret['priority'] = define.FLOW_PRIORITY_DROP
						actions = []
		else:
			ret['status'] = define.HTTP_STATUS_BAD_REQUEST
			ret['message'] = ERR_MSG_BAD_REQUEST
			LOG.error("END : Not found action in reqBody : ret[\'status\'] = " + str(ret['status'] + ", ret[\'message\'] = " + ret['message']))
			return ret

		ret['idle_timeout'] = define.FLOW_IDLE_TIMEOUT_NO_LIMIT;
		if idleTimeOutFlag == define.FLOW_IDLE_TIMEOUT_NORMAL:
			ret['idle_timeout'] = define.FLOW_IDLE_TIMEOUT_NORMAL
		elif idleTimeOutFlag == define.FLOW_IDLE_TIMEOUT_PACKET_IN_DISABLE:
			ret['idle_timeout'] = define.FLOW_IDLE_TIMEOUT_NORMAL

		ret['actions'] = actions
		ret['status'] = define.HTTP_STATUS_SUCCESS
		ret['message'] = define.SUCCESS_MSG
		LOG.debug("END : status = " + str(ret['status']) + ", message = " + ret['message'])
		return ret

	def parse_queryStr(self, queryStr):
		LOG.debug("START")

		ret = {'status':'','message':'','query':''}

		query = cgi.parse_qsl(queryStr)
		queryParam = {}
		match = {}
		action = {}
		for param in query:
			LOG.debug("param[0] = " + param[0] + ", param[1] = " + param[1])
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
		ret['status'] = define.HTTP_STATUS_SUCCESS
		ret['message'] = define.SUCCESS_MSG
		LOG.debug("END : status = " + str(ret['status']) + ", message = " + ret['message'])
		return ret

	def set_response_data(self, status=define.HTTP_STATUS_CREATED_SUCCESS, message = define.SUCCESS_MSG):
		response_data = {'status':status, 'message':message}
		res = Response(status = status,content_type = 'application/json', body = json.dumps(response_data))
		LOG.debug("status = " + str(status) + ", message = \"" + message + "\"")
		return res

	def set_response_headers_for_all(res):
		res.headers.update({'Access-Control-Allow-Header':'*'})
		return res

	def set_response_headers_for_options(res):
		res.headers.update({'Access-Control-Allow-Origin':'*'})
		res.headers.update({'Allow':'GET,POST,PUT,DELETE,OPTIONS'})
		res.headers.update({'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'})
		return res
